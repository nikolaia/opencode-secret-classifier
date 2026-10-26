import { fileURLToPath } from "node:url"
import { Language, Parser, type Node } from "web-tree-sitter"

const OLLAMA = (process.env.OPENCODE_SECRET_CLASSIFIER_OLLAMA_URL ?? "http://127.0.0.1:11434").replace(/\/+$/, "")
const MODEL = process.env.OPENCODE_SECRET_CLASSIFIER_MODEL ?? "tev1:4b-q8_0"
const THRESHOLD = Number(process.env.OPENCODE_SECRET_CLASSIFIER_THRESHOLD ?? 0.6)
const PERSONAL_DATA_THRESHOLD = Number(process.env.OPENCODE_SECRET_CLASSIFIER_PERSONAL_DATA_THRESHOLD ?? 0.6)
const JUDGE_TIMEOUT_MS = 8000
const MAX_NESTED_SCRIPT_DEPTH = 3
// The model only reads the start of long outputs.
const MAX_OUTPUT_CHARS_FOR_JUDGE = 4000
const PERSONAL_DATA_ACTION = "personal_data"

// Wording measured with eval.ts; spelling out what does not count reduced false flags.
const QUESTIONS = {
  exposes_secret: {
    type: "noul",
    instructions:
      "Running the command would print the actual value of a secret (password, API key, token, private key, connection string, or decrypted secret file contents) to the terminal. It does not count if the command only lists file, variable, or secret names; counts lines or checks that a file exists; passes a secret variable to another program without printing it (for example $TOKEN to curl or $DATABASE_URL to psql); encrypts a file; or runs a program with secrets in its environment without printing them.",
  },
  exposes_pii: {
    type: "noul",
    instructions:
      "This tool output contains personal data about identifiable people: for example names together with addresses, birth dates, health, financial, or customer records. Developer names in version control history, usernames in file listings, and placeholder names in code or tests do not count.",
  },
}

const SECRET_VARIABLE_NAME = /KEY|TOKEN|SECRET|PASS|CREDENTIAL|AUTH/i
const SAFE_ENV_FILE = /(^|\/)\.env\.(example|sample)$/
const CREDENTIAL_FILES = [
  /(^|\/)\.env(\.[^/]+)?$/,
  /(^|\/)\.ssh\/(?!.*\.pub$|known_hosts|config$|authorized_keys$)[^/]+$/,
  /\.(pem|key)$/,
  /(^|\/)(\.aws\/credentials|\.npmrc|\.netrc|\.pypirc|\.docker\/config\.json|\.kube\/config|gh\/hosts\.yml)$/,
  /\.tfstate(\.backup)?$/,
  /^\/proc\/[^/]+\/environ$/,
]
// Commands that print the contents of the files they are given. `wc .env` or `source .env` do not.
const FILE_PRINTERS = new Set(["cat", "bat", "tac", "head", "tail", "less", "more", "nl", "strings", "xxd", "od", "hexdump", "base64", "sed", "awk", "cut", "sort", "uniq", "column", "diff", "jq", "yq", "grep", "egrep", "fgrep", "rg", "ag"])
const GREPS = new Set(["grep", "egrep", "fgrep", "rg", "ag"])
// grep flags that print file names, counts, or nothing instead of matching lines.
const GREP_WITHOUT_LINES = (arg: string) => ["--count", "--files-with-matches", "--files-without-match", "--quiet"].includes(arg) || /^-[A-Za-z]*[lLcq]/.test(arg)
// Commands that run the rest of their arguments as another command.
const WRAPPERS = new Set(["sudo", "doas", "command", "exec", "nohup", "time", "nice", "xargs", "env"])
const SECRET_TOOLS: [string, (args: string[]) => boolean][] = [
  ["sops", (args) => args.includes("-d") || args.includes("--decrypt") || args[0] === "decrypt"],
  ["kubectl", (args) => args.includes("get") && args.some((a) => /^secrets?(\/|$)/.test(a)) && args.some((a) => a.startsWith("-o") || a.startsWith("--output"))],
  ["gh", (args) => args[0] === "auth" && args[1] === "token"],
  ["security", (args) => /^find-(generic|internet)-password$/.test(args[0]) && (args.includes("-w") || args.includes("-g"))],
  ["op", (args) => args[0] === "read"],
  ["aws", (args) => args[0] === "configure" && args[1] === "get"],
  ["vault", (args) => (args[0] === "kv" && args[1] === "get") || args[0] === "read"],
  ["az", (args) => args[0] === "account" && args[1] === "get-access-token"],
  ["gcloud", (args) => args[0] === "auth" && args[1] === "print-access-token"],
]

const parser = (async () => {
  await Parser.init()
  const bash = await Language.load(fileURLToPath(import.meta.resolve("tree-sitter-bash/tree-sitter-bash.wasm")))
  return new Parser().setLanguage(bash)
})()

type Part = { text: string; words: string[]; expandedVariables: string[]; inputFiles: string[] }
type Check = { effect: "deny"; reason: string } | { effect: "allowlisted" } | { effect: "judge" }

function unquote(node: Node): string {
  if (node.type === "raw_string" || node.type === "string") return node.text.slice(1, -1)
  if (node.type === "concatenation") return node.children.map((child) => (child ? unquote(child) : "")).join("")
  return node.text.replace(/\\(.)/g, "$1")
}

// The script that `bash -c`, `eval`, or `sops exec-env` will run, if this command runs one.
function nestedScript([name, ...args]: string[]): string | undefined {
  if (["bash", "sh", "zsh", "dash"].includes(name) && args.includes("-c")) return args[args.indexOf("-c") + 1]
  if (name === "eval") return args.join(" ")
  if (name === "sops" && (args[0] === "exec-env" || args[0] === "exec-file")) return args.at(-1)
}

// Every simple command in the source, nested scripts included. Undefined when the command cannot be read.
async function parse(source: string, depth = 0): Promise<Part[] | undefined> {
  const root = (await parser).parse(source)?.rootNode
  if (!root || root.hasError) return undefined
  const parts: Part[] = []
  for (const command of root.descendantsOfType(["command", "declaration_command"])) {
    if (!command) continue
    // `export`, `declare` and friends are declaration_command nodes with the keyword as first child.
    const nodes = command.type === "command" ? [command.childForFieldName("name"), ...command.childrenForFieldName("argument")] : command.children
    const words = nodes.flatMap((node) => (node ? [unquote(node)] : []))
    const expandedVariables = command
      .descendantsOfType("variable_name")
      .flatMap((node) => (node && node.parent?.type !== "variable_assignment" ? [node.text] : []))
    // `cat < .env`: the file arrives through a redirect on the surrounding statement, not as an argument.
    const inputFiles =
      command.parent?.type === "redirected_statement"
        ? command.parent.children.flatMap((redirect) => {
            const destination = redirect?.type === "file_redirect" && redirect.text.startsWith("<") ? redirect.childForFieldName("destination") : null
            return destination ? [unquote(destination)] : []
          })
        : []
    parts.push({ text: command.text, words, expandedVariables, inputFiles })

    const script = nestedScript(words)
    if (script === undefined) continue
    if (depth >= MAX_NESTED_SCRIPT_DEPTH) return undefined
    const nestedParts = await parse(script, depth + 1)
    if (!nestedParts) return undefined
    parts.push(...nestedParts)
  }
  return parts
}

// Strips `sudo`, `env FOO=1`, and the like, so the real command is checked.
function unwrap(words: string[]): [string, string[]] {
  let [name, ...args] = words
  for (;;) {
    name = name?.split("/").pop() ?? ""
    if (!WRAPPERS.has(name)) return [name, args]
    const commandIndex = args.findIndex((arg) => !arg.startsWith("-") && !(name === "env" && arg.includes("=")))
    if (commandIndex === -1) return [name, []]
    ;[name, ...args] = args.slice(commandIndex)
  }
}

function staticDenyReason(part: Part): string | undefined {
  const [name, args] = unwrap(part.words)
  const allFlags = args.every((arg) => arg.startsWith("-"))
  if (
    (["env", "printenv", "set"].includes(name) && args.length === 0) ||
    (name === "export" && (args.length === 0 || args.includes("-p"))) ||
    (["declare", "typeset"].includes(name) && allFlags && (args.length === 0 || args.some((arg) => /[px]/.test(arg))))
  )
    return `\`${part.text}\` dumps the environment`
  if (["echo", "printf", "printenv"].includes(name)) {
    const variable = [...part.expandedVariables, ...(name === "printenv" ? args : [])].find((v) => SECRET_VARIABLE_NAME.test(v))
    if (variable) return `\`${part.text}\` prints the secret variable ${variable}`
  }
  if (SECRET_TOOLS.some(([tool, printsSecret]) => tool === name && printsSecret(args)))
    return `\`${part.text}\` prints a decrypted secret`
  const printsFiles = FILE_PRINTERS.has(name) && !(GREPS.has(name) && args.some(GREP_WITHOUT_LINES))
  if (printsFiles) {
    const credentialFile = [...args, ...part.inputFiles].find((file) => !SAFE_ENV_FILE.test(file) && CREDENTIAL_FILES.some((pattern) => pattern.test(file)))
    if (credentialFile) return `\`${part.text}\` prints the credential file ${credentialFile}`
  }
}

function globToRegExp(pattern: string): RegExp {
  return new RegExp(`^${pattern.split("*").map((s) => s.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`)
}

export async function check(command: string, allowPatterns: string[] = []): Promise<Check> {
  const parts = await parse(command)
  if (!parts) return { effect: "deny", reason: "the command could not be parsed" }
  for (const part of parts) {
    const reason = staticDenyReason(part)
    if (reason) return { effect: "deny", reason }
  }
  const allow = allowPatterns.map(globToRegExp)
  if (parts.every((part) => allow.some((pattern) => pattern.test(part.text)))) return { effect: "allowlisted" }
  return { effect: "judge" }
}

export async function judge(question: keyof typeof QUESTIONS, state: Record<string, unknown>): Promise<{ score: number } | { error: string }> {
  const signal = AbortSignal.timeout(JUDGE_TIMEOUT_MS)
  try {
    // Ollama cloud models answer on the local API but run on ollama.com.
    const { models } = await (await fetch(`${OLLAMA}/api/tags`, { signal })).json()
    const fullName = MODEL.includes(":") ? MODEL : `${MODEL}:latest`
    const model = models.find((m: { name: string }) => m.name === fullName)
    if (!model) return { error: `the judge model ${MODEL} is not installed (ollama pull ${MODEL})` }
    if (model.remote_host) return { error: `the judge model ${MODEL} runs on ${model.remote_host}, not this machine, so it is refused` }

    const response = await fetch(`${OLLAMA}/v1/systemone`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ model: MODEL, state, questions: { [question]: QUESTIONS[question] } }),
      signal,
    })
    if (!response.ok) return { error: `the judge returned HTTP ${response.status}` }
    const score = (await response.json())?.answers?.[question]?.noul
    if (typeof score !== "number" || !(score >= 0 && score <= 1)) return { error: "the judge answer was unreadable" }
    return { score }
  } catch (error) {
    return { error: `the judge was unavailable (${(error as Error).message})` }
  }
}

// Fødselsnummer and D-numbers: a plausible date and both mod-11 check digits.
function isNorwegianNationalId(digits: string): boolean {
  const d = [...digits].map(Number)
  const day = (d[0] * 10 + d[1]) % 40
  const month = (d[2] * 10 + d[3]) % 40
  if (day < 1 || day > 31 || month < 1 || month > 12) return false
  const checkDigit = (weights: number[]) => {
    const remainder = 11 - (weights.reduce((sum, weight, i) => sum + weight * d[i], 0) % 11)
    return remainder === 11 ? 0 : remainder
  }
  return checkDigit([3, 7, 6, 1, 8, 9, 4, 5, 2]) === d[9] && checkDigit([5, 4, 3, 2, 7, 6, 5, 4, 3, 2]) === d[10]
}

function passesLuhn(digits: string): boolean {
  let sum = 0
  for (let i = 0; i < digits.length; i++) {
    let digit = Number(digits[digits.length - 1 - i])
    if (i % 2 === 1) digit = digit * 2 > 9 ? digit * 2 - 9 : digit * 2
    sum += digit
  }
  return sum % 10 === 0
}

function isValidIban(iban: string): boolean {
  const rearranged = iban.slice(4) + iban.slice(0, 4)
  const numeric = [...rearranged].map((c) => (/[A-Z]/.test(c) ? String(c.charCodeAt(0) - 55) : c)).join("")
  return [...numeric].reduce((remainder, digit) => (remainder * 10 + Number(digit)) % 97, 0) === 1
}

// Secrets are always masked. Personal data is masked too, but comes back when the user allows the output.
type MaskKind = "secret" | "personal"
const ALL_KINDS: MaskKind[] = ["secret", "personal"]

// Applied in order. Each label replaces the matched value; `keep` keeps a leading capture group.
const MASKS: { kind: MaskKind; label: string; pattern: RegExp; keep?: boolean; valid?: (match: string) => boolean }[] = [
  { kind: "secret", label: "private key", pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
  { kind: "secret", label: "token", pattern: /\b(?:sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|glpat-[A-Za-z0-9_-]{20,})\b/g },
  { kind: "secret", label: "token", pattern: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g },
  { kind: "secret", label: "password", pattern: /(\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:)[^\s@/]+(?=@)/gi, keep: true },
  { kind: "secret", label: "secret", pattern: /(\b[A-Za-z0-9_.-]*(?:KEY|TOKEN|SECRET|PASS|CREDENTIAL|AUTH)[A-Za-z0-9_]*["']?\s*[=:]\s*["']?)(?!\[)[^\s"',;]+/gi, keep: true },
  { kind: "personal", label: "email", pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  { kind: "personal", label: "IBAN", pattern: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b/g, valid: (m) => isValidIban(m.replace(/ /g, "")) },
  { kind: "personal", label: "card number", pattern: /(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)/g, valid: (m) => passesLuhn(m.replace(/\D/g, "")) && /[ -]/.test(m) },
  { kind: "personal", label: "national ID", pattern: /(?<!\d)\d{6} ?\d{5}(?!\d)/g, valid: (m) => isNorwegianNationalId(m.replace(/ /g, "")) },
  { kind: "personal", label: "phone number", pattern: /(?<![\w+])\+\d{1,3}(?:[ -]?\d){7,12}(?!\d)/g },
]

export function mask(text: string, kinds: MaskKind[] = ALL_KINDS): { text: string; counts: Record<string, number> } {
  const counts: Record<string, number> = {}
  for (const { kind, label, pattern, keep, valid } of MASKS.filter((m) => kinds.includes(m.kind)))
    text = text.replace(pattern, (match: string, prefix: string) => {
      if (valid && !valid(match)) return match
      counts[label] = (counts[label] ?? 0) + 1
      return keep ? `${prefix}[${label}]` : `[${label}]`
    })
  return { text, counts }
}

// Masks every string inside a tool result, whatever shape the tool gives it.
function maskDeep(value: unknown, kinds: MaskKind[] = ALL_KINDS): unknown {
  if (typeof value === "string") return mask(value, kinds).text
  if (Array.isArray(value)) return value.map((item) => maskDeep(item, kinds))
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, maskDeep(item, kinds)]))
  return value
}

// The output text shown to the agent. Shell results carry it as `content` text parts.
function outputText(result: unknown): string {
  const content = (result as { content?: unknown })?.content
  if (typeof content === "string") return content
  if (Array.isArray(content)) return content.flatMap((part) => (typeof part?.text === "string" ? [part.text] : [])).join("\n")
  return ""
}

function withheld(result: unknown, reason: string): unknown {
  const text = `[output withheld by opencode-secret-classifier: ${reason}]`
  return { ...(result as object), output: text, content: [{ type: "text", text }] }
}

type PermissionEvaluation = {
  readonly sessionID: string
  readonly action: string
  readonly resources: readonly string[]
  readonly metadata?: Record<string, unknown>
  effect: "allow" | "ask" | "deny"
  message?: string
}
type Context = {
  readonly options: { allow?: string[] }
  readonly location: { directory: string }
  readonly permission: {
    hook: (name: "evaluate", callback: (event: PermissionEvaluation) => Promise<void>) => Promise<unknown>
    assert: (input: {
      sessionID: string
      action: string
      resources: string[]
      source: { type: "tool"; messageID: string; id: string }
      metadata?: Record<string, unknown>
    }) => Promise<void>
  }
  readonly tool: { hook: (name: "execute.after", callback: (event: ToolExecuteAfter) => Promise<void>) => Promise<unknown> }
  readonly event: { subscribe: () => AsyncIterable<{ type: string; data: unknown }> }
}
type PermissionAsked = { id: string; sessionID: string; action: string; resources: string[] }
type PermissionReplied = { requestID: string; reply: "once" | "always" | "reject" }
type ToolExecuteAfter = { readonly tool: string; readonly sessionID: string; readonly messageID: string; readonly id: string } & (
  | { readonly status: "completed"; result: unknown }
  | { readonly status: "error" }
)

export default {
  id: "opencode-secret-classifier",
  async setup(ctx: Context) {
    const allowPatterns = ctx.options.allow ?? []

    // "Always" on one of the plugin's shell prompts means: stop asking about this exact command for the
    // rest of this session. Kept in memory only, so a mistaken click ends with the session.
    // Permanent trust belongs in the `allow` option, where it can be seen and removed.
    const sessionCommandKey = (sessionID: string, commands: readonly string[]) => `${sessionID}\n${JSON.stringify(commands)}`
    const promptedByPlugin = new Set<string>()
    const allowedForSession = new Set<string>()
    const promptKeyByRequestID = new Map<string, string>()
    void (async () => {
      for await (const event of ctx.event.subscribe()) {
        if (event.type === "permission.asked") {
          const { id, sessionID, action, resources } = event.data as PermissionAsked
          const key = sessionCommandKey(sessionID, resources)
          if (action === "shell" && promptedByPlugin.has(key)) promptKeyByRequestID.set(id, key)
        } else if (event.type === "permission.replied") {
          const { requestID, reply } = event.data as PermissionReplied
          const key = promptKeyByRequestID.get(requestID)
          promptKeyByRequestID.delete(requestID)
          if (key && reply === "always") allowedForSession.add(key)
        }
      }
    })().catch((error) => console.error(`opencode-secret-classifier: stopped listening for permission replies: ${error}`))

    await ctx.permission.hook("evaluate", async (event) => {
      // Raised by the output check below; always shown to the user, whatever OpenCode's rules say.
      if (event.action === PERSONAL_DATA_ACTION) {
        event.effect = "ask"
        event.message = `opencode-secret-classifier: ${String(event.metadata?.reason)} Send it to the model? Reject to withhold it.`
        return
      }
      if (event.action !== "shell") return
      const commands = [...event.resources]
      const decide = (effect: "ask" | "deny", message: string) => {
        event.effect = effect
        event.message = `opencode-secret-classifier: ${message}`
        console.error(`opencode-secret-classifier: ${effect} ${JSON.stringify(commands)}: ${message}`)
      }

      const checks = await Promise.all(commands.map((command) => check(command, allowPatterns)))
      const denied = checks.find((c) => c.effect === "deny")
      if (denied?.effect === "deny") return decide("deny", `denied because ${denied.reason}, which would print a secret value into the context.`)
      if (checks.every((c) => c.effect === "allowlisted")) return
      const key = sessionCommandKey(event.sessionID, commands)
      if (allowedForSession.has(key)) return

      const prompt = (message: string) => {
        promptedByPlugin.add(key)
        decide("ask", `${message} "Always" stops asking about this exact command for the rest of this session; to allow it permanently, add it to \`allow\` in opencode.jsonc.`)
      }
      const verdict = await judge("exposes_secret", { commands, project: ctx.location.directory })
      if ("error" in verdict) return prompt(`could not check this command for secrets: ${verdict.error}.`)
      if (verdict.score >= THRESHOLD)
        // The model can be wrong, so its verdict asks; only the exact built-in list denies outright.
        return prompt(`the local judge scored exposes_secret ${verdict.score.toFixed(2)} (threshold ${THRESHOLD}): this command may print a secret value into the context. Run it?`)
    })

    // Runs after every tool, before the result reaches the model or the session history.
    await ctx.tool.hook("execute.after", async (event) => {
      if (event.status !== "completed") return
      const original = event.result
      event.result = maskDeep(original)
      // Counted on the text the agent sees; shell results carry the same text twice.
      const { counts } = mask(outputText(original))
      if (Object.keys(counts).length)
        console.error(`opencode-secret-classifier: masked ${Object.entries(counts).map(([label, count]) => `${count} ${label}`).join(", ")} in ${event.tool} output`)

      // Personal data the patterns cannot see (names, addresses): ask, because it may be synthetic.
      const text = outputText(event.result)
      if (!text.trim()) return
      const verdict = await judge("exposes_pii", { tool: event.tool, tool_output: text.slice(0, MAX_OUTPUT_CHARS_FOR_JUDGE) })
      let reason: string
      if ("error" in verdict) reason = `could not check this ${event.tool} output for personal data: ${verdict.error}.`
      else if (verdict.score >= PERSONAL_DATA_THRESHOLD) reason = `this ${event.tool} output may contain personal data (score ${verdict.score.toFixed(2)}).`
      else return
      try {
        await ctx.permission.assert({
          sessionID: event.sessionID,
          action: PERSONAL_DATA_ACTION,
          resources: [event.tool],
          source: { type: "tool", messageID: event.messageID, id: event.id },
          metadata: { reason },
        })
        // The user vouched for the personal data (it may be synthetic); secrets stay masked.
        event.result = maskDeep(original, ["secret"])
        console.error(`opencode-secret-classifier: user allowed ${event.tool} output: ${reason}`)
      } catch (rejection) {
        event.result = withheld(event.result, "the user did not allow output that may contain personal data")
        console.error(`opencode-secret-classifier: withheld ${event.tool} output: ${reason}`)
        throw rejection
      }
    })
  },
}
