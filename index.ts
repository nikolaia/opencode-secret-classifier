import { fileURLToPath } from "node:url"
import { Language, Parser, type Node } from "web-tree-sitter"

const OLLAMA = "http://127.0.0.1:11434"
const MODEL = process.env.OPENCODE_SECRET_CLASSIFIER_MODEL ?? "tev1:4b-q8_0"
const THRESHOLD = Number(process.env.OPENCODE_SECRET_CLASSIFIER_THRESHOLD ?? 0.6)
const JUDGE_TIMEOUT_MS = 8000
const MAX_NESTED_SCRIPT_DEPTH = 3

const QUESTIONS = {
  exposes_secret: {
    type: "noul",
    instructions:
      "Running the command would print a secret value (password, API key, token, private key, connection string, or decrypted secret file contents) to the terminal or into the agent's context.",
  },
}

const SECRET_VARIABLE_NAME = /KEY|TOKEN|SECRET|PASS|CREDENTIAL|AUTH/i
const SAFE_ENV_FILE = /(^|\/)\.env\.(example|sample)$/
const CREDENTIAL_FILES = [
  /(^|\/)\.env(\.[^/]+)?$/,
  /(^|\/)\.ssh\/(?!.*\.pub$|known_hosts|config$|authorized_keys$)[^/]+$/,
  /\.(pem|key)$/,
  /(^|\/)(\.aws\/credentials|\.npmrc|\.netrc|\.pypirc|\.docker\/config\.json|\.kube\/config|gh\/hosts\.yml)$/,
]
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

type Part = { text: string; words: string[]; expandedVariables: string[] }
type Parsed = { parts: Part[]; words: string[] }
export type Check = { effect: "deny"; reason: string } | { effect: "allowlisted" } | { effect: "judge" }

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

// Undefined when the command cannot be read.
async function parse(source: string, depth = 0): Promise<Parsed | undefined> {
  const root = (await parser).parse(source)?.rootNode
  if (!root || root.hasError) return undefined
  const parsed: Parsed = {
    parts: [],
    words: root.descendantsOfType(["word", "string", "raw_string", "concatenation"]).flatMap((node) => (node ? [unquote(node)] : [])),
  }
  for (const command of root.descendantsOfType(["command", "declaration_command"])) {
    if (!command) continue
    // `export`, `declare` and friends are declaration_command nodes with the keyword as first child.
    const nodes = command.type === "command" ? [command.childForFieldName("name"), ...command.childrenForFieldName("argument")] : command.children
    const words = nodes.flatMap((node) => (node ? [unquote(node)] : []))
    const expandedVariables = command
      .descendantsOfType("variable_name")
      .flatMap((node) => (node && node.parent?.type !== "variable_assignment" ? [node.text] : []))
    parsed.parts.push({ text: command.text, words, expandedVariables })

    const script = nestedScript(words)
    if (script === undefined) continue
    if (depth >= MAX_NESTED_SCRIPT_DEPTH) return undefined
    const nested = await parse(script, depth + 1)
    if (!nested) return undefined
    parsed.parts.push(...nested.parts)
    parsed.words.push(...nested.words)
  }
  return parsed
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
}

function globToRegExp(pattern: string): RegExp {
  return new RegExp(`^${pattern.split("*").map((s) => s.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`)
}

export async function check(command: string, allowPatterns: string[] = []): Promise<Check> {
  const parsed = await parse(command)
  if (!parsed) return { effect: "deny", reason: "the command could not be parsed" }
  for (const part of parsed.parts) {
    const reason = staticDenyReason(part)
    if (reason) return { effect: "deny", reason }
  }
  const credentialFile = parsed.words.find((word) => !SAFE_ENV_FILE.test(word) && CREDENTIAL_FILES.some((file) => file.test(word)))
  if (credentialFile) return { effect: "deny", reason: `the command names the credential file ${credentialFile}` }
  const allow = allowPatterns.map(globToRegExp)
  if (parsed.parts.every((part) => allow.some((pattern) => pattern.test(part.text)))) return { effect: "allowlisted" }
  return { effect: "judge" }
}

export async function judge(commands: string[], project: string): Promise<{ score: number } | { error: string }> {
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
      body: JSON.stringify({ model: MODEL, state: { commands, project }, questions: QUESTIONS }),
      signal,
    })
    if (!response.ok) return { error: `the judge returned HTTP ${response.status}` }
    const score = (await response.json())?.answers?.exposes_secret?.noul
    if (typeof score !== "number" || !(score >= 0 && score <= 1)) return { error: "the judge answer was unreadable" }
    return { score }
  } catch (error) {
    return { error: `the judge was unavailable (${(error as Error).message})` }
  }
}

type PermissionEvaluation = {
  readonly action: string
  readonly resources: readonly string[]
  effect: "allow" | "ask" | "deny"
  message?: string
}
type Context = {
  readonly options: { allow?: string[] }
  readonly location: { directory: string }
  readonly permission: { hook: (name: "evaluate", callback: (event: PermissionEvaluation) => Promise<void>) => Promise<unknown> }
}

export default {
  id: "opencode-secret-classifier",
  async setup(ctx: Context) {
    const allowPatterns = ctx.options.allow ?? []
    await ctx.permission.hook("evaluate", async (event) => {
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

      const verdict = await judge(commands, ctx.location.directory)
      if ("error" in verdict) return decide("ask", `could not check this command for secrets: ${verdict.error}.`)
      if (verdict.score >= THRESHOLD)
        return decide("deny", `denied because the local judge scored exposes_secret ${verdict.score.toFixed(2)} (threshold ${THRESHOLD}), so it would likely print a secret value into the context.`)
    })
  },
}
