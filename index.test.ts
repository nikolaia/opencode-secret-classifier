import assert from "node:assert/strict"
import { test } from "node:test"
import { check, mask } from "./index.ts"

const ALLOW = ["sops -e *", "sops -d *", "sops exec-env *", "npm test"]

const DENIED = [
  "cat .env",
  "cat config/.env.production",
  "printenv",
  "env",
  "set",
  "export -p",
  "echo $OPENAI_API_KEY",
  'printf "%s" "${DB_PASSWORD}"',
  "printenv GITHUB_TOKEN",
  "cat ~/.ssh/id_ed25519",
  "cat < ~/.aws/credentials",
  "sudo cat ~/.npmrc",
  "sops -d secrets.yaml",
  "sops --decrypt secrets/prod.yaml",
  "kubectl get secret db-creds -o yaml",
  "gh auth token",
  "security find-generic-password -s github -w",
  "op read op://vault/db/password",
  "cat terraform.tfstate",
  "cat /proc/self/environ",
  "grep -r password .env",
  "tail -f .env.local",
  "git status && cat .env",
  'echo "x $(cat .env)"',
  "sh -c 'cat .env'",
  "bash -c 'printenv'",
  "eval printenv",
  "env FOO=1 printenv",
  "sops exec-env secrets.yaml 'printenv'",
  'echo "unterminated',
]

const NOT_DENIED = [
  "git status",
  "npm test",
  "cat .env.example",
  "cat ~/.ssh/id_ed25519.pub",
  "printenv HOME",
  "echo $PATH",
  "env FOO=1 npm test",
  "kubectl get secret",
  "sops -e -i secrets.yaml",
  "sops exec-env secrets.yaml 'npm test'",
  "grep -rl API_KEY .",
  "grep -c API_KEY .env",
  "wc -l .env",
  "test -f .env && echo exists",
  "source .env && npm start",
  "git commit -m \"$(cat <<'EOF'\nfix: don't print .env\nEOF\n)\"",
]

for (const command of DENIED)
  test(`denies ${command}`, async () => {
    assert.equal((await check(command, ALLOW)).effect, "deny")
  })

for (const command of NOT_DENIED)
  test(`does not deny ${command}`, async () => {
    assert.notEqual((await check(command, ALLOW)).effect, "deny")
  })

test("allowlisted commands skip the judge", async () => {
  assert.equal((await check("sops -e -i secrets.yaml", ALLOW)).effect, "allowlisted")
  assert.equal((await check("sops exec-env secrets.yaml 'npm test'", ALLOW)).effect, "allowlisted")
})

test("an allowlisted command whose nested script is not allowlisted goes to the judge", async () => {
  assert.equal((await check("sops exec-env secrets.yaml 'npm run build'", ALLOW)).effect, "judge")
})

test("the static list wins over the allowlist", async () => {
  assert.equal((await check("sops -d secrets.yaml", ALLOW)).effect, "deny")
})

const MASKED = [
  ["mail ola.nordmann@example.no now", "mail [email] now"],
  ["fnr 15088510140", "fnr [national ID]"],
  ["IBAN NO93 8601 1117 947", "IBAN [IBAN]"],
  ["card 4111 1111 1111 1111", "card [card number]"],
  ["call +47 912 34 567", "call [phone number]"],
  ["OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwx", "OPENAI_API_KEY=[token]"],
  ["DB_PASSWORD=hunter2", "DB_PASSWORD=[secret]"],
  ["password: hunter2", "password: [secret]"],
  ["postgres://app:s3cret@db:5432/app", "postgres://app:[password]@db:5432/app"],
  ["-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----", "[private key]"],
]

const UNTOUCHED = [
  "fnr-shaped 15088510141",
  "card-shaped 4111 1111 1111 1112",
  "commit 9f8e7d6c5b4a39281706f5e4d3c2b1a098765432 at 1793049505983",
  "size 41234567 bytes",
  "phone 91234567",
]

for (const [input, expected] of MASKED)
  test(`masks ${JSON.stringify(input)}`, () => {
    assert.equal(mask(input).text, expected)
  })

test("masking secrets only keeps personal data and still masks tokens", () => {
  assert.equal(mask("ola@example.no API_TOKEN=abc123 sk-proj-abcdefghijklmnopqrstuvwx", ["secret"]).text, "ola@example.no API_TOKEN=[secret] [token]")
})

for (const input of UNTOUCHED)
  test(`leaves ${JSON.stringify(input)} alone`, () => {
    assert.equal(mask(input).text, input)
  })
