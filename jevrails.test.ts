import assert from "node:assert/strict"
import { test } from "node:test"
import { check } from "./index.ts"

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
