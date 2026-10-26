# opencode-secret-classifier

A local classifier for OpenCode that denies any shell command that would print a secret value into the agent's context or the terminal. An OpenCode plugin checks a built-in list, then asks a Jev-style decision model on this machine via Ollama `/v1/systemone`. Not a chat model, not a server.

This is the first proof of concept. It only ever denies. It never allows a command that OpenCode would otherwise ask about.

## Goal

Runs entirely on an Apple Silicon Mac. Commands, paths, and user messages never leave the machine: no OpenRouter, no hosted Jev, no Ollama cloud models. The only network call is to `127.0.0.1:11434`.

## Requires

- OpenCode 2.0.12 or later (for `ctx.permission.hook("evaluate")`).
- Ollama 0.35 or later (for `/v1/systemone`), with `ollama pull tev1:4b-q8_0`.

## Out

Not a secrets proxy, not redaction, not a hosted runtime, not a second agent in the transcript. No HTTP server, no sessions, rules feed, or dashboard. No auto-approve. Shell only: secrets read through OpenCode's own read tool are not covered.

## Decision

One shell request in. In order:

1. Static list matches → `deny`. Do not call the model.
2. Every part of the command matches the allowlist → leave `event.effect` as OpenCode set it. Do not call the model.
3. Otherwise ask the model. `exposes_secret` at least `0.6` → `deny`.
4. Model down, timeout (8 s), non-OK response, or an unreadable answer → `ask`. A miss is not a pass.
5. Otherwise leave `event.effect` as OpenCode set it.

`event.message` names the check that matched and the score. On `deny` the agent reads it and continues. On `ask` it shows in the prompt. A log line shows the same thing. That is the whole UI.

Static list, built in, not a config file:

- Environment dumps: bare `env`, `printenv`, `set`, `export -p`, `declare -x`.
- Printing a variable whose name contains `KEY`, `TOKEN`, `SECRET`, `PASSWORD`, `PASS`, `CREDENTIAL`, or `AUTH` (`echo $X`, `printenv X`).
- A command that names a credential file: `.env` and `.env.*` (except `.env.example` and `.env.sample`), a private key under `.ssh/` (not `*.pub`), `*.pem`, `*.key`, `.aws/credentials`, `.npmrc`, `.netrc`, `.pypirc`, `.docker/config.json`, `.kube/config`, `gh/hosts.yml`.
- Secret tools that print plaintext: `sops -d` / `sops --decrypt`, `kubectl get secret` with `-o`, `gh auth token`, `security find-*-password` with `-w` or `-g`, `op read`, `aws configure get`, `vault kv get`, `vault read`, `az account get-access-token`, `gcloud auth print-access-token`.

`sops exec-env` and `sops -e` are not on the list: they do not print plaintext.

A compound command is denied if any part matches. A command the splitter cannot read is denied. Use a real shell parser, not regex on the whole string.

`sops exec-env <file> '<command>'` runs `<command>` with the decrypted secrets in its environment, so `<command>` is checked as its own command (static list, allowlist, model) before the outer command passes. `sops exec-env secrets.yaml 'printenv'` is denied. The same goes for `bash -c`, `sh -c`, `zsh -c`, and `eval`.

## Allowlist

Commands the user trusts to skip the model, set in the plugin's options (see OpenCode below):

```jsonc
"plugins": [{ "package": "/absolute/path/to/opencode-secret-classifier", "options": { "allow": ["sops -e *", "sops exec-env *"] } }]
```

Patterns are matched against each part of a compound command, with `*` matching the rest of the part. The allowlist skips the model only; the static list still wins, so `"sops -d *"` changes nothing. Overriding the static list means changing the code, not the config. OpenCode `allow` rules do not skip the plugin: the evaluate hook runs for them too.

## Judge

`POST http://127.0.0.1:11434/v1/systemone`, the same shape as the Jev Decisions API: a body with `model`, `state`, and `questions`; the reply has `answers.<name>.noul`, a score from 0 to 1. Confirmed on Ollama 0.40.6.

The URL is fixed to loopback. It is not configurable, and `OLLAMA_HOST` is ignored.

Default model: `tev1:4b-q8_0`, the GGUF build. Plain `tev1` is an MLX build and fails on an Ollama without the MLX runtime, such as the nix package. Override with `OPENCODE_SECRET_CLASSIFIER_MODEL`. Threshold override: `OPENCODE_SECRET_CLASSIFIER_THRESHOLD`.

Ollama cloud models answer on the same local API but run on ollama.com. Before the first decision, the plugin checks the model in `GET /api/tags` and refuses one that Ollama marks as remote; every decision then asks, with a message that says why. Confirm the field Ollama uses for this before building on it.

State sent to the model: the commands and the project directory. Nothing else.

Question, type `noul`:

- `exposes_secret`: running the command would print a secret value (password, API key, token, private key, connection string, or decrypted secret file contents) to the terminal or into the agent's context.

Measured on 44 hand-labelled commands with `tev1:4b-q8_0` (about 0.4 s each): at `0.6` the model alone caught 18 of 24 secret-exposing commands and denied 2 of 20 safe ones (`grep -rl API_KEY .`, `sops -e -i`). Its misses (`env`, `printenv`, `set`, `export -p`, `cat ~/.npmrc`, `cat ~/.config/gh/hosts.yml`) are all on the static list, which is why the list runs first.

## OpenCode

The plugin is `index.ts` in this repo, listed by path under `plugins` in `~/.config/opencode/opencode.jsonc` (every project) or a project's `opencode.jsonc`. OpenCode loads the `index` or `server` module of a configured directory and skips a path to a single file, without a log line.

It registers `ctx.permission.hook("evaluate")`. The hook runs for `allow` and `ask`. A configured `deny` never reaches it and cannot be overridden. The plugin acts only on shell requests and returns without changes for anything else.

Commands come from `event.resources`. The plugin sets `event.effect` and `event.message` only when the decision above says `deny` or `ask`. A `deny` reaches the model as a tool error with that message, and the agent continues.

## Done

- `cat .env`, `printenv`, and `sops -d secrets.yaml` are denied and Ollama is not called.
- `terraform output -json` and `docker inspect postgres | grep -i password` are denied by the model.
- `git status`, `npm test`, and `cat .env.example` run as OpenCode would run them.
- With `"sops -e *"` allowlisted, `sops -e -i secrets.yaml` runs and Ollama is not called; an allowlisted `"sops -d *"` is still denied.
- `sops exec-env secrets.yaml 'npm test'` runs; `sops exec-env secrets.yaml 'printenv'` is denied.
- Ollama not running asks, with a message that says the judge was unavailable.
- A cloud model in `OPENCODE_SECRET_CLASSIFIER_MODEL` is refused, and nothing is sent to it.
- A deny message reaches the agent in a real OpenCode session.

## Later

Auto-approve (allow when the command is safe). Measured with `tev1:4b-q8_0`, `reversible` separated safe (0.83–0.93) from dangerous (0.32–0.48) commands, but `serves_task` was noise. Needs a larger labelled set and a model comparison before it is worth building.
