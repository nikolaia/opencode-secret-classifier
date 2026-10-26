# Jevrails

> [!WARNING]
> **Idea / draft. Not a security tool you should rely on.**
> This is an early proof of concept, written and tested in one sitting on one Mac. The rules are a short hand-written list, the model thresholds come from 44 hand-labelled commands, and it has only been run in a handful of real OpenCode sessions. It will miss secrets and it will deny harmless commands. The design, the API, and the defaults can all change. Use it to experiment, not to protect anything that matters.

An OpenCode plugin that denies shell commands that would print a secret value (an API key, a token, a private key, a decrypted secrets file) into the agent's context. It checks a built-in list first, then asks a small decision model running locally in Ollama. Nothing leaves your machine: the only network call is to `127.0.0.1:11434`.

It only ever denies or asks. It never approves a command that OpenCode would otherwise ask about. See [SPEC.md](SPEC.md) for the full design.

## Requirements

- An Apple Silicon Mac
- OpenCode 2.0.12 or later
- Ollama 0.35 or later, with the judge model pulled:

  ```sh
  ollama pull tev1:4b-q8_0
  ```

  Plain `tev1` is an MLX build and fails on an Ollama without the MLX runtime, such as the nix package. The `q8_0` tag is a GGUF build that runs anywhere.
- Node.js or Bun, to install dependencies

## Install

Install the dependencies:

```sh
npm install
```

Then add the plugin to the `plugins` array in an OpenCode config file. To use it in every project, put it in `~/.config/opencode/opencode.jsonc`; for one project, put it in that project's `opencode.jsonc`:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": [
    {
      "package": "/absolute/path/to/jevrails",
      "options": { "allow": ["sops -e *", "sops exec-env *"] }
    }
  ]
}
```

The path must be the repository directory, not `index.ts`. OpenCode loads a directory's `index` module and skips a path to a single file without logging anything.

OpenCode also loads plugins from `.opencode/plugins/` or `~/.config/opencode/plugins/` with no config entry. Plugins loaded that way get no options, so the allowlist cannot be set.

## Allowlist

`options.allow` lists commands that skip the model. `*` matches the rest of the command. Each part of a compound command (`a && b`, `a | b`) must match for the command to skip the model.

The built-in list always wins over the allowlist, so allowing `sops -d *` changes nothing. The command run by `sops exec-env`, `bash -c`, `sh -c`, `zsh -c`, or `eval` is checked on its own, so `sops exec-env secrets.yaml 'printenv'` is still denied.

## Settings

| Environment variable | Default | Meaning |
|---|---|---|
| `JEVRAILS_MODEL` | `tev1:4b-q8_0` | Ollama model used as the judge. A cloud model is refused. |
| `JEVRAILS_THRESHOLD` | `0.6` | `exposes_secret` score at or above which the model denies. |

## What happens to a shell command

1. It matches the built-in list → denied, without calling the model.
2. Every part matches the allowlist → left to OpenCode's normal rules.
3. The model scores `exposes_secret` at or above the threshold → denied.
4. Ollama is down, times out (8 s), or answers something unreadable → OpenCode asks you.
5. Otherwise → left to OpenCode's normal rules.

A denial reaches the agent as a tool error, for example:

```
jevrails: denied because the command names the credential file .env, which would print a secret value into the context.
```

## Test

```sh
npm test
```

The tests cover the built-in list, the allowlist, and nested commands. They do not need Ollama.

## Limits

- Shell only. Secrets read with OpenCode's own read tool are not covered, though OpenCode's built-in rules already ask before reading `*.env` files.
- The model is a 4B decision model. On 44 hand-labelled commands it caught 18 of 24 secret-exposing commands on its own; the built-in list covers the ones it missed. Scores close to the threshold can vary between runs.
