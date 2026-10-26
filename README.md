# opencode-secret-classifier

> [!WARNING]
> **Idea / draft.** An early proof of concept, tested on one Mac. It will miss secrets and stop harmless commands. Don't rely on it.

**Keeps secrets and personal data out of your coding agent's context, judged entirely on your machine.**

An OpenCode plugin. A small decision model runs locally in Ollama; nothing is sent to a hosted service for judging.

| When | Secrets | Personal data |
|---|---|---|
| Before a shell command | Built-in list (`cat .env`, `printenv`, `sops -d`, …) → **deny**. Model flags it → **ask**. | — |
| After any tool | Always **masked** (`[token]`, `[secret]`, …) | **Masked** (`[email]`, `[national ID]`, …). Model flags names or addresses → **ask**: allow restores the data, reject withholds the output. |

It never approves anything OpenCode would otherwise ask about.

## Install

Needs OpenCode 2.0.12+ and Ollama 0.35+.

```sh
ollama pull tev1:4b-q8_0
npm install
```

Add the repository directory (not `index.ts`) to `~/.config/opencode/opencode.jsonc`, or a project's `opencode.jsonc`:

```jsonc
{
  "plugins": [
    { "package": "/absolute/path/to/opencode-secret-classifier", "options": { "allow": ["sops -e *"] } }
  ]
}
```

## Allowlist

`allow` lists commands that skip the model; `*` matches the rest. The built-in list still wins, so `cat .env` is always denied.

"Always" in a prompt only lasts for that exact command in this session. Use `allow` for permanent trust.

## Settings

| Environment variable | Default |
|---|---|
| `OPENCODE_SECRET_CLASSIFIER_MODEL` | `tev1:4b-q8_0` |
| `OPENCODE_SECRET_CLASSIFIER_THRESHOLD` | `0.6` (secret commands) |
| `OPENCODE_SECRET_CLASSIFIER_PERSONAL_DATA_THRESHOLD` | `0.6` (personal data in output) |
| `OPENCODE_SECRET_CLASSIFIER_OLLAMA_URL` | `http://127.0.0.1:11434` |

Ollama cloud models are refused.

## What stays on disk

OpenCode itself keeps local copies the plugin can't touch:

- Raw shell output in `~/.local/share/opencode/shell/`.
- Undo snapshots of files not in `.gitignore`. Keep secret files gitignored, or set `"snapshots": false`.

## Test

```sh
npm test         # rules and masking, no Ollama needed
node eval.ts     # model accuracy on 96 labelled commands
```

## Limits

- The command check is shell only; masking covers every tool, but only known formats.
- The model catches 43 of 46 secret-exposing commands in `eval.ts` and prompts on 4 of 50 harmless ones. Allowlist commands that prompt often.
