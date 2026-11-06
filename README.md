# Cosine 🛡️

> Static Application Security Testing (SAST) engine specialized for Lua codebases (Lua 5.1–5.4 and LuaJIT).

Cosine performs automated security analysis on Lua source files to discover vulnerabilities, dangerous runtime practices, and credential leaks. It features zero external dependencies, automated model retries/fallbacks, and terminal ANSI reporting.

---

## ✨ Features

- **Multi-Provider AI Architecture**: Native support for **Google Gemini**, **Anthropic Claude**, **Alibaba Qwen**, **OpenAI**, **OpenRouter**, **DeepSeek**, and **Local LLMs** (Ollama, vLLM) without external SDKs.
- **Lua-Specific Auditing**: Detects issues considering metatables, `_G` environment pollution, C-API boundaries, and dynamic module loading.
- **Zero External Dependencies**: Pure Lua standard library (`io`, `os`, `string`, `table`) with `curl`. Runs seamlessly on Lua 5.1, 5.2, 5.3, 5.4, and LuaJIT.
- **High-Demand Resilience**: Automatic retry with exponential backoff and seamless fallback cascading across models.
- **Zero False Positives Mandate**: Strict anti-hallucination rules and realistic threat modeling. Distinguishes benign local CLI idioms from genuine attack vectors. See [docs/AUDITING_RULES.md](docs/AUDITING_RULES.md).
- **Rich ANSI Terminal Reports**: Categorized severity badges (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), precise code locations, descriptions, exploit scenarios, and recommended remediations.
- **Automated JSON Export**: Saves machine-readable findings to `results.json` for CI/CD integration.
- **Project-Wide Scanning**: Recursively scans and aggregates findings across entire projects with `cosine check_project`.

---

## 🎯 Target Vulnerabilities

- **Insecure Shell/Process Execution**: Unsanitized string concatenation or variable interpolation into `os.execute`, `io.popen`, or custom subprocess wrappers.
- **Dynamic Code Execution**: Dangerous use of `load`, `loadstring`, or bytecode loading with untrusted inputs.
- **Debug Library Abuse**: Risky access to `debug.getinfo`, `debug.setlocal`, `debug.upvaluejoin`, or raw memory modifications.
- **Path Traversal & Insecure File System Access**: Arbitrary path creation in `io.open`, `os.remove`, or `package.path` manipulation.
- **Environment Pollution**: Unintended leaks into the global namespace (`_G`) that could cause state corruption or race conditions.
- **Leaked Credentials**: Hardcoded API keys, auth headers, private secrets, or internal service URLs.

---

## 🚀 Installation

### Option 1: Quick Install via Makefile (Recommended)

```bash
git clone https://github.com/davidykmisha2015-prog/cosine.git
cd cosine
make install
```

This installs the `cosine` executable into `~/.local/bin` (make sure `~/.local/bin` is in your `$PATH`).

### Option 2: Run Directly

You can execute directly from the cloned repository:

```bash
./bin/cosine --help
```

---

## 🔑 Setup & Supported Providers

Cosine automatically detects your provider based on your environment variables, or you can specify it via `-p, --provider`.

| Provider | Environment Variable | Default Model | Manual Flag |
|---|---|---|---|
| **Google Gemini** | `GEMINI_API_KEY` | `gemini-3.8-flash` | `-p gemini` |
| **Anthropic Claude** | `ANTHROPIC_API_KEY` / `CLAUDE_API_KEY` | `claude-3-5-haiku-20241022` | `-p claude` |
| **Alibaba Qwen** | `QWEN_API_KEY` / `DASHSCOPE_API_KEY` | `qwen-plus` | `-p qwen` |
| **OpenAI** | `OPENAI_API_KEY` | `gpt-4o-mini` | `-p openai` |
| **OpenRouter** | `OPENROUTER_API_KEY` | `qwen/qwen-2.5-coder-32b-instruct` | `-p openrouter` |
| **DeepSeek** | `DEEPSEEK_API_KEY` | `deepseek-chat` | `-p deepseek` |
| **Local / Custom** | `COSINE_API_KEY` / `OPENAI_BASE_URL` | `default` | `-p custom --base-url <url>` |

### Quick Start by Provider

```bash
# Using Alibaba Qwen
export QWEN_API_KEY="sk-..."
cosine script.lua

# Using Anthropic Claude
export ANTHROPIC_API_KEY="sk-ant-..."
cosine script.lua

# Using Google Gemini
export GEMINI_API_KEY="AIza..."
cosine script.lua

# Using Local Ollama / vLLM
cosine --provider custom --base-url http://localhost:11434/v1/chat/completions script.lua
```

---

## 💻 Usage

### Audit a Single File

```bash
cosine /path/to/script.lua
# or
cosine check /path/to/script.lua
```

### Audit an Entire Project

Recursively scan all `.lua` files in a directory or project root:

```bash
cosine check_project /path/to/project
```

### CLI Options

| Flag | Description |
|---|---|
| `-p, --provider <name>` | Select provider: `gemini`, `claude`, `qwen`, `openai`, `openrouter`, `deepseek`, `custom` |
| `-k, --api-key <key>` | Pass API key directly via CLI (overrides environment variable) |
| `-m, --model <name>` | Custom model ID for selected provider |
| `--base-url <url>` | Custom base URL for OpenAI-compatible endpoints (Ollama, vLLM, etc.) |
| `-o, --output <file>` | Custom JSON report file path (default: `results.json`) |
| `--no-color` | Disable ANSI terminal colors |
| `-s, --silent` | Suppress progress logs and display only findings |
| `-v, --version` | Display version information |
| `-h, --help` | Display help banner |

### Example Terminal Output

```text
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  COSINE SAST AUDIT REPORT
  Total Findings: 2  (CRITICAL: 1 | HIGH: 0 | MEDIUM: 1 | LOW: 0)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [CRITICAL]  Command Injection
  Location:       src/backup.lua:52
  Description:    User input concatenated into 'io.popen' without sanitization.
  Exploit Vector: Passing filenames containing shell metacharacters triggers arbitrary shell commands.
  Remediation:    Validate input against an allowlist and escape shell parameters.

  ─────────────────────────────────────────────────────────────────────────

  [MEDIUM]  Insecure File System Access
  Location:       src/config.lua:40
  Description:    Path constructed using unvalidated environment variable.
  Exploit Vector: Tampered environment variables may trick the script into accessing arbitrary files.
  Remediation:    Validate resolved paths against an authorized base directory.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## 📄 License

GNU General Public License v3.0 (GPL-3.0) © 2026 Davidyk Misha
