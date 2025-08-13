# Kester.py

**Kester.py** — a lightweight, single-file Python tool to extract and validate API / AI / cloud keys from one input file and classify them by platform.

> No external dependencies. Built on Python's standard library so it runs out-of-the-box on macOS and Windows (or inside a virtual environment).

---

## What it does

* Reads a single input file (plain `.txt` or `.rtf`).
* Extracts many API key formats (OpenAI, Google `AIza`, AWS `AKIA`, Groq, Ollama, DeepSeek, GitHub, and more).
* Uses **context heuristics** and **endpoint testing** to separate Google-style keys into **GEMINI** vs **GOOGLE\_CLOUD** when possible.
* Tests keys online where feasible (using `urllib`) and classifies them as `WORKING`, `REJECTED`, or `UNKNOWN`.
* Writes a readable log file next to the input file (default: `kester_key_check.log`).

---

## Features

* Single-file, dependency-free Python script (`Kester.py`).
* Supports `.txt` and `.rtf` inputs.
* Platform-aware classification and online validation (where possible).
* Safe for local use — no external packages required.
* Easily extensible: add regexes or endpoints to support more providers.

---

## Quick start

1. Copy `Kester.py` into a folder.

2. (Optional but recommended) Create and activate a virtual environment:

```bash
python3 -m venv venv
# macOS / Linux
source venv/bin/activate
# Windows (cmd)
venv\Scripts\activate
```

3. Run the script against your file:

```bash
python Kester.py /full/path/to/your/keys.txt
```

4. The script prints results to the terminal and saves a log file next to the input file named `kester_key_check.log`.

---

## Log layout

The log file is organized by platform sections, each containing three subsections:

```
=== PLATFORM ===
-- WORKING --
...keys...

-- REJECTED --
...keys...

-- UNKNOWN --
...keys...
```

Common platform headings: `GEMINI`, `GOOGLE_CLOUD`, `OPENAI`, `AWS`, `GROQ`, `OLLAMA`, `DEEPSEEK`, `GITHUB`, `OTHER`.

---

## How Google key classification works

Because Google API keys share the same `AIza` prefix across many services, Kester.py uses a hybrid method:

1. Extract all `AIza...` keys and capture surrounding text.
2. Use context hints (variable names or nearby words like `GEMINI`, `AI_STUDIO`, `GCP`, `VERTEX`) to make an initial guess.
3. Attempt a **Gemini-specific** endpoint test first — if it returns `200`, classify as **GEMINI**.
4. If Gemini fails, try a generic Google Cloud endpoint — success means **GOOGLE\_CLOUD**.
5. If both fail, fall back to context-based guess and mark the key `REJECTED` or `UNKNOWN`.

This approach reduces false classifications compared to format-only matching.

---

## Limitations & notes

* **AWS keys:** An AWS Access Key ID (e.g., `AKIA...`) cannot be validated without the secret access key and a signed request — Kester marks these as `UNKNOWN`.
* **Rate limits:** Rapidly testing many keys may hit provider rate limits — use responsibly.
* **Restricted keys:** A key may exist but be limited to specific APIs or projects; tests against particular endpoints may fail even though the key is otherwise valid.
* **Security:** **Do not** commit real keys or logs to a public repo. Treat logs as sensitive data; consider redaction before sharing.

---

## Extending Kester.py

* Add new patterns in the `KEY_PATTERNS` section.
* Add or change endpoints in the `ENDPOINTS` mapping.
* Add parallelism (thread pool) to speed up many checks.
* Export JSON/CSV summaries in addition to the human-readable log.

---

## License & contribution

This project is licensed under the MIT License. See `LICENSE` for details.

Contributions, issues, and feature requests are welcome — open a GitHub issue or a pull request.
