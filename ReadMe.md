# Unified Key Checker

**A lightweight, single-file Python tool** to extract and validate API/AI/cloud keys from a single text or RTF file, classify them by platform, test them online (where possible), and produce a structured log file.

This repository contains `unified_key_checker.py` — a no-dependencies script (uses Python's built-in `urllib`) so it runs out-of-the-box on macOS and Windows with system Python or inside a virtual environment.

---

## Features

* Extracts a wide range of keys from one input file (supports `.txt` and `.rtf`).
* Recognizes and classifies keys for platforms including:

  * **OpenAI** (`sk-...`)
  * **Google** (`AIza...`) — uses heuristics + endpoint testing to separate **GEMINI** vs **GOOGLE\_CLOUD**
  * **AWS** (Access Key IDs like `AKIA...`) — marked as *unknown* (cannot validate without secret)
  * **Groq**, **Ollama**, **DeepSeek**, **GitHub** and more
* Tests keys online where possible using platform-specific endpoints and records whether keys are: `WORKING`, `REJECTED`, or `UNKNOWN`.
* Writes a human-readable log file next to the input file: `unified_key_check.log` with sections per platform.
* No third-party packages required — works with built-in Python libraries.

---

## Quick Start

1. **Clone** this repository (or copy `unified_key_checker.py`) into a folder.

2. (Optional but recommended) Create and activate a virtual environment:

```bash
python3 -m venv venv
# macOS / Linux
source venv/bin/activate
# Windows (cmd)
venv\Scripts\activate
```

3. **Run** the checker against your file (plain text or RTF):

```bash
python unified_key_checker.py /full/path/to/your/keys.txt
```

4. After completion you'll see terminal output and a `unified_key_check.log` saved in the same folder as the input file.

---

## Example log layout (`unified_key_check.log`)

```
=== GEMINI ===
-- WORKING --
AIza...validkey1

-- REJECTED --
No keys

-- UNKNOWN --
No keys

=== OPENAI ===
-- WORKING --
sk-...workingkey

-- REJECTED --
sk-...badkey

-- UNKNOWN --
No keys

=== AWS ===
-- WORKING --
No keys

-- REJECTED --
No keys

-- UNKNOWN --
AKIA... (cannot validate without secret)
```

---

## How classification works for Google API keys

Google API keys (the public-style key that starts with `AIza`) are used for many Google services — including **Google Cloud** and the **Generative Language (Gemini)** API. Because they share the same prefix, the script:

1. Extracts all `AIza` keys using a regex.
2. Captures the surrounding text (context) around each match to detect clues like `GEMINI`, `AI_STUDIO`, `GCP`, `VERTEX`, `PROJECT_ID`.
3. Definitively tests keys against the **Gemini** endpoint first (`generativelanguage.googleapis.com/v1/models?key=...`). If that returns 200, the key is classified as **GEMINI**.
4. If Gemini fails, it tries a generic Google Cloud endpoint (e.g., Cloud Resource Manager). If that returns 200, the key is classified as **GOOGLE\_CLOUD**.
5. If neither test succeeds, the script falls back to the context-based guess and marks the key `REJECTED` or `UNKNOWN`.

This hybrid approach (context + endpoint testing) is more reliable than matching format alone.

---

## Limitations & Notes

* **AWS validation:** An AWS Access Key ID (e.g., `AKIA...`) cannot be validated with a simple GET — it requires a secret access key and signed request. The script marks such keys `UNKNOWN` and notes that validation needs the secret and a signed request.
* **Rate limits & quotas:** Testing many keys rapidly may hit API rate limits. Use responsibly.
* **False negatives:** A key may exist but be restricted to specific APIs or projects; it may fail a platform test even though it’s valid in another context.
* **Security & privacy:** Do **not** commit logs containing real keys to public repositories. Treat logs as sensitive information. Consider redacting keys or storing logs locally only.

---

## Extending the script

* Add new regex patterns in the `KEY_PATTERNS` dictionary.
* Add platform endpoints and auth header styles to the `ENDPOINTS` mapping.
* Add parallelism (thread pool) to speed up testing of many keys.
* Output JSON/CSV summaries for programmatic consumption.

---

## Troubleshooting

* If Python complains about missing libraries, the script is intentionally dependency-free — ensure you're running it with a standard Python 3 interpreter.
* For macOS PEP 668 errors, use a virtual environment (see Quick Start).
* If `.rtf` files appear to include garbage, open and save them as **Plain Text** or let the script parse them (it ignores RTF control characters but may still capture tokens).

---

## Security Reminder

**DO NOT** push real API credentials to public repositories. Use this tool locally and securely. If you need to share results, redact or replace keys with placeholders.

---

## License

This repository is provided under the **MIT License** — see `LICENSE` for details.

---

## Contributing

Contributions, bug reports, and feature requests are welcome. Open a GitHub issue or send a pull request.
