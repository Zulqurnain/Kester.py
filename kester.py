#!/usr/bin/env python3
"""
unified_key_checker.py

Usage:
    python unified_key_checker.py /path/to/keys.txt_or_rtf

What it does:
 - Extracts many types of keys from a single file (txt or rtf).
 - Uses heuristics + endpoint testing to classify keys into platform headings:
     OPENAI, GEMINI, GOOGLE_CLOUD, AWS, GROQ, OLLAMA, DEEPSEEK, GITHUB, OTHER
 - Tests keys online where possible (using urllib only).
 - Writes a log file `unified_key_check.log` next to the input file with sections:
     === PLATFORM ===
       -- WORKING --
       -- REJECTED --
       -- UNKNOWN --
"""

import re
import os
import sys
import urllib.request
import urllib.error
from collections import defaultdict
from typing import List, Tuple

# ---------------------------
# Patterns to extract keys
# ---------------------------
KEY_PATTERNS = {
    "OPENAI": re.compile(r"(sk-[A-Za-z0-9\-_]{20,64})"),
    # Google API keys (used by Google Cloud / Gemini). Use a flexible length.
    "GOOGLE_API_KEY": re.compile(r"(AIza[0-9A-Za-z_\-]{20,50})"),
    "AWS": re.compile(r"(AKIA[0-9A-Z]{16})"),
    "GROQ": re.compile(r"(groq_[0-9A-Za-z\-_]{10,64})"),
    "OLLAMA": re.compile(r"(ollama_[0-9A-Za-z\-_]{8,64})"),
    "DEEPSEEK": re.compile(r"(ds_[0-9A-Za-z\-_]{8,64})"),
    "GITHUB": re.compile(r"(ghp_[0-9A-Za-z\-_]{36})"),
    # Fallback: any long-looking token (avoid overmatching)
    "POTENTIAL_TOKEN": re.compile(r"([A-Za-z0-9\-_]{30,100})")
}

# ---------------------------
# Endpoint templates & behavior
# ---------------------------
ENDPOINTS = {
    # Header-based checks
    "OPENAI": {"url": "https://api.openai.com/v1/models", "auth_header": "Bearer"},
    "GITHUB": {"url": "https://api.github.com/user", "auth_header": "token"},
    "GROQ": {"url": "https://api.groq.ai/v1/models", "auth_header": "Bearer"},
    "OLLAMA": {"url": "https://api.ollama.com/models", "auth_header": "Bearer"},
    "DEEPSEEK": {"url": "https://api.deepseek.ai/v1/models", "auth_header": "Bearer"},
    # Key-as-query checks
    "GEMINI": {"url": "https://generativelanguage.googleapis.com/v1/models?key={}", "auth_header": None},
    "GOOGLE_CLOUD": {"url": "https://cloudresourcemanager.googleapis.com/v1/projects?key={}", "auth_header": None},
    # AWS: cannot test with single Access Key ID alone (needs secret + signed request)
    "AWS": {"url": None, "auth_header": None}
}

# ---------------------------
# Context heuristics for AIza keys
# ---------------------------
GEMINI_CONTEXT_TOKENS = ["gemini", "generativelanguage", "ai studio", "vertex ai", "google ai studio"]
GCLOUD_CONTEXT_TOKENS = ["gcp", "google_cloud", "gcloud", "project_id", "google cloud", "cloudresourcemanager"]

CONTEXT_RADIUS = 80  # characters around the match to examine

# ---------------------------
# Helpers
# ---------------------------
def read_file_content(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()

def extract_keys_with_context(content: str) -> List[Tuple[str, str, str]]:
    """
    Returns list of tuples: (key, platform_hint_from_pattern, surrounding_snippet)
    platform_hint_from_pattern is keys of KEY_PATTERNS (e.g., OPENAI, GOOGLE_API_KEY, AWS, ...)
    """
    found = {}
    for platform_hint, pattern in KEY_PATTERNS.items():
        for m in pattern.finditer(content):
            key = m.group(1)
            if key in found:
                continue
            start = max(0, m.start() - CONTEXT_RADIUS)
            end = min(len(content), m.end() + CONTEXT_RADIUS)
            snippet = content[start:end]
            found[key] = (platform_hint, snippet)
    # return list of tuples
    return [(k, v[0], v[1]) for k, v in found.items()]

def http_check_get(url: str, headers: dict = None, timeout: int = 6) -> bool:
    """Perform GET with optional headers; return True if status==200, False otherwise."""
    try:
        req = urllib.request.Request(url)
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except urllib.error.HTTPError as he:
        # he.code available; treat non-200 as invalid
        return False
    except urllib.error.URLError:
        return False
    except Exception:
        return False

# ---------------------------
# Classification + checking
# ---------------------------
def classify_google_api_key_by_context(snippet: str) -> str:
    low = snippet.lower()
    if any(tok in low for tok in GEMINI_CONTEXT_TOKENS):
        return "GEMINI"
    if any(tok in low for tok in GCLOUD_CONTEXT_TOKENS):
        return "GOOGLE_CLOUD"
    return "UNKNOWN_GOOGLE"

def test_key_for_platform(platform: str, key: str) -> bool:
    """
    Returns:
      True  -> working (200)
      False -> rejected (non-200 or error)
      None  -> cannot test (unknown / not supported)
    """
    meta = ENDPOINTS.get(platform)
    if not meta:
        return None
    url_template = meta.get("url")
    auth_header = meta.get("auth_header")
    if not url_template:
        # e.g., AWS: cannot be validated by simple GET without signature/secret
        return None
    if auth_header:
        # header-based request
        url = url_template
        headers = {"Authorization": f"{auth_header} {key}"}
        return http_check_get(url, headers=headers)
    else:
        # key-in-query request
        url = url_template.format(key)
        return http_check_get(url)

def classify_and_test_google_key(key: str, snippet: str) -> Tuple[str, bool]:
    """
    Given an AIza key, use context heuristics + endpoint testing to classify into
    'GEMINI' or 'GOOGLE_CLOUD' (or 'UNKNOWN_GOOGLE'), and test working status.
    Returns: (final_platform_label, working_bool_or_None)
    """
    # Context guess
    guess = classify_google_api_key_by_context(snippet)
    # First, definitive check: test Gemini endpoint (most specific for generative)
    gemini_result = test_key_for_platform("GEMINI", key)
    if gemini_result is True:
        return "GEMINI", True
    if gemini_result is False:
        # if explicit fail, continue to test generic google endpoint
        pass
    # Test generic Google Cloud endpoint
    gcloud_result = test_key_for_platform("GOOGLE_CLOUD", key)
    if gcloud_result is True:
        return "GOOGLE_CLOUD", True
    if gcloud_result is False:
        # Neither endpoint accepted the key -> return context guess and rejected
        if guess == "GEMINI":
            return "GEMINI", False
        if guess == "GOOGLE_CLOUD":
            return "GOOGLE_CLOUD", False
        return "GOOGLE_UNKNOWN", False
    # If both returned None or were inconclusive:
    return guess if guess != "UNKNOWN_GOOGLE" else "GOOGLE_UNKNOWN", None

# ---------------------------
# Main flow
# ---------------------------
def main():
    if len(sys.argv) < 2:
        print("Usage: python unified_key_checker.py /path/to/keys.txt_or_rtf")
        sys.exit(1)

    source_file = sys.argv[1]
    if not os.path.exists(source_file):
        print(f"❌ File not found: {source_file}")
        sys.exit(1)

    content = read_file_content(source_file)
    extracted = extract_keys_with_context(content)

    # Prepare results structure
    platforms = ["OPENAI", "GEMINI", "GOOGLE_CLOUD", "GOOGLE_UNKNOWN", "AWS", "GROQ", "OLLAMA", "DEEPSEEK", "GITHUB", "OTHER"]
    results = {p: {"WORKING": [], "REJECTED": [], "UNKNOWN": []} for p in platforms}
    results["OTHER"] = {"WORKING": [], "REJECTED": [], "UNKNOWN": []}

    processed_keys = set()

    print(f"Found {len(extracted)} candidate keys. Testing where possible...\n")

    for key, hint, snippet in extracted:
        if key in processed_keys:
            continue
        processed_keys.add(key)

        # Decide initial platform from pattern hint
        if hint == "GOOGLE_API_KEY":
            final_label, status = classify_and_test_google_key(key, snippet)
            if status is True:
                results.setdefault(final_label, {"WORKING": [], "REJECTED": [], "UNKNOWN": []})["WORKING"].append(key)
                print(f"✅ WORKING ({final_label}): {key}")
            elif status is False:
                results.setdefault(final_label, {"WORKING": [], "REJECTED": [], "UNKNOWN": []})["REJECTED"].append(key)
                print(f"❌ REJECTED ({final_label}): {key}")
            else:
                results.setdefault(final_label, {"WORKING": [], "REJECTED": [], "UNKNOWN": []})["UNKNOWN"].append(key)
                print(f"⚠️ UNKNOWN ({final_label}): {key}")
            continue

        # Non-Google keys - try to test where possible
        if hint in ("OPENAI", "GITHUB", "GROQ", "OLLAMA", "DEEPSEEK"):
            status = test_key_for_platform(hint, key)
            if status is True:
                results[hint]["WORKING"].append(key)
                print(f"✅ WORKING ({hint}): {key}")
            elif status is False:
                results[hint]["REJECTED"].append(key)
                print(f"❌ REJECTED ({hint}): {key}")
            else:
                results[hint]["UNKNOWN"].append(key)
                print(f"⚠️ UNKNOWN ({hint}): {key}")
            continue

        if hint == "AWS":
            # We cannot validate an AWS access key id without a secret & signing.
            results["AWS"]["UNKNOWN"].append(key)
            print(f"⚠️ AWS (cannot validate without secret/signature): {key}")
            continue

        # POTENTIAL_TOKEN or other long token - try heuristic tests (OpenAI/GitHub header first)
        if hint == "POTENTIAL_TOKEN":
            # Try OpenAI
            tried = False
            for platform_try in ("OPENAI", "GITHUB", "GROQ", "DEEPSEEK", "OLLAMA"):
                status = test_key_for_platform(platform_try, key)
                if status is True:
                    results[platform_try]["WORKING"].append(key)
                    print(f"✅ WORKING ({platform_try}): {key}")
                    tried = True
                    break
                elif status is False:
                    # keep trying other platforms
                    tried = True
                    continue
            if not tried:
                results["OTHER"]["UNKNOWN"].append(key)
                print(f"⚠️ UNKNOWN (OTHER): {key}")
            else:
                # if tried but none returned True, record as REJECTED under OTHER
                if all(test_key_for_platform(p, key) is not True for p in ("OPENAI", "GITHUB", "GROQ", "DEEPSEEK", "OLLAMA")):
                    results["OTHER"]["REJECTED"].append(key)
                    print(f"❌ REJECTED (OTHER heuristics): {key}")
            continue

        # Fallback - mark as OTHER unknown
        results["OTHER"]["UNKNOWN"].append(key)
        print(f"⚠️ OTHER (unclassified): {key}")

    # Write structured log file
    log_file = os.path.join(os.path.dirname(source_file), "unified_key_check.log")
    with open(log_file, "w", encoding="utf-8") as out:
        for platform in platforms + ["OTHER"]:
            if platform not in results:
                continue
            out.write(f"=== {platform} ===\n")
            for status in ("WORKING", "REJECTED", "UNKNOWN"):
                out.write(f"-- {status} --\n")
                arr = results[platform][status]
                if arr:
                    for k in arr:
                        out.write(k + "\n")
                else:
                    out.write("No keys\n")
                out.write("\n")
            out.write("\n")

    print(f"\nDone. Log written to: {log_file}")

if __name__ == "__main__":
    main()
