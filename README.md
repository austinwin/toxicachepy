# toxicachepy

**toxicachepy** is a Python-based, cache-aware **header reflection scanner** inspired by the original Golang tool [toxicache](https://github.com/xhzeem/toxicache). the tool for educational purpose only.  

It identifies potential **web cache poisoning candidates** by injecting a fixed set of HTTP headers and reporting reflections **only when cache-related response headers are present**.

This tool does **not** confirm exploitability. It is designed to reduce noise during large-scale reconnaissance by filtering out reflections that do not appear to pass through a caching layer.

> Original concept by @xhzeem  
> Python implementation maintained informally

  
**python toxicache.py -i urls.txt --json**  
<img width="559" height="196" alt="image" src="https://github.com/user-attachments/assets/77c7dd97-6230-4282-bda8-ae91000cc1bb" />

---

## Key Features
*   **Smart Detection**: Checks for reflections in headers or body, but only if caching is detected.
*   **Two-Step Validation**: Optional re-request without injection to verify cache poisoning persistence.
*   **JSON Output**: Use `--json` for easy integration with jq or other pipelines.
*   **Proxy Support**: Tunnel requests through Burp/Zap using `--proxy`.
*   **Resilience**: Auto-retries on 429/5xx errors.
*   **Visual Feedback**: Colorful, structured console output with live progress stats.

## What This Tool Actually Does

- Injects **26 predefined HTTP header probes**
- Appends a random `toxicache=<int>` query parameter to each request
- Sends requests with redirects disabled
- Checks whether injected values are reflected in:
  - Response headers
  - Response body
- Reports reflections **only if at least one cache-related response header exists**
- Optionally validates findings with a second request (use `--validate` flag):
  - Re-requests the same URL without the malicious header
  - Checks if the poisoned content persists in the cache
  - Reports validation status to confirm actual cache poisoning

---

## Installation

```bash
git clone https://github.com/austinwin/toxicachepy.git
cd toxicachepy
pip install requests
```

---

## Usage

### Basic Scan

```bash
python toxicache.py -i urls.txt
```

### Piped Input (stdin)

```bash
cat urls.txt | python toxicache.py
```

### Custom Output and Threads

```bash
python toxicache.py -i urls.txt -o results.txt -t 50
```

### Two-Step Validation (Recommended)

Use `--validate` to confirm cache poisoning by re-requesting without malicious headers:

```bash
python toxicache.py -i urls.txt --validate
```

This performs:
1. Initial request with poisoned header injection
2. Follow-up request without injection to verify persistence

---

## Options

| Flag | Long Flag | Description | Default |
|-----:|-----------|-------------|---------|
| `-i` | `--input` | Input file containing URLs | None |
| `-o` | `--output` | Output file path | `toxicache-TIMESTAMP.txt` |
| `-t` | `--threads` | Number of concurrent threads | CPU count × 5 |
| | `--timeout` | Request timeout in seconds | 10 |
| | `--proxy` | Proxy URL (e.g., `http://127.0.0.1:8080`) | None |
| | `--json` | Output results in JSONL format | False |
| | `--payload` | Custom payload to inject | `xhzeem.me` |
| | `--validate` | Enable two-step validation to verify cache poisoning | False |
| | `--show-cache-headers` | Print detected cache headers | False |
| | `--insecure` | Disable TLS verification | False |
| | `--follow-redirects` | Follow HTTP redirects | False |
| | `--max-inflight` | Max active requests (for memory safety) | Auto |
| `-v` | `--verbose` | Enable verbose error logging | False |

---

## Example Output

**Console Output (without validation):**

```text
[+] Reflection found at https://example.com/
    ├─ Payload: X-Forwarded-Host: xhzeem.me
    ├─ Source:  Header(X-Reflected-Host)
    ├─ Status:  200
    └─ Cache:   HIT
```

**Console Output (with --validate):**

```text
[+] Reflection found at https://example.com/
    ├─ Payload: X-Forwarded-Host: xhzeem.me
    ├─ Source:  Header(X-Reflected-Host)
    ├─ Status:  200
    ├─ Cache:   HIT
    └─ Validation: ✓ VALIDATED (Persisted in Body, Status: 200)
```

**File Output (Default):**

```text
Reflected: X-Forwarded-Host: xhzeem.me | Loc: Header(X-Reflected-Host) | Status: 200 @ https://example.com/
```

**File Output (with --validate):**

```text
Reflected: X-Forwarded-Host: xhzeem.me | Loc: Header(X-Reflected-Host) | Status: 200 | Validated: YES (Persisted in Body) @ https://example.com/
```

**File Output (JSON):**

```json
{"url": "https://example.com/", "payload_headers": {"X-Forwarded-Host": "xhzeem.me"}, "source": "Header(X-Reflected-Host)", "status": 200, "cache_headers": ["x-cache"], "timestamp": "2026-01-17_16-01-55"}
```

**File Output (JSON with --validate):**

```json
{"url": "https://example.com/", "payload_headers": {"X-Forwarded-Host": "xhzeem.me"}, "source": "Header(X-Reflected-Host)", "status": 200, "cache_headers": ["x-cache"], "timestamp": "2026-01-17_16-01-55", "validated": true, "validation_source": "Body", "validation_status": 200}
```

Each entry represents a **header reflection that occurred in the presence of cache-related response headers**.

---

## Cache Awareness

A result is only reported if the response contains at least one of the following (non-exhaustive):

- `X-Cache`
- `CF-Cache-Status`
- `Server-Timing`
- `Akamai-Cache-Status`
- `X-Varnish`
- `X-Cache-Hits`

These headers are **not printed**, only checked internally.

---

## What This Tool Does NOT Do

- Does not guarantee cache poisoning (even with `--validate`, requires manual testing)
- Does not verify shared cache impact across different users
- Does not manipulate cache keys or cache behaviors
- Does not replace comprehensive manual security testing

**Note**: The `--validate` flag performs a two-step check to verify cache poisoning, but manual verification is still recommended for production security assessments.

---

## Burp Suite Comparison

| Capability | toxicachepy | Burp Suite |
|-----------|-------------|------------|
| Header reflection automation | Yes | Manual |
| Cache-aware filtering | Yes | No |
| Large URL list scanning | Yes | Poor |
| Two-step validation | Yes (with `--validate`) | Manual |
| Exploit confirmation | Limited | Yes |
| Proxy / GUI | No | Yes |

**Use toxicachepy** to find and validate candidates quickly.  
**Use Burp** for detailed manual testing and complex exploit chains.

---

## Legal Disclaimer

This tool is intended for **authorized security testing only**.

Do not scan systems you do not own or have explicit permission to test.

The authors assume **no responsibility** for misuse or damage.

---

## Credits

- Research & original concept: @xhzeem
- Python port: community-maintained

---

## License

Provided as-is, without warranty of any kind.
