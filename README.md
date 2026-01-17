# toxicachepy

**toxicachepy** is a Python-based, cache-aware **header reflection scanner** inspired by the original Golang tool [toxicache](https://github.com/xhzeem/toxicache).

It identifies potential **web cache poisoning candidates** by injecting a fixed set of HTTP headers and reporting reflections **only when cache-related response headers are present**.

This tool does **not** confirm exploitability. It is designed to reduce noise during large-scale reconnaissance by filtering out reflections that do not appear to pass through a caching layer.

> Original concept by @xhzeem  
> Python implementation maintained informally

  
**python toxicache.py -i urls.txt --json**  
<img width="559" height="196" alt="image" src="https://github.com/user-attachments/assets/77c7dd97-6230-4282-bda8-ae91000cc1bb" />

---

## Key Features
*   **Smart Detection**: Checks for reflections in headers or body, but only if caching is detected.
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
| | `--show-cache-headers` | Print detected cache headers | False |
| | `--insecure` | Disable TLS verification | False |
| | `--follow-redirects` | Follow HTTP redirects | False |
| | `--max-inflight` | Max active requests (for memory safety) | Auto |
| `-v` | `--verbose` | Enable verbose error logging | False |

---

## Example Output

**Console Output:**

```text
[+] Reflection found at https://example.com/
    ├─ Payload: X-Forwarded-Host: xhzeem.me
    ├─ Source:  Header(X-Reflected-Host)
    ├─ Status:  200
    └─ Cache:   HIT
```

**File Output (Default):**

```text
Reflected: X-Forwarded-Host: xhzeem.me | Loc: Header(X-Reflected-Host) | Status: 200 @ https://example.com/
```

**File Output (JSON):**

```json
{"url": "https://example.com/", "payload_headers": {"X-Forwarded-Host": "xhzeem.me"}, "source": "Header(X-Reflected-Host)", "status": 200, "cache_headers": ["x-cache"], "timestamp": "2026-01-17_16-01-55"}
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

- Does not confirm cache poisoning
- Does not verify shared cache impact
- Does not manipulate cache keys
- Does not retry requests to validate poisoning
- Does not replace manual testing

All findings **require manual verification**.

---

## Burp Suite Comparison

| Capability | toxicachepy | Burp Suite |
|-----------|-------------|------------|
| Header reflection automation | Yes | Manual |
| Cache-aware filtering | Yes | No |
| Large URL list scanning | Yes | Poor |
| Exploit confirmation | No | Yes |
| Proxy / GUI | No | Yes |

**Use toxicachepy** to find candidates.  
**Use Burp** to prove impact.

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
