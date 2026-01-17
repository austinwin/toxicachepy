# toxicachepy

**toxicachepy** is a Python-based, cache-aware **header reflection scanner** inspired by the original Golang tool [toxicache](https://github.com/xhzeem/toxicache).

It identifies potential **web cache poisoning candidates** by injecting a fixed set of HTTP headers and reporting reflections **only when cache-related response headers are present**.

This tool does **not** confirm exploitability. It is designed to reduce noise during large-scale reconnaissance by filtering out reflections that do not appear to pass through a caching layer.

> Original concept by @xhzeem  
> Python implementation maintained informally

---

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

| Flag | Long Flag     | Description                  | Default |
|-----:|---------------|------------------------------|---------|
| -i   | --input       | Input file containing URLs   | None |
| -o   | --output      | Output file path             | toxicache-YYYY-MM-DD_HH-MM-SS.txt |
| -t   | --threads     | Number of concurrent threads | CPU count × 5 |
| -ua  | --user-agent  | Custom User-Agent string     | Chrome/111.0.0.0 |

---

## Example Output

Console output:

```text
Headers reflected: X-Forwarded-Host: xhzeem.me
https://example.com
```

File output:

```text
Headers reflected: X-Forwarded-Host: xhzeem.me @ https://example.com
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
