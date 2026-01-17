# toxicachepy

**Python port** of the popular [toxicache](https://github.com/xhzeem/toxicache) Golang scanner.

`toxicachepy` detects potential **web cache poisoning** vulnerabilities by injecting common headers often mistakenly trusted by caches (CDNs, reverse proxies, etc.) and checking if the injected input is reflected in the response.

The tool focuses on sites that expose cache-related headers (e.g., `CF-Cache-Status`, `X-Cache`, etc.) and only reports reflections when such headers are present—significantly reducing false positives.

> **Note:** Original concept and header list by [@xhzeem](https://github.com/xhzeem). This Python port is maintained informally.

## Features

* **Extensive Vectors:** Tests **25+ known header injection vectors** (e.g., `X-Forwarded-Host`, `X-Rewrite-Url`) commonly abused in cache poisoning attacks.
* **Cache Busting:** Automatically appends a random `toxicache=<random>` query parameter to every request to bypass cache normalization and ensure fresh responses.
* **Smart Detection:** Only reports reflections if the server response also contains known caching headers (e.g., `X-Cache`, `Server-Timing`, `Akamai-Cache-Status`).
* **High Performance:** Concurrent scanning with configurable threads (Default: CPU cores × 5).
* **Flexible Input:** Supports reading URLs from a file or via standard input (stdin/piping).
* **Detailed Output:** Colored terminal output and automatic saving to timestamped text files.

## Installation

1.  **Clone the repository** (or download the script):
    ```bash
    git clone [https://github.com/your-username/toxicachepy.git](https://github.com/your-username/toxicachepy.git)
    cd toxicachepy
    ```

2.  **Install dependencies**:
    The tool relies on `requests` to handle HTTP connections.
    ```bash
    pip install requests
    ```

## Usage

### Basic Usage
To scan a list of URLs from a file:
```bash
python toxicache.py -i urls.txt
```

### Piping Input (Stdin)
You can pipe URLs directly from other tools (like `waybackurls`, `subfinder`, or `cat`):
```bash
cat urls.txt | python toxicache.py
```
### Customizing Output & Performance
Specify a custom output file and increase the number of threads:
```bash
python toxicache.py -i urls.txt -o my_scan_results.txt -t 50
```
How It Works  
Parsing: The script reads URLs from the provided input.  

Injection: For every URL, it iterates through a list of ~25 headers known to cause poisoning.  

Cache Busting: A unique query parameter (?toxicache=1234) is added to the URL to force the cache to treat it as a new resource.  

Verification:

The script checks if the response contains specific Cache Headers (like X-Cache or CF-Cache-Status). If no cache headers are found, the result is ignored to avoid false positives on non-cached pages.  

If cache headers are present, it checks if the injected payload (xhzeem.me) is reflected in the response headers or body.

Reporting: Successful reflections are printed to the console and saved to the output file.

Legal Disclaimer
This tool is created for educational purposes and authorized security testing only. Do not use this tool on systems or domains you do not own or do not have explicit permission to test. The authors are not responsible for any misuse or damage caused by this tool.


