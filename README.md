# toxicachepy

**Python port** of the popular [toxicache](https://github.com/xhzeem/toxicache) Golang scanner.  
Detects potential **web cache poisoning** vulnerabilities by injecting common headers that are often mistakenly trusted by caches (CDNs, reverse proxies, etc.) and checking if they are reflected in responses.

The tool focuses on sites that expose cache-related headers (e.g., `CF-Cache-Status`, `X-Cache`, etc.) and only reports reflections when such headers are present — reducing false positives.

Original concept and header list by [@xhzeem](https://github.com/xhzeem).  
Python port maintained informally (feel free to contribute!).

## Features

- Tests **25+ known header injection vectors** commonly abused in cache poisoning attacks.
- Adds a random `toxicache=<random>` query parameter to each request to help bypass cache normalization and ensure fresh responses.
- Concurrent scanning with configurable threads (default: CPU cores × 5).
- Supports input via stdin (piping) or file.
- Colored terminal output with a banner.
- Saves results to a timestamped file.
- Disables SSL verification and follows no redirects (mirroring the original behavior).
- Only reports reflections when a known cache header is present in the response.

## Installation

```bash
# Clone or download the script
git clone https://github.com/austinwin/toxicachepy.git  # (or just download the .py file)
cd toxicachepy

# Install the only dependency
pip install requests
