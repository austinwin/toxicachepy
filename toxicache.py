import argparse
import sys
import os
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

import concurrent.futures
import threading
import random
import datetime
from urllib.parse import urlparse, urlencode, parse_qs

REFLECT = 0
reflect_lock = threading.Lock()

def colorize(text, color_code):
    return f"\033[38;5;{color_code}m{text}\033[0m"

def print_banner():
    banner = """
_____  ___  __     _   ___    __    ___   _     ____ 
 | |  / / \\ \\ \_/ | | / / %s  / /\\  / / %s | |_| | |_  
 |_|  \\_\\_/ /_/ \\ |_| \\_\\_, /_/--\\ \\_\\_, |_| | |_|__ 

				      @xhzeem | v0.2				
    """ % ('`', '`')
    print(colorize(banner, "204"), file=sys.stderr)

def format_headers(headers):
    return ", ".join(f"{k}: {v}" for k, v in headers.items())

def has_cache_header(resp):
    cache_headers = [
        "x-cache", "cf-cache-status", "x-drupal-cache", "x-varnish-cache", "akamai-cache-status",
        "server-timing", "x-iinfo", "x-nc", "x-hs-cf-cache-status", "x-proxy-cache",
        "x-cache-hits", "x-cache-status", "x-cache-info", "x-rack-cache", "cdn_cache_status",
        "x-akamai-cache", "x-akamai-cache-remote", "x-cache-remote",
    ]
    resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    for header in cache_headers:
        if header.lower() in resp_headers_lower:
            return True
    return False

def toxic_param(target_url):
    random_value = random.randint(0, 9999)
    parsed = urlparse(target_url)
    query = parse_qs(parsed.query)
    query["toxicache"] = [str(random_value)]
    new_query = urlencode(query, doseq=True)
    return parsed._replace(query=new_query).geturl()

def check_header_reflected(target_url, inj_headers, check_value, user_agent):
    modified_url = toxic_param(target_url)
    headers = {"User-Agent": user_agent}
    headers.update(inj_headers)

    try:
        resp = requests.get(modified_url, headers=headers, verify=False, allow_redirects=False, timeout=30)
    except Exception:
        return False

    if not has_cache_header(resp):
        return False

    # Check response headers
    for header_values in resp.headers.values():
        if check_value in header_values:
            return True

    # Check response body
    try:
        body = resp.text
        if check_value in body:
            return True
    except Exception:
        pass

    return False

def process_check(url, hc, user_agent, output_file):
    global REFLECT
    reflected = check_header_reflected(url, hc["headers"], hc["check"], user_agent)
    if reflected:
        with reflect_lock:
            REFLECT += 1
            print("\n" + colorize("Headers reflected:", "11") + f" [{format_headers(hc['headers'])}]")
            print(url + "\n")
            with open(output_file, "a") as f:
                f.write(f"Headers reflected: {format_headers(hc['headers'])} @ {url}\n")

def main():
    parser = argparse.ArgumentParser(description="toxicache - Web Cache Poisoning Scanner")
    parser.add_argument("-i", "--input", type=str, default="", help="Input File Location")
    parser.add_argument("-o", "--output", type=str, default="", help="Output File Location")
    parser.add_argument("-ua", "--user-agent", type=str, 
                        default="Mozilla/5.0 (Macintosh; Intel Mac OS X 12_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
                        help="User Agent Header")
    parser.add_argument("-t", "--threads", type=int, default=(os.cpu_count() or 1) * 5, help="Number of Threads")

    args = parser.parse_args()

    if args.output == "":
        now = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        args.output = f"toxicache-{now}.txt"

    print(f"▶ Output will be saved to: {colorize(args.output + '\n', '80')}")

    # Determine input source
    if not sys.stdin.isatty():
        urls = [line.strip() for line in sys.stdin if line.strip()]
    elif args.input:
        if not os.path.isfile(args.input):
            print(f"Error: Input file {args.input} not found.", file=sys.stderr)
            sys.exit(1)
        with open(args.input) as f:
            urls = [line.strip() for line in f if line.strip()]
    else:
        print("No input provided (use -i or pipe URLs via stdin).", file=sys.stderr)
        sys.exit(1)

    if not urls:
        print("No URLs to process.", file=sys.stderr)
        sys.exit(0)

    print_banner()

    headers_to_check = [
        {"headers": {"X-Forwarded-Host": "xhzeem.me"}, "check": "xhzeem.me"},
        {"headers": {"X-Forwarded-For": "xhzeem.me"}, "check": "xhzeem.me"},
        {"headers": {"X-Rewrite-Url": "xhzeem.me"}, "check": "xhzeem.me"},
        {"headers": {"X-Host": "xhzeem.me"}, "check": "xhzeem.me"},
        {"headers": {"User-Agent": "xhzeem.me"}, "check": "xhzeem.me"},
        {"headers": {"Handle": "xhzeem.me"}, "check": "xhzeem.me"},
        {"headers": {"H0st": "xhzeem.me"}, "check": "xhzeem.me"},
        {"headers": {"Origin": "xhzeem.me"}, "check": "xhzeem.me"},
        {"headers": {"Transfer-Encoding": "xhzeem.me"}, "check": "xhzeem.me"},
        {"headers": {"X-Original-Url": "xhzeem.me"}, "check": "xhzeem.me"},
        {"headers": {"X-Original-Host": "xhzeem.me"}, "check": "xhzeem.me"},
        {"headers": {"X-Forwarded-Prefix": "xhzeem.me"}, "check": "xhzeem.me"},
        {"headers": {"X-Amz-Server-Side-Encryption": "xhzeem.me"}, "check": "xhzeem.me"},
        {"headers": {"X-Amz-Website-Redirect-Location": "xhzeem.me"}, "check": "xhzeem.me"},
        {"headers": {"Trailer": "xhzeem.me"}, "check": "xhzeem.me"},
        {"headers": {"Fastly-Ssl": "xhzeem.me"}, "check": "xhzeem.me"},
        {"headers": {"Fastly-Host": "xhzeem.me"}, "check": "xhzeem.me"},
        {"headers": {"Fastly-Ff": "xhzeem.me"}, "check": "xhzeem.me"},
        {"headers": {"Fastly-Client-ip": "xhzeem.me"}, "check": "xhzeem.me"},
        {"headers": {"Content-Type": "xhzeem.me"}, "check": "xhzeem.me"},
        {"headers": {"Api-Version": "xhzeem.me"}, "check": "xhzeem.me"},
        {"headers": {"AcunetiX-Header": "xhzeem.me"}, "check": "xhzeem.me"},
        {"headers": {"Accept-Version": "xhzeem.me"}, "check": "xhzeem.me"},
        {"headers": {"X-Forwarded-Proto": "13377"}, "check": ":13377"},
        {"headers": {"X-Forwarded-Host": "xhzeem.me", "X-Forwarded-Scheme": "http"}, "check": "xhzeem.me"},
    ]

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for url in urls:
            for hc in headers_to_check:
                futures.append(executor.submit(process_check, url, hc, args.user_agent, args.output))
        # Wait for completion
        for future in concurrent.futures.as_completed(futures):
            pass

    print(f"\n▶ Number of Reflections Found: {colorize(str(REFLECT), '80')}\n")

if __name__ == "__main__":
    main()
