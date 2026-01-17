import argparse
import concurrent.futures
import datetime as dt
import os
import random
import sys
import threading
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning


# -----------------------------
# Config / constants
# -----------------------------

CACHE_HEADERS = [
    "x-cache",
    "cf-cache-status",
    "x-drupal-cache",
    "x-varnish-cache",
    "akamai-cache-status",
    "server-timing",
    "x-iinfo",
    "x-nc",
    "x-hs-cf-cache-status",
    "x-proxy-cache",
    "x-cache-hits",
    "x-cache-status",
    "x-cache-info",
    "x-rack-cache",
    "cdn_cache_status",
    "x-akamai-cache",
    "x-akamai-cache-remote",
    "x-cache-remote",
]

BANNER = r"""
_____  ___  __     _   ___    __    ___   _     ____ 
 | |  / / \ \ \_/ | | / / `  / /\  / / ` | |_| | |_  
 |_|  \_\_/ /_/ \ |_| \_\_, /_/--\ \_\_, |_| | |_|__ 

                      @xhzeem | v0.2 (python port)
"""


# -----------------------------
# Thread-local session (fast)
# -----------------------------

_tls = threading.local()

def get_session(insecure: bool) -> requests.Session:
    s = getattr(_tls, "session", None)
    if s is None:
        s = requests.Session()
        _tls.session = s
    # If insecure is true, suppress warnings once globally
    if insecure:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    return s


# -----------------------------
# Utilities
# -----------------------------

def colorize(text: str, color_code: str) -> str:
    return f"\033[38;5;{color_code}m{text}\033[0m"


def print_banner() -> None:
    print(colorize(BANNER, "204"), file=sys.stderr)


def now_timestamp() -> str:
    return dt.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def normalize_url(url: str) -> Optional[str]:
    """
    Normalize URLs:
    - trims whitespace
    - if scheme missing, assume https
    - drops fragments
    """
    u = url.strip()
    if not u:
        return None

    parsed = urlparse(u)
    if not parsed.scheme:
        # Assume https if scheme missing
        parsed = urlparse("https://" + u)

    # Require host
    if not parsed.netloc:
        return None

    # Drop fragments
    parsed = parsed._replace(fragment="")
    return urlunparse(parsed)


def dedupe_preserve_order(urls: Iterable[str]) -> List[str]:
    seen = set()
    out = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def format_headers(headers: Dict[str, str]) -> str:
    return ", ".join(f"{k}: {v}" for k, v in headers.items())


def inject_toxic_param(target_url: str, token: str) -> str:
    """
    Add/replace toxicache param to bust normalization.
    Uses a stable per-run token (easier debugging / validation).
    """
    parsed = urlparse(target_url)
    query = parse_qs(parsed.query)
    query["toxicache"] = [token]
    new_query = urlencode(query, doseq=True)
    return parsed._replace(query=new_query).geturl()


def detect_cache_headers(resp: requests.Response) -> List[str]:
    resp_headers_lower = {k.lower(): k for k in resp.headers.keys()}
    hits = []
    for h in CACHE_HEADERS:
        if h in resp_headers_lower:
            # Keep original case from response if possible
            hits.append(resp_headers_lower[h])
    return hits


@dataclass(frozen=True)
class Probe:
    headers: Dict[str, str]
    check: str


# -----------------------------
# Core logic
# -----------------------------

def check_reflection(
    url: str,
    probe: Probe,
    user_agent: str,
    timeout: int,
    insecure: bool,
    follow_redirects: bool,
    token: str,
) -> Tuple[bool, List[str], str]:
    """
    Returns:
      (reflected, cache_header_hits, modified_url)
    """
    modified_url = inject_toxic_param(url, token)

    # IMPORTANT: The probe may include User-Agent; keep behavior consistent:
    # Start with baseline UA then overlay probe headers.
    headers = {"User-Agent": user_agent}
    headers.update(probe.headers)

    try:
        sess = get_session(insecure)
        resp = sess.get(
            modified_url,
            headers=headers,
            verify=not insecure,
            allow_redirects=follow_redirects,
            timeout=timeout,
        )
    except requests.RequestException:
        return (False, [], modified_url)

    cache_hits = detect_cache_headers(resp)
    if not cache_hits:
        return (False, [], modified_url)

    # Check response headers values
    for v in resp.headers.values():
        if probe.check in str(v):
            return (True, cache_hits, modified_url)

    # Check response body
    try:
        if probe.check in (resp.text or ""):
            return (True, cache_hits, modified_url)
    except Exception:
        pass

    return (False, cache_hits, modified_url)


def process_one(
    url: str,
    probe: Probe,
    args,
    token: str,
    output_lock: threading.Lock,
    reflect_counter: "ReflectCounter",
) -> None:
    reflected, cache_hits, _ = check_reflection(
        url=url,
        probe=probe,
        user_agent=args.user_agent,
        timeout=args.timeout,
        insecure=args.insecure,
        follow_redirects=args.follow_redirects,
        token=token,
    )

    if not reflected:
        return

    with output_lock:
        reflect_counter.inc()

        hdrs = format_headers(probe.headers)
        print("\n" + colorize("Headers reflected:", "11") + f" [{hdrs}]")

        if args.show_cache_headers:
            print(colorize("Cache headers:", "80") + f" {', '.join(cache_hits)}")

        print(url + "\n")

        with open(args.output, "a", encoding="utf-8") as f:
            # Keep file format consistent but optionally include cache hits
            if args.show_cache_headers:
                f.write(f"Headers reflected: {hdrs} @ {url} | Cache: {', '.join(cache_hits)}\n")
            else:
                f.write(f"Headers reflected: {hdrs} @ {url}\n")


class ReflectCounter:
    def __init__(self) -> None:
        self._n = 0
        self._lock = threading.Lock()

    def inc(self) -> None:
        with self._lock:
            self._n += 1

    def value(self) -> int:
        with self._lock:
            return self._n


def iter_tasks(urls: List[str], probes: List[Probe]) -> Iterable[Tuple[str, Probe]]:
    for u in urls:
        for p in probes:
            yield (u, p)


# -----------------------------
# CLI / main
# -----------------------------

def read_urls_from_input(input_path: str) -> List[str]:
    # stdin wins when piped
    if not sys.stdin.isatty():
        raw = [line.strip() for line in sys.stdin if line.strip()]
    elif input_path:
        if not os.path.isfile(input_path):
            raise FileNotFoundError(f"Input file {input_path} not found.")
        with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
            raw = [line.strip() for line in f if line.strip()]
    else:
        raise ValueError("No input provided (use -i or pipe URLs via stdin).")

    normalized = []
    for u in raw:
        nu = normalize_url(u)
        if nu:
            normalized.append(nu)

    return dedupe_preserve_order(normalized)


def build_probes(payload_host: str) -> List[Probe]:
    # Keep payload consistent with your script, but make it explicit and centralized.
    # NOTE: The original script used ":13377" check for X-Forwarded-Proto. That is not
    # universally correct. If you want port-style reflection checks, use a payload that
    # actually includes a colon. Here we keep a clean, predictable check: "13377".
    return [
        Probe({"X-Forwarded-Host": payload_host}, payload_host),
        Probe({"X-Forwarded-For": payload_host}, payload_host),
        Probe({"X-Rewrite-Url": payload_host}, payload_host),
        Probe({"X-Host": payload_host}, payload_host),
        Probe({"User-Agent": payload_host}, payload_host),
        Probe({"Handle": payload_host}, payload_host),
        Probe({"H0st": payload_host}, payload_host),
        Probe({"Origin": payload_host}, payload_host),
        Probe({"Transfer-Encoding": payload_host}, payload_host),
        Probe({"X-Original-Url": payload_host}, payload_host),
        Probe({"X-Original-Host": payload_host}, payload_host),
        Probe({"X-Forwarded-Prefix": payload_host}, payload_host),
        Probe({"X-Amz-Server-Side-Encryption": payload_host}, payload_host),
        Probe({"X-Amz-Website-Redirect-Location": payload_host}, payload_host),
        Probe({"Trailer": payload_host}, payload_host),
        Probe({"Fastly-Ssl": payload_host}, payload_host),
        Probe({"Fastly-Host": payload_host}, payload_host),
        Probe({"Fastly-Ff": payload_host}, payload_host),
        Probe({"Fastly-Client-ip": payload_host}, payload_host),
        Probe({"Content-Type": payload_host}, payload_host),
        Probe({"Api-Version": payload_host}, payload_host),
        Probe({"AcunetiX-Header": payload_host}, payload_host),
        Probe({"Accept-Version": payload_host}, payload_host),
        Probe({"X-Forwarded-Proto": "13377"}, "13377"),
        Probe({"X-Forwarded-Host": payload_host, "X-Forwarded-Scheme": "http"}, payload_host),
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description="toxicachepy - cache-aware header reflection scanner")
    parser.add_argument("-i", "--input", type=str, default="", help="Input file containing URLs")
    parser.add_argument("-o", "--output", type=str, default="", help="Output file path")
    parser.add_argument("-t", "--threads", type=int, default=(os.cpu_count() or 1) * 5, help="Thread count")
    parser.add_argument(
        "-ua",
        "--user-agent",
        type=str,
        default="Mozilla/5.0 (Macintosh; Intel Mac OS X 12_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
        help="User-Agent header value",
    )
    parser.add_argument("--timeout", type=int, default=30, help="Request timeout in seconds")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification (like curl -k)")
    parser.add_argument("--follow-redirects", action="store_true", help="Follow redirects (default: off)")
    parser.add_argument("--show-cache-headers", action="store_true", help="Print/log detected cache headers")
    parser.add_argument("--max-inflight", type=int, default=0,
                        help="Max queued futures (0 = auto: threads*20). Helps avoid RAM blowups.")
    parser.add_argument("--payload", type=str, default="xhzeem.me", help="Payload value used for probes")

    args = parser.parse_args()

    if not args.output:
        args.output = f"toxicache-{now_timestamp()}.txt"

    # Stable token per run makes debugging and validation cleaner than random per request.
    token = str(random.randint(0, 9999))

    print(f"▶ Output will be saved to: {colorize(args.output, '80')}")
    print(f"▶ toxicache token: {colorize(token, '80')}\n")

    try:
        urls = read_urls_from_input(args.input)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if not urls:
        print("No URLs to process after normalization.", file=sys.stderr)
        sys.exit(0)

    print_banner()

    probes = build_probes(args.payload)

    output_lock = threading.Lock()
    reflect_counter = ReflectCounter()

    max_inflight = args.max_inflight if args.max_inflight > 0 else args.threads * 20

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        inflight: set[concurrent.futures.Future] = set()

        for (url, probe) in iter_tasks(urls, probes):
            fut = executor.submit(process_one, url, probe, args, token, output_lock, reflect_counter)
            inflight.add(fut)

            # Bound memory: if too many queued tasks, wait for some to finish.
            if len(inflight) >= max_inflight:
                done, inflight = concurrent.futures.wait(
                    inflight, return_when=concurrent.futures.FIRST_COMPLETED
                )

        # Drain remaining
        if inflight:
            concurrent.futures.wait(inflight)

    print(f"\n▶ Number of Reflections Found: {colorize(str(reflect_counter.value()), '80')}\n")


if __name__ == "__main__":
    main()
