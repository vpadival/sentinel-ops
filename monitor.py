"""
monitor.py
──────────
Automatically monitors your localhost website and sends suspicious
activity to Sentinel-Ops for AI threat analysis.

HOW IT WORKS:
  1. Acts as a proxy/middleware sitting between the internet and your app
  2. Watches every request coming into your website
  3. Detects suspicious patterns (brute force, SQL injection, XSS, etc.)
  4. Automatically submits alerts to Sentinel-Ops at localhost:8000

USAGE:
  python monitor.py --target http://localhost:3000 --port 9000

  Then visit YOUR website at: http://localhost:9000
  (monitor sits in between and watches all traffic)

  OR if you just want to simulate attacks without a proxy:
  python monitor.py --simulate

  Control simulation speed:
  python monitor.py --simulate --interval 10   # 10s between attacks (default: 5)

REQUIREMENTS:
  pip install httpx flask flask-cors
"""

import argparse
import os
import threading
import time
import re
import json
import httpx
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional, Set
from urllib.parse import unquote_plus, urlsplit
from dotenv import load_dotenv

load_dotenv()

# ── Sentinel-Ops config ────────────────────────────────────────────────────
SENTINEL_URL = "http://localhost:8000"

# ── Attack detection patterns ──────────────────────────────────────────────
ATTACK_PATTERNS: Dict[str, Optional[List[str]]] = {
    "SQL Injection": [
        r"(\bUNION\b.*\bSELECT\b)",
        r"(\bSELECT\b.*\bFROM\b)",
        r"(--|#|/\*.*\*/)",
        r"(\bDROP\b.*\bTABLE\b)",
        r"(\bOR\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?)",
        r"(\bINSERT\b.*\bINTO\b)",
        r"(;.*\bEXEC\b)",
    ],
    "XSS Attack": [
        r"(<script.*?>)",
        r"(javascript\s*:)",
        r"(onerror\s*=)",
        r"(onload\s*=)",
        r"(<img.*?src.*?=.*?javascript)",
        r"(alert\s*\()",
        r"(document\.cookie)",
    ],
    "Path Traversal": [
        r"(\.\./){2,}",
        r"(%2e%2e%2f)",
        r"(\.\.\\){2,}",
        r"(/etc/passwd)",
        r"(/windows/system32)",
    ],
    "Command Injection": [
        r"(;\s*ls\s)",
        r"(;\s*cat\s)",
        r"(\|\s*whoami)",
        r"(`.*`)",
        r"(\$\(.*\))",
        r"(;\s*rm\s+-rf)",
        r"(&&\s*wget\s)",
    ],
    "Brute Force": None,  # handled separately via rate tracking
    "Scanner/Bot": [
        r"(nikto)",
        r"(sqlmap)",
        r"(nmap)",
        r"(masscan)",
        r"(dirbuster)",
        r"(gobuster)",
        r"(burpsuite)",
        r"(python-requests.*scan)",
    ],
}

# ── State tracking ─────────────────────────────────────────────────────────
request_counts: Dict[str, List[float]]   = defaultdict(list)   # ip -> [timestamps]
failed_auth: Dict[str, int]              = defaultdict(int)    # ip -> count
submitted_alerts: Set[str]               = set()               # dedupe alerts
_submitted_at: Dict[str, float] = {}
_submit_lock = threading.Lock()
ALERT_DEDUPE_SECONDS = 30

# ── Thresholds ─────────────────────────────────────────────────────────────
RATE_LIMIT_WINDOW   = 60    # seconds
RATE_LIMIT_MAX      = 30    # requests per window before alert
BRUTE_FORCE_MAX     = 5     # failed logins before alert


def now():
    return datetime.now().strftime("%H:%M:%S")


def log(msg: str, level: str = "INFO") -> None:
    colors = {"INFO": "\033[36m", "WARN": "\033[33m", "ALERT": "\033[31m", "OK": "\033[32m"}
    reset = "\033[0m"
    c = colors.get(level, "")
    print(f"{c}[{now()}] [{level}] {msg}{reset}", flush=True)


# ── Sentinel-Ops integration ───────────────────────────────────────────────
def submit_to_sentinel(problem_statement: str, dedupe_key: Optional[str] = None) -> None:
    """Create an investigation directly; no open browser is required."""
    with _submit_lock:
        _submit_alert(problem_statement, dedupe_key)


def _submit_alert(problem_statement: str, dedupe_key: Optional[str]) -> None:
    now_mono = time.monotonic()
    for key in list(_submitted_at):
        if now_mono - _submitted_at[key] >= ALERT_DEDUPE_SECONDS:
            _submitted_at.pop(key)
            submitted_alerts.discard(key)

    if dedupe_key and dedupe_key in submitted_alerts:
        log("Duplicate alert suppressed for up to 30 seconds.", "INFO")
        return

    log(f"Starting Sentinel-Ops investigation: {problem_statement[:80]}...", "ALERT")

    try:
        resp = httpx.post(
            f"{SENTINEL_URL}/api/v1/jobs",
            json={"problem_statement": problem_statement},
            headers={"X-API-Key": os.getenv("SENTINEL_API_KEY", "").strip()},
            timeout=5,
        )
        if resp.status_code == 202:
            job_id = resp.json()["job_id"]
            if dedupe_key:
                submitted_alerts.add(dedupe_key)
                _submitted_at[dedupe_key] = time.monotonic()
            log(f"Job created: {job_id}. Dashboard: {SENTINEL_URL}", "OK")
        else:
            log(f"Sentinel-Ops returned HTTP {resp.status_code}; no job created. "
                "For HTTP 401, check SENTINEL_API_KEY in .env.", "WARN")
    except httpx.RequestError:
        log("Cannot reach Sentinel-Ops. Is it running on port 8000?", "WARN")


def poll_result(job_id: str):
    """Poll job until complete and print the threat report."""
    for _ in range(30):
        time.sleep(2)
        try:
            r = httpx.get(f"{SENTINEL_URL}/api/v1/jobs/{job_id}", timeout=5)
            data = r.json()
            status = data.get("status")

            if status == "complete":
                fact = data.get("fact_sheet", {})
                severity = fact.get("severity", "UNKNOWN") if fact else "UNKNOWN"
                markdown = fact.get("raw_markdown", "") if fact else ""
                log(f"── Threat Report for job {job_id[:8]} ──────────────────", "OK")
                log(f"Severity: {severity}", "OK")
                if markdown:
                    preview = markdown[:500].replace("\n", " | ")
                    log(f"Report: {preview}...", "OK")
                log(f"Full report: {SENTINEL_URL} → click the job in the dashboard", "OK")
                return

            elif status == "failed":
                log(f"Job {job_id[:8]} failed: {data.get('error')}", "WARN")
                return

        except Exception:
            pass


# ── Request analyzer ───────────────────────────────────────────────────────
def analyze_request(method: str, path: str, headers: Dict[str, str],
                    body: str, client_ip: str) -> None:
    """
    Analyze an incoming request for threats.
    Call this from your web framework middleware.
    """
    full_request = f"{method} {path} body={body} headers={json.dumps(headers)}"
    user_agent   = headers.get("user-agent", headers.get("User-Agent", ""))
    timestamp    = time.time()

    # ── 1. Rate limiting / brute force detection ───────────────────────────
    window_start = timestamp - RATE_LIMIT_WINDOW
    request_counts[client_ip] = [
        t for t in request_counts[client_ip] if t > window_start
    ]
    request_counts[client_ip].append(timestamp)
    count = len(request_counts[client_ip])

    if count == RATE_LIMIT_MAX:
        submit_to_sentinel(
            f"Possible brute force / DDoS from {client_ip}. "
            f"{count} requests in {RATE_LIMIT_WINDOW}s to {path}. "
            f"User-Agent: {user_agent}",
            dedupe_key=f"ratelimit:{client_ip}"
        )

    # ── 3. Pattern-based attack detection ─────────────────────────────────
    for attack_type, patterns in ATTACK_PATTERNS.items():
        if patterns is None:
            continue
        for pattern in patterns:
            if re.search(pattern, full_request, re.IGNORECASE):
                submit_to_sentinel(
                    f"{attack_type} detected from {client_ip}. "
                    f"Method: {method}, Path: {path}. "
                    f"Payload snippet: {(path + ' ' + body)[:200]}. "
                    f"User-Agent: {user_agent}",
                    dedupe_key=f"{attack_type}:{client_ip}:{path}"
                )
                break

    # ── 4. Sensitive path access ───────────────────────────────────────────
    sensitive_paths = [
        "/admin", "/.env", "/config", "/backup",
        "/phpinfo", "/.git", "/wp-admin", "/database",
        "/secret", "/private", "/api/keys"
    ]
    for sp in sensitive_paths:
        if path.lower().startswith(sp):
            submit_to_sentinel(
                f"Sensitive path access attempt from {client_ip}. "
                f"Path: {path}. Method: {method}. "
                f"User-Agent: {user_agent}",
                dedupe_key=f"sensitive:{client_ip}:{path}"
            )
            break


# ── Flask proxy middleware ─────────────────────────────────────────────────
def run_proxy(target_url: str, listen_port: int):
    """
    Run a reverse proxy that sits in front of your website.
    All traffic goes through here so we can inspect it.
    """
    target_url = target_url.rstrip("/")
    target = urlsplit(target_url)
    if target.scheme not in ("http", "https") or not target.hostname:
        raise ValueError("Target must be an http:// or https:// website URL.")
    target_port = target.port or (443 if target.scheme == "https" else 80)
    if target.hostname in ("localhost", "127.0.0.1", "0.0.0.0", "::1") and target_port == listen_port:
        raise ValueError("Target port must differ from proxy port; forwarding to the proxy itself causes a request loop.")

    try:
        from flask import Flask, request, Response
        import flask_cors
    except ImportError:
        log("flask and flask-cors are required. Install with: pip install flask flask-cors", "WARN")
        raise SystemExit(1)

    # Forward /static to the target as well; Flask's default static route would
    # intercept dashboard assets and return 404 from the monitor directory.
    app = Flask(__name__, static_folder=None)
    flask_cors.CORS(app)

    log(f"Starting monitor proxy on port {listen_port}", "INFO")
    log(f"Forwarding traffic to: {target_url}", "INFO")
    log(f"Sentinel-Ops dashboard: {SENTINEL_URL}", "INFO")
    log("─" * 60, "INFO")
    log(f"Visit YOUR website at: http://localhost:{listen_port}", "OK")
    log("All requests will be monitored for threats.", "OK")
    log("─" * 60, "INFO")

    @app.route("/", defaults={"path": ""}, methods=["GET","POST","PUT","DELETE","PATCH","OPTIONS"])
    @app.route("/<path:path>",             methods=["GET","POST","PUT","DELETE","PATCH","OPTIONS"])
    def proxy(path: str):  # type: ignore[return]  # Flask route
        client_ip = request.headers.get("X-Forwarded-For") or request.remote_addr or "unknown"
        raw_body  = request.get_data()
        body      = raw_body.decode("utf-8", errors="replace")
        headers   = dict(request.headers)

        log(f"{request.method} /{path} from {client_ip}")

        analyze_request(
            method=request.method,
            path=unquote_plus(request.full_path),
            headers=headers,
            body=body,
            client_ip=client_ip,
        )

        try:
            url = f"{target_url}/{path}"
            if request.query_string:
                url += "?" + request.query_string.decode()

            fwd_headers = {
                k: v for k, v in headers.items()
                if k.lower() not in ("host", "content-length")
            }

            resp = httpx.request(
                method=request.method,
                url=url,
                headers=fwd_headers,
                content=raw_body,
                timeout=10,
                follow_redirects=False,
            )

            if resp.status_code in (401, 403) and "/" + path in (
                "/login", "/admin", "/auth", "/signin", "/wp-login.php",
            ):
                failed_auth[client_ip] += 1
                if failed_auth[client_ip] >= BRUTE_FORCE_MAX:
                    submit_to_sentinel(
                        f"Brute force login attack from {client_ip}. "
                        f"{failed_auth[client_ip]} failed attempts on /{path}.",
                        dedupe_key=f"bruteforce:{client_ip}",
                    )

            return Response(
                resp.content,
                status=resp.status_code,
                headers=[
                    (key, value) for key, value in resp.headers.multi_items()
                    if key.lower() not in (
                        "content-encoding", "content-length", "transfer-encoding",
                        "connection", "keep-alive", "proxy-authenticate",
                        "proxy-authorization", "te", "trailer", "upgrade",
                    )
                ],
            )

        except httpx.RequestError as exc:
            log(f"Target request failed: {type(exc).__name__}: {exc}. Target: {target_url}", "WARN")
            return Response(
                f"<h1>Monitor Error</h1><p>Cannot reach {target_url}. "
                f"Make sure your website is running.</p>",
                status=502,
                mimetype="text/html"
            )

    app.run(host="0.0.0.0", port=listen_port, debug=False, threaded=True)


# ── Attack simulator (for testing) ────────────────────────────────────────
def run_simulator(interval: int = 5, port: int = 9000):
    """
    Simulate various attacks against the monitor proxy for testing.
    interval: seconds to wait between each attack (default 5).
    """
    import httpx

    TARGET = f"http://localhost:{port}"

    attacks = [
        ("Normal request",          "GET",  "/",             ""),
        ("SQL Injection in URL",    "GET",  "/search?q=1' UNION SELECT * FROM users--", ""),
        ("XSS in body",             "POST", "/comment",      '{"text": "<script>alert(document.cookie)</script>"}'),
        ("Path traversal",          "GET",  "/../../etc/passwd", ""),
        ("Admin brute force 1",     "POST", "/admin",        "user=admin&pass=password1"),
        ("Admin brute force 2",     "POST", "/admin",        "user=admin&pass=password2"),
        ("Admin brute force 3",     "POST", "/admin",        "user=admin&pass=password3"),
        ("Admin brute force 4",     "POST", "/admin",        "user=admin&pass=password4"),
        ("Admin brute force 5",     "POST", "/admin",        "user=admin&pass=password5"),
        ("Sensitive path access",   "GET",  "/.env",         ""),
        ("Sensitive path access",   "GET",  "/.git/config",  ""),
        ("Command injection",       "POST", "/ping",         "host=127.0.0.1; cat /etc/passwd"),
        ("Scanner user agent",      "GET",  "/",             ""),
    ]

    log("Starting attack simulation...", "WARN")
    log(f"Targeting: {TARGET}", "WARN")
    log(f"Interval between attacks: {interval}s", "INFO")
    log("─" * 60)

    failures = 0
    # Detection may perform several five-second alert submissions before forwarding.
    with httpx.Client(timeout=60, trust_env=False) as client:
        for desc, method, path, body in attacks:
            log(f"Simulating: {desc}")
            try:
                headers = {"Content-Type": "application/x-www-form-urlencoded"}
                if "Scanner" in desc:
                    headers["User-Agent"] = "Mozilla/5.0 (nikto scanner)"

                response = client.request(method, TARGET + path,
                                          content=body.encode(), headers=headers)
                log(f"{desc}: HTTP {response.status_code}",
                    "WARN" if response.status_code >= 500 else "INFO")
                if response.status_code >= 500:
                    failures += 1
            except httpx.ConnectError as exc:
                log(f"Cannot connect to proxy at {TARGET}: {exc}. Keep the proxy running in a separate terminal.", "WARN")
                return
            except httpx.RequestError as exc:
                failures += 1
                log(f"{desc} failed: {type(exc).__name__}: {exc}", "WARN")
            time.sleep(interval)

    log("─" * 60)
    log(f"Simulation finished with {failures} failed request(s). Check the proxy terminal for upstream errors.",
        "WARN" if failures else "OK")
    log(f"Dashboard: {SENTINEL_URL}", "OK")


# ── Entry point ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Sentinel-Ops Website Monitor"
    )
    parser.add_argument(
        "--target", default="http://localhost:3000",
        help="Your website URL (default: http://localhost:3000)"
    )
    parser.add_argument(
        "--port", type=int, default=9000,
        help="Port to run the monitor proxy on (default: 9000)"
    )
    parser.add_argument(
        "--simulate", action="store_true",
        help="Run attack simulation instead of proxy"
    )
    parser.add_argument(
        "--interval", type=int, default=5,
        help="Seconds between simulated attacks (default: 5)"
    )
    args = parser.parse_args()

    if args.simulate:
        run_simulator(interval=args.interval, port=args.port)
    else:
        run_proxy(args.target, args.port)
