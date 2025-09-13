#!/usr/bin/env python3
import os
import re
import sys
import time
import pathlib
import json as _json
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

import requests
import yaml

# Make Windows console happy for UTF-8 logs
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# ----------------------------------------------------------------------
# Globals / env
# ----------------------------------------------------------------------
DEBUG_SHOTS_DIR = os.environ.get("PC_DEBUG_DIR", "pc_debug")
os.makedirs(DEBUG_SHOTS_DIR, exist_ok=True)

PC_REAL_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36"
)

PC_HEADED = os.environ.get("PC_HEADED", "").strip() == "1"
PC_BLOCK_CHALLENGE_JS = os.environ.get("PC_BLOCK_CHALLENGE_JS", "1").strip() == "1"

# Optional: path to storage state JSON exported from a real browser session
PC_STORAGE_STATE = os.environ.get("PC_STORAGE_STATE", "").strip()
# Optional: raw JSON array of cookie dicts (or {"cookies":[...]})
PC_COOKIES_JSON = os.environ.get("PC_COOKIES_JSON", "").strip()

# Imperva / session handling (our own persistence)
PC_USE_PERSISTENT = os.environ.get("PC_USE_PERSISTENT", "").strip() == "1"
PC_USER_DATA_DIR = os.environ.get("PC_USER_DATA_DIR", "pc_debug/pw-profile")
PC_CHALLENGE_TIMEOUT_S = int(os.environ.get("PC_CHALLENGE_TIMEOUT_S", "180"))
STORAGE_STATE_PATH = os.environ.get("PC_STORAGE_STATE_PATH", "pc_debug/pc_state.json")

# Extra “real-ish” headers inc. UA-CH (some botwalls check these)
_PC_EXTRA_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Upgrade-Insecure-Requests": "1",
    "sec-ch-ua": '"Google Chrome";v="126", "Chromium";v="126", "Not.A/Brand";v="24"',
    "sec-ch-ua-platform": '"Windows"',
    "sec-ch-ua-mobile": "?0",
}

# Human bootstrap: open a visible window and wait for user to clear Imperva once
PC_REQUIRE_HUMAN = os.environ.get("PC_REQUIRE_HUMAN", "").strip() == "1"
PC_BOOT_URL = os.environ.get("PC_BOOT_URL", "https://www.pokemoncenter.com/")

# Optionally launch a real installed browser channel ('chrome' or 'msedge') for higher trust
PW_CHANNEL = os.environ.get("PW_CHANNEL", "").strip()  # "", "chrome", or "msedge"

# --- Traffic/latency heuristics ----------------------------------------------
TRAFFIC_LATENCY_MS = 2500   # treat >2.5s as “high traffic”
HIGH_TRAFFIC_STATUSES = {429, 503}

GITHUB_API = "https://api.github.com"

# =========================
# Data models / config
# =========================

@dataclass
class TargetParse:
    mode: str = "contains"   # "regex" or "contains"
    pattern_in_stock: Optional[str] = None
    pattern_out_of_stock: Optional[str] = None
    in_stock_contains: List[str] = field(default_factory=list)
    out_of_stock_contains: List[str] = field(default_factory=list)

@dataclass
class Target:
    name: str
    url: str
    parse: TargetParse
    priority_keywords: List[str] = field(default_factory=list)
    expand: Optional[str] = None  # e.g., "pc_category"

@dataclass
class Config:
    poll_interval_seconds: int = 120
    timeout_seconds: int = 20
    user_agent: str = "RestockWatch-GHA/1.0"
    targets: List[Target] = field(default_factory=list)
    # optional push channels (need repo secrets to work)
    pushover_token: Optional[str] = None
    pushover_user: Optional[str] = None
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None

def load_config(path: str) -> Config:
    try:
        raw = yaml.safe_load(open(path, "r", encoding="utf-8"))
    except FileNotFoundError:
        print(f"[error] {path} not found. Create it with at least one target.", file=sys.stderr)
        return Config()
    except Exception as e:
        print(f"[error] Failed to parse {path}: {e}", file=sys.stderr)
        return Config()

    targets: List[Target] = []
    for t in (raw.get("targets") or []):
        parse = t.get("parse", {})
        tp = TargetParse(
            mode=(parse.get("mode") or "contains"),
            pattern_in_stock=parse.get("pattern_in_stock"),
            pattern_out_of_stock=parse.get("pattern_out_of_stock"),
            in_stock_contains=parse.get("in_stock_contains") or [],
            out_of_stock_contains=parse.get("out_of_stock_contains") or [],
        )
        targets.append(Target(
            name=t.get("name", "Unnamed"),
            url=t.get("url", ""),
            parse=tp,
            priority_keywords=t.get("priority_keywords") or [],
            expand=t.get("expand"),
        ))

    return Config(
        poll_interval_seconds=raw.get("poll_interval_seconds", 120),
        timeout_seconds=raw.get("timeout_seconds", 20),
        user_agent=raw.get("user_agent", "RestockWatch-GHA/1.0"),
        targets=targets,
        pushover_token=os.environ.get("PUSHOVER_TOKEN"),
        pushover_user=os.environ.get("PUSHOVER_USER"),
        telegram_bot_token=os.environ.get("TELEGRAM_BOT_TOKEN"),
        telegram_chat_id=os.environ.get("TELEGRAM_CHAT_ID"),
    )

# =========================
# HTTP helpers
# =========================

def fetch_html_with_retries(url: str, timeout: int, ua: str, retries: int = 2):
    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    for attempt in range(retries + 1):
        start = time.time()
        try:
            r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            elapsed_ms = int((time.time() - start) * 1000)
            return r.text, r.status_code, elapsed_ms
        except Exception as e:
            _ = int((time.time() - start) * 1000)
            print(f"[warn] fetch attempt {attempt+1}/{retries+1} failed for {url}: {e}", file=sys.stderr)
            time.sleep(1.0)
    return None, None, None

# =========================
# Playwright helpers / debug
# =========================

def _pc_slug(url: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", url.lower())
    return s.strip("-")[:120]

def _pc_debug_dir() -> pathlib.Path:
    d = pathlib.Path("pc_debug")
    d.mkdir(parents=True, exist_ok=True)
    return d

def _pc_dump(name: str, page, html: str, resp_status: Optional[int], notes: str, responses: list):
    """Write HTML, PNG, and a small info.json (plus XHR bodies) when DEBUG_PC_DUMP=1."""
    if os.environ.get("DEBUG_PC_DUMP") != "1":
        return

    outdir = _pc_debug_dir()
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    base = outdir / f"{ts}-{name}"

    try:
        (base.with_suffix(".html")).write_text(html or "", encoding="utf-8")
    except Exception as e:
        print(f"[warn] debug html write failed: {e}", file=sys.stderr)

    try:
        page.screenshot(path=str(base.with_suffix(".png")), full_page=True)
    except Exception as e:
        print(f"[warn] debug screenshot failed: {e}", file=sys.stderr)

    info = {"status": resp_status, "notes": notes, "responses": []}
    for r in responses:
        try:
            ctype = (r.headers.get("content-type") or "").lower()
            rec = {"url": r.url, "status": r.status, "content_type": ctype}
            info["responses"].append(rec)
            if "application/json" in ctype:
                body = r.text()
                if body and len(body) < 2_000_000:
                    jname = outdir / f"{ts}-{name}-{_pc_slug(r.url)}.json"
                    jname.write_text(body, encoding="utf-8")
        except Exception:
            continue

    try:
        (base.with_suffix(".info.json")).write_text(_json.dumps(info, indent=2), encoding="utf-8")
    except Exception as e:
        print(f"[warn] debug info write failed: {e}", file=sys.stderr)

# ---- Playwright context / routing -------------------------------------------
from playwright.sync_api import sync_playwright

def _open_context(pw):
    extra_args = [
        "--disable-blink-features=AutomationControlled",
        "--disable-dev-shm-usage",
        "--no-sandbox",
        "--disable-gpu",
    ]

    if PC_USE_PERSISTENT:
        ctx = pw.chromium.launch_persistent_context(
            user_data_dir=PC_USER_DATA_DIR,
            headless=not PC_HEADED,
            args=extra_args,
            user_agent=PC_REAL_UA,
            viewport={"width": 1366, "height": 900},
            locale="en-US",
            timezone_id="America/New_York",
            channel=(PW_CHANNEL or None),
        )
    else:
        browser = pw.chromium.launch(
            headless=not PC_HEADED,
            args=extra_args,
            channel=(PW_CHANNEL or None),
        )
        ctx = browser.new_context(
            user_agent=PC_REAL_UA,
            viewport={"width": 1366, "height": 900},
            locale="en-US",
            timezone_id="America/New_York",
        )
        ctx._attached_browser = browser

    ctx.set_default_timeout(20_000)
    ctx.set_default_navigation_timeout(20_000)
    ctx.set_extra_http_headers(_PC_EXTRA_HEADERS)
    ctx.add_init_script("""
        Object.defineProperty(navigator,'webdriver',{get:()=>undefined});
        window.chrome = { runtime: {} };
        Object.defineProperty(navigator, 'languages', { get: () => ['en-US','en'] });
        Object.defineProperty(navigator, 'platform', { get: () => 'Win32' });
        Object.defineProperty(navigator, 'plugins', { get: () => [1,2,3] });
        Object.defineProperty(navigator, 'mimeTypes', { get: () => [1,2] });
    """)
    try:
        ctx.set_geolocation({'latitude': 40.7128, 'longitude': -74.0060})
    except Exception:
        pass
    return ctx

def _close_context(ctx):
    try:
        ctx.close()
    except Exception:
        pass
    br = getattr(ctx, "_attached_browser", None)
    if br:
        try:
            br.close()
        except Exception:
            pass

def _maybe_load_cookies_into_context(context):
    # Highest priority: full storage state file (user-provided)
    if PC_STORAGE_STATE and os.path.isfile(PC_STORAGE_STATE):
        try:
            context.storage_state(path=PC_STORAGE_STATE)  # validate readable
            browser = context.browser
            context.close()
            return browser.new_context(storage_state=PC_STORAGE_STATE)
        except Exception as e:
            print(f"[warn] storage_state load failed: {e}", file=sys.stderr)

    # Next: raw cookies JSON
    if PC_COOKIES_JSON:
        try:
            import json as _json_local
            cookies = _json_local.loads(PC_COOKIES_JSON)
            if isinstance(cookies, dict) and "cookies" in cookies:
                cookies = cookies["cookies"]
            if isinstance(cookies, list) and cookies:
                context.add_cookies(cookies)
        except Exception as e:
            print(f"[warn] cookie JSON load failed: {e}", file=sys.stderr)
    return context

def _wire_challenge_blocking(page):
    if not PC_BLOCK_CHALLENGE_JS:
        return
    challenge_pat = re.compile(r"/(vice-come-[A-Za-z0-9-]+|GEDIE-OF-MACBETH-[A-Za-z0-9-]+)\b", re.I)
    def _route_handler(route):
        try:
            req = route.request
            url = getattr(req, "url", "")
            if challenge_pat.search(url or ""):
                print(f"[debug] blocking challenge script: {url}", file=sys.stderr)
                return route.abort()
            return route.continue_()
        except Exception as e:
            print(f"[warn] route handler error: {e}", file=sys.stderr)
            try:
                return route.continue_()
            except Exception:
                pass
    page.route("**/*", _route_handler)

# ---- Imperva detection / guided solve ---------------------------------------

def _looks_like_incapsula_challenge(page_html: str) -> bool:
    low = (page_html or "").lower()
    if "additional security check is required" in low: return True
    if "hcaptcha" in low: return True
    if "powered by imperva" in low: return True
    return False

def _await_challenge_resolution(page) -> bool:
    """
    If the Imperva page is shown, ask the human to solve it (only in headed mode).
    Returns True if we think the challenge is cleared afterwards.
    """
    has_iframe = page.locator('iframe[src*="hcaptcha"]').first
    banner = page.locator('text=Additional security check').first

    try:
        visible = has_iframe.is_visible(timeout=500) or banner.is_visible(timeout=500)
    except Exception:
        visible = False

    if not visible:
        return False

    if not PC_HEADED:
        print("[warn] Imperva challenge detected but PC_HEADED is off; cannot be solved automatically.", file=sys.stderr)
        return False

    print("[action] Imperva challenge detected. Please solve the checkbox in the visible window...", file=sys.stderr)

    deadline = time.time() + PC_CHALLENGE_TIMEOUT_S
    solved = False
    while time.time() < deadline:
        try:
            if (not has_iframe.is_visible(timeout=500)) and (not banner.is_visible(timeout=1500)):
                page.wait_for_load_state("networkidle", timeout=5000)
                html = page.content()
                if len(html or "") > 9000 and ("product" in html or "category" in html):
                    solved = True
                    break
        except Exception:
            pass
        page.wait_for_timeout(750)

    if solved:
        print("[info] Challenge cleared. Persisting cookies/state.", file=sys.stderr)
        try:
            page.context.storage_state(path=STORAGE_STATE_PATH)
        except Exception:
            pass
    else:
        print("[warn] Challenge not cleared in time.", file=sys.stderr)
    return solved

# =========================
# PC fetchers
# =========================

def fetch_pc_rendered(url: str, ua: str, timeout_seconds: int = 20):
    t0 = time.perf_counter()
    html = None
    status = None
    responses = []

    try:
        with sync_playwright() as pw:
            ctx = _open_context(pw)
            ctx = _maybe_load_cookies_into_context(ctx)
            page = ctx.new_page()
            try:
                if PC_HEADED:
                    page.bring_to_front()
            except Exception:
                pass
            page.on("response", lambda r: responses.append(r))

            # Warm-up: homepage (helps set cookie)
            try:
                page.goto("https://www.pokemoncenter.com/", wait_until="domcontentloaded", timeout=15000)
                page.wait_for_load_state("networkidle", timeout=5000)
            except Exception:
                pass

            page.goto(url, wait_until="domcontentloaded", timeout=timeout_seconds * 1000)

            # Early 403 log
            try:
                if any((getattr(r, "status", None) or 0) == 403 for r in responses):
                    print(f"[warn] 403 seen on PC while loading {url}", file=sys.stderr)
            except Exception:
                pass

            # If we’re staring at the Imperva page, let the human solve it once
            html_probe = page.content()
            if _looks_like_incapsula_challenge(html_probe):
                if _await_challenge_resolution(page):
                    responses.clear()
                    page.reload(wait_until="domcontentloaded")

            # Progressive scroll to fire lazy feeds
            end = time.time() + 7
            while time.time() < end:
                try:
                    page.mouse.wheel(0, 900)
                except Exception:
                    pass
                page.wait_for_timeout(400)

            try:
                page.wait_for_load_state("networkidle", timeout=8000)
            except Exception:
                page.wait_for_timeout(2000)

            html = page.content()

            # Pick a plausible status
            status = 200
            for r in responses:
                try:
                    if r.request.resource_type == "document" and "pokemoncenter.com" in r.url:
                        status = r.status
                        break
                except Exception:
                    continue

            _pc_dump(_pc_slug(url), page, html or "", status, "waited=networkidle", responses)

            if html and len(html) > 9000:
                try:
                    ctx.storage_state(path=STORAGE_STATE_PATH)
                except Exception:
                    pass

            _close_context(ctx)

    except Exception as e:
        print(f"[warn] Playwright fetch failed for {url}: {e}", file=sys.stderr)
        return None, None, None

    elapsed_ms = int((time.perf_counter() - t0) * 1000)
    if len(html or "") < 9000:
        print(f"[info] PC page small after render ({len(html)} bytes): {url}", file=sys.stderr)
    return html, status, elapsed_ms

def fetch_pc_or_raw(url: str, ua: str, timeout_seconds: int):
    """Use Playwright for Pokemon Center; otherwise plain requests."""
    is_pc = "pokemoncenter.com" in (url or "")
    if is_pc:
        html, status, elapsed_ms = fetch_pc_rendered(url, ua=ua, timeout_seconds=timeout_seconds)
        source = "rendered"
        if html is None:
            html, status, elapsed_ms = fetch_html_with_retries(
                url, timeout=timeout_seconds, ua=ua, retries=2
            )
            source = "raw-fallback"
    else:
        html, status, elapsed_ms = fetch_html_with_retries(
            url, timeout=timeout_seconds, ua=ua, retries=2
        )
        source = "raw"
    return html, status, elapsed_ms, source

# =========================
# Category link extractors
# =========================

def extract_pc_product_links(html: str, max_links: int = 50) -> List[str]:
    """
    Scrape Pokémon Center product links from rendered HTML.
    Handles href, data-pdp-url, absolute URLs, and JSON-embedded strings.
    """
    patterns = [
        r'href=[\'"](/product/[^\'"]+)[\'"]',
        r'data-pdp-url=[\'"](/product/[^\'"]+)[\'"]',
        r'https?://www\.pokemoncenter\.com(/product/[^\'"]+)',
        r'"pdpUrl"\s*:\s*"\s*(/product/[^"]+)"',
        r'"url"\s*:\s*"\s*(/product/[^"]+)"',
    ]
    found: List[str] = []
    seen = set()
    for pat in patterns:
        for m in re.findall(pat, html or "", flags=re.I):
            path = m if m.startswith("/product/") else ("/" + m.lstrip("/"))
            url = "https://www.pokemoncenter.com" + path.split("?")[0]
            if url not in seen:
                seen.add(url)
                found.append(url)
                if len(found) >= max_links:
                    return found
    return found

def collect_pc_product_links_with_network(url: str, timeout_seconds: int = 20, max_links: int = 60) -> List[str]:
    """
    Open a Pokémon Center *category* URL in Playwright and capture product URLs
    by scanning the *network responses* (JSON/JS/HTML) for '/product/...' paths.
    Two attempts: 1) possibly blocking challenge; 2) always allowing challenge.
    """
    base = "https://www.pokemoncenter.com"
    links: List[str] = []
    seen = set()

    def _maybe_add(pathish: Optional[str]):
        if not pathish:
            return
        if pathish.startswith("/product/"):
            full = base + pathish.split("?")[0]
        elif pathish.startswith(base + "/product/"):
            full = pathish.split("?")[0]
        else:
            return
        if full not in seen:
            seen.add(full)
            links.append(full)

    for attempt in (1, 2):
        try:
            with sync_playwright() as pw:
                ctx = _open_context(pw)
                ctx = _maybe_load_cookies_into_context(ctx)
                page = ctx.new_page()
                if attempt == 1 and PC_BLOCK_CHALLENGE_JS:
                    _wire_challenge_blocking(page)

                def on_response(resp):
                    try:
                        url_l = resp.url.lower()
                        if "pokemoncenter.com" not in url_l:
                            return
                        ct = (resp.headers or {}).get("content-type", "").lower()
                        if not any(k in ct for k in ("json", "javascript", "html")):
                            return
                        body = resp.text()
                        for m in re.findall(r'(?:"|\')(/product/[A-Za-z0-9\-/]+)(?:\?|["\'])', body):
                            _maybe_add(m)
                        for m in re.findall(r'(?:"|\')(https://www\.pokemoncenter\.com/product/[A-Za-z0-9\-/]+)(?:\?|["\'])', body):
                            _maybe_add(m)
                    except Exception:
                        pass

                page.on("response", on_response)
                page.goto(url, wait_until="domcontentloaded", timeout=timeout_seconds * 1000)

                # --- Log 403s early
                # (Responses captured in handler above—this log will appear on the next loop if any 403s hit.)
                # Cookie banner (best-effort)
                for sel in [
                    'button:has-text("Accept All")',
                    'button:has-text("Accept Cookies")',
                    '[data-testid="cookie-accept-all"]',
                    '[id*="onetrust-accept"]',
                ]:
                    try:
                        if page.is_visible(sel, timeout=500):
                            page.click(sel, timeout=500)
                            break
                    except Exception:
                        pass

                if PC_HEADED:
                    try:
                        page.mouse.move(300, 300)
                        page.mouse.wheel(0, 1200)
                    except Exception:
                        pass

                try:
                    page.wait_for_load_state("networkidle", timeout=8000)
                except Exception:
                    page.wait_for_timeout(2500)

                _close_context(ctx)

            if links:
                break
        except Exception as e:
            print(f"[warn] Network link extraction failed (attempt {attempt}) for {url}: {e}", file=sys.stderr)
            continue

    if len(links) > max_links:
        links = links[:max_links]
    return links

def extract_pc_links_from_dom_with_playwright(url: str, timeout_seconds: int = 20) -> List[str]:
    """
    Simple DOM fallback: look for anchors or data-pdp-url in hydrated DOM.
    Two attempts: 1) possibly blocking challenge; 2) always allowing challenge.
    """
    base = "https://www.pokemoncenter.com"
    links: List[str] = []
    seen = set()

    def _norm(h: Optional[str]) -> Optional[str]:
        if not h:
            return None
        h = h.strip()
        if h.startswith("/product/"):
            return base + h.split("?")[0]
        if h.startswith(base + "/product/"):
            return h.split("?")[0]
        return None

    for attempt in (1, 2):
        try:
            with sync_playwright() as pw:
                ctx = _open_context(pw)
                ctx = _maybe_load_cookies_into_context(ctx)
                page = ctx.new_page()
                if attempt == 1 and PC_BLOCK_CHALLENGE_JS:
                    _wire_challenge_blocking(page)

                all_responses = []
                page.on("response", lambda r: all_responses.append(r))

                page.goto(url, wait_until="domcontentloaded", timeout=timeout_seconds * 1000)

                # --- Log 403s early
                try:
                    if any((getattr(r, "status", 0) == 403) for r in all_responses):
                        print(f"[warn] 403 seen on PC while loading {url}", file=sys.stderr)
                except Exception:
                    pass

                # Cookie accept best-effort
                for sel in [
                    'button:has-text("Accept All")',
                    'button:has-text("Accept Cookies")',
                    '[data-testid="cookie-accept-all"]',
                    '[id*="onetrust-accept"]'
                ]:
                    try:
                        if page.is_visible(sel, timeout=500):
                            page.click(sel, timeout=500)
                            break
                    except Exception:
                        pass

                try:
                    page.wait_for_load_state("networkidle", timeout=6000)
                except Exception:
                    page.wait_for_timeout(2000)

                hrefs = page.eval_on_selector_all(
                    'a[href*="/product/"], [data-pdp-url]',
                    '''els => els.map(e => e.getAttribute("href") || e.getAttribute("data-pdp-url"))'''
                ) or []
                for h in hrefs:
                    u = _norm(h)
                    if u and u not in seen:
                        seen.add(u)
                        links.append(u)

                _close_context(ctx)

            if links:
                break
        except Exception as e:
            print(f"[warn] DOM link extraction failed (attempt {attempt}) for {url}: {e}", file=sys.stderr)
            continue

    return links

# =========================
# GitHub helpers
# =========================

def gh_call(method: str, path: str, token: str, payload: Optional[Dict[str, Any]] = None) -> Optional[Any]:
    if not token:
        print("[warn] No token provided to gh_call.", file=sys.stderr)
        return None
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    url = GITHUB_API + path
    try:
        if method == "GET":
            r = requests.get(url, headers=headers, timeout=20)
        elif method == "POST":
            r = requests.post(url, headers=headers, json=payload, timeout=20)
        elif method == "PATCH":
            r = requests.patch(url, headers=headers, json=payload, timeout=20)
        else:
            return None
        if r.status_code >= 400:
            print(f"[warn] GitHub API {method} {path} -> {r.status_code} {r.text}", file=sys.stderr)
            return None
        return r.json()
    except Exception as e:
        print(f"[warn] GitHub API {method} {path} failed: {e}", file=sys.stderr)
        return None

def list_open_issues(repo: str, token: str, label: str) -> List[Dict[str, Any]]:
    return gh_call("GET", f"/repos/{repo}/issues?state=open&labels={label}", token) or []

def find_issue_by_key(open_issues: List[Dict[str, Any]], key: str) -> Optional[Dict[str, Any]]:
    for i in open_issues:
        if key in (i.get("title") or ""):
            return i
    return None

def create_issue(repo: str, token: str, title: str, body: str, labels: List[str]):
    gh_call("POST", f"/repos/{repo}/issues", token, {"title": title, "body": body, "labels": labels})

def close_issue(repo: str, token: str, issue_number: int):
    gh_call("PATCH", f"/repos/{repo}/issues/{issue_number}", token, {"state": "closed"})

# =========================
# Push helpers
# =========================

def maybe_send_pushover(token: Optional[str], user: Optional[str], title: str, message: str, url: Optional[str] = None):
    if not token or not user:
        return
    data = {"token": token, "user": user, "title": title, "message": message}
    if url:
        data["url"] = url
    try:
        requests.post("https://api.pushover.net/1/messages.json", data=data, timeout=15)
    except Exception as e:
        print(f"[warn] pushover failed: {e}", file=sys.stderr)

def maybe_send_telegram(bot_token: Optional[str], chat_id: Optional[str], title: str, message: str, url: Optional[str] = None):
    if not bot_token or not chat_id:
        return
    text = f"*{title}*\n{message}"
    if url:
        text += f"\n{url}"
    try:
        requests.post(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            data={"chat_id": chat_id, "text": text, "parse_mode": "Markdown"},
            timeout=15,
        )
    except Exception as e:
        print(f"[warn] telegram failed: {e}", file=sys.stderr)

# =========================
# Stock detection
# =========================

def detect_stock(html: str, t: Target) -> Optional[bool]:
    """
    Return True (in stock), False (OOS), or None (unknown).
    Prefers JSON/schema signals, then regex/contains according to config.
    """
    mode = (t.parse.mode or "contains").lower()
    low = (html or "").lower()

    # Strong structured signals
    if re.search(r'"availability"\s*:\s*"[^"]*InStock', html or "", flags=re.I) or \
       re.search(r'"(availability_status|availability|inventory_status)"\s*:\s*"IN_STOCK"', html or "", flags=re.I):
        return True
    if re.search(r'"availability"\s*:\s*"[^"]*OutOfStock', html or "", flags=re.I) or \
       re.search(r'"(availability_status|availability|inventory_status)"\s*:\s*"(OUT_OF_STOCK|UNAVAILABLE)"', html or "", flags=re.I):
        return False

    if mode == "regex":
        pin = t.parse.pattern_in_stock
        pout = t.parse.pattern_out_of_stock
        has_in = bool(re.search(pin, html or "", flags=re.I | re.S)) if pin else False
        has_out = bool(re.search(pout, html or "", flags=re.I | re.S)) if pout else False
        if has_in and not has_out:
            return True
        if has_out and not has_in:
            return False
        return None

    # mode == "contains"
    def contains_any(text: str, needles: List[str]) -> bool:
        return any((n or "").lower() in text for n in (needles or []))

    has_in = contains_any(low, t.parse.in_stock_contains)
    has_out = contains_any(low, t.parse.out_of_stock_contains)
    if has_in and not has_out:
        return True
    if has_out and not has_in:
        return False
    return None

def _human_bootstrap_once():
    """
    If PC_REQUIRE_HUMAN=1 and we detect Imperva on the homepage,
    open a headed window, bring it to front, and wait for the user to clear it.
    Persist cookies/state so future runs are hands-free.
    """
    if not PC_REQUIRE_HUMAN:
        return

    if not PC_HEADED:
        print("[warn] PC_REQUIRE_HUMAN=1 but PC_HEADED=0; cannot show a window.", file=sys.stderr)
        return

    print("[action] Human bootstrap: opening a visible browser window for Imperva solve...", file=sys.stderr)
    from playwright.sync_api import sync_playwright

    try:
        with sync_playwright() as pw:
            ctx = _open_context(pw)
            ctx = _maybe_load_cookies_into_context(ctx)
            page = ctx.new_page()
            try:
                page.bring_to_front()
            except Exception:
                pass

            page.goto(PC_BOOT_URL, wait_until="domcontentloaded", timeout=30000)

            html = page.content()
            if not _looks_like_incapsula_challenge(html):
                # Already clear; persist and bail
                try: ctx.storage_state(path=STORAGE_STATE_PATH)
                except Exception: pass
                _close_context(ctx)
                print("[info] No challenge detected on bootstrap.", file=sys.stderr)
                return

            print("[action] Please solve the 'I am human' check in the visible window.", file=sys.stderr)
            solved = _await_challenge_resolution(page)

            if solved:
                print("[info] Bootstrap solved; cookies persisted.", file=sys.stderr)
            else:
                print("[warn] Bootstrap did not complete within timeout.", file=sys.stderr)

            _close_context(ctx)
    except Exception as e:
        print(f"[warn] Human bootstrap failed: {e}", file=sys.stderr)

# =========================
# Main loop
# =========================

def safe_main():
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GITHUB_TOKEN", "")

    cfg = load_config("targets.yaml")
    if not cfg.targets:
        print("[warn] No targets found in targets.yaml. Nothing to check this run.", file=sys.stderr)
        return

    label = "restockwatch"
        # Try a one-time human bootstrap if requested
    _human_bootstrap_once()

    # Ensure label exists (422 if already exists is fine)
    _ = gh_call("POST", f"/repos/{repo}/labels", token,
                {"name": label, "color": "0E8A16", "description": "Auto-created by restock watcher"})

    open_issues = list_open_issues(repo, token, label=label)

    for t in cfg.targets:
        if not t.url:
            print(f"[warn] Skipping target with empty URL: {t.name}", file=sys.stderr)
            continue

        # --- Category expansion for Pokémon Center ---
        if (t.expand or "").lower() == "pc_category":
            # Render category (PC needs JS)
            cat_html, cat_status, cat_elapsed, cat_source = fetch_pc_or_raw(
                t.url, ua=cfg.user_agent, timeout_seconds=cfg.timeout_seconds
            )
            if cat_html is None:
                print(f"[warn] Could not fetch category {t.name}; skipping.", file=sys.stderr)
                continue

            print(
                f"[debug] {t.name} [category]: fetched {len(cat_html)} bytes in {cat_elapsed} ms "
                f"(status={cat_status}, source={cat_source}) from {t.url}"
            )

            # Extract product links from network (best), fallback to DOM, then HTML scan
            product_urls = collect_pc_product_links_with_network(
                t.url, timeout_seconds=cfg.timeout_seconds, max_links=60
            )
            if not product_urls:
                product_urls = extract_pc_links_from_dom_with_playwright(
                    t.url, timeout_seconds=cfg.timeout_seconds
                )
            if not product_urls:
                product_urls = extract_pc_product_links(cat_html, max_links=30)

            if product_urls:
                preview = ", ".join(product_urls[:5])
                print(f"[debug] {t.name}: network-extracted {len(product_urls)} product URLs")
                print(f"[debug] {t.name}: first URLs -> {preview}")
            else:
                print(f"[info] No product links found in category: {t.name}")
                aggregate_key = f"[ANY IN STOCK] {t.name}"
                existing_any = find_issue_by_key(open_issues, aggregate_key)
                if existing_any:
                    close_issue(repo, token, existing_any["number"])
                    open_issues = list_open_issues(repo, token, label=label)
                    print(f"[info] closed aggregate issue for {t.name} (no products found)")
                continue

            # Check each product page (rendered for PC) using this target's parse rules
            in_stock_urls: List[str] = []
            for purl in product_urls:
                p_html, p_status, p_elapsed, p_source = fetch_pc_or_raw(
                    purl, ua=cfg.user_agent, timeout_seconds=cfg.timeout_seconds
                )
                if p_html is None:
                    continue
                st = detect_stock(p_html, t)
                print(
                    f"[debug] {t.name} product: detect_stock -> {st} "
                    f"(len={len(p_html)}, ms={p_elapsed}, source={p_source}) {purl}"
                )
                if st is True:
                    in_stock_urls.append(purl)

            # === Aggregate issue logic: one issue if ANY are in stock ===
            aggregate_key = f"[ANY IN STOCK] {t.name}"
            existing_any = find_issue_by_key(open_issues, aggregate_key)

            if in_stock_urls:
                title = f"✅ In stock in category – {t.name} {aggregate_key}"
                body_lines = [
                    f"One or more items in **{t.name}** appear to be **IN STOCK**:",
                    "",
                    *[f"- {u}" for u in in_stock_urls],
                    "",
                    "_(Auto by RestockWatch)_",
                ]
                body = "\n".join(body_lines)

                if not existing_any:
                    create_issue(repo, token, title, body, labels=[label])
                    open_issues = list_open_issues(repo, token, label=label)  # refresh to avoid dupes
                    print(f"[alert] opened aggregate IN-STOCK issue for {t.name}")
                else:
                    print(f"[info] aggregate IN-STOCK issue already open for {t.name}")
            else:
                if existing_any:
                    close_issue(repo, token, existing_any["number"])
                    open_issues = list_open_issues(repo, token, label=label)
                    print(f"[info] closed aggregate issue for {t.name} (no items currently in stock)")
                else:
                    print(f"[info] no items in stock for {t.name} (no aggregate issue)")
            continue  # done with this category target

        # --- Single product / general URL path ---
        html, status, elapsed_ms, source = fetch_pc_or_raw(
            t.url, ua=cfg.user_agent, timeout_seconds=cfg.timeout_seconds
        )
        if html is None:
            print(f"[warn] Could not fetch {t.name}; skipping.", file=sys.stderr)
            continue

        print(
            f"[debug] {t.name}: fetched {len(html)} bytes in {elapsed_ms} ms "
            f"(status={status}, source={source}) from {t.url}"
        )

        # Traffic spike heuristics
        is_high_status = (status in HIGH_TRAFFIC_STATUSES) if status is not None else False
        is_high_latency = (elapsed_ms is not None and elapsed_ms > TRAFFIC_LATENCY_MS)

        if is_high_status or is_high_latency:
            traffic_key = f"[TRAFFIC] {t.name}"
            traffic_title = f"⚠️ High traffic detected {traffic_key}"
            traffic_body = (
                f"Detected potential high traffic on: {t.name}\n\n"
                f"URL: {t.url}\n"
                f"HTTP status: {status}\n"
                f"Latency: {elapsed_ms} ms\n"
                f"Source: {source}\n\n"
                f"_(Auto by RestockWatch)_"
            )
            existing_traffic = find_issue_by_key(open_issues, traffic_key)
            if not existing_traffic:
                create_issue(repo, token, traffic_title, traffic_body, labels=[label])
                open_issues = list_open_issues(repo, token, label=label)  # refresh
                print(f"[info] opened traffic issue for {t.name}")
            else:
                print(f"[info] traffic issue already open for {t.name}")

        # Normal stock detection
        state = detect_stock(html, t)
        print(f"[debug] {t.name}: detect_stock -> {state}")
        stock_key = f"[{t.name}]"
        existing_stock = find_issue_by_key(open_issues, stock_key)

        if state is True:
            title = f"✅ IN STOCK {stock_key}"
            body = f"{t.name} appears to be IN STOCK.\n\nURL: {t.url}\n\n_(Auto by RestockWatch)_"
            if not existing_stock:
                create_issue(repo, token, title, body, labels=[label])
                open_issues = list_open_issues(repo, token, label=label)  # refresh
                maybe_send_pushover(cfg.pushover_token, cfg.pushover_user, title, t.url, t.url)
                maybe_send_telegram(cfg.telegram_bot_token, cfg.telegram_chat_id, title, t.url, t.url)
                print(f"[alert] opened issue for {t.name}")
            else:
                print(f"[info] already open issue for {t.name}")
        elif state is False:
            if existing_stock:
                close_issue(repo, token, existing_stock["number"])
                print(f"[info] closed issue for {t.name} (OOS)")
        else:
            print(f"[info] Unknown state for {t.name} (no action)")

# =========================
# Entrypoint
# =========================

if __name__ == "__main__":
    try:
        safe_main()
    except Exception as e:
        print(f"[fatal] Uncaught error: {e}", file=sys.stderr)
