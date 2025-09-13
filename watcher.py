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

DEBUG_SHOTS_DIR = os.environ.get("PC_DEBUG_DIR", "pc_debug")
os.makedirs(DEBUG_SHOTS_DIR, exist_ok=True)

PC_REAL_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36"
)
PC_HEADED = os.environ.get("PC_HEADED", "0") == "1"  # set to 1 to run non-headless on self-hosted

# --- Traffic/latency heuristics ---
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
# Scraping helpers
# =========================

def extract_pc_product_links(html: str, max_links: int = 50) -> List[str]:
    """
    Scrape Pokémon Center product links from a category page (raw HTML).
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
        for m in re.findall(pat, html, flags=re.I):
            path = m if m.startswith("/product/") else ("/" + m.lstrip("/"))
            url = "https://www.pokemoncenter.com" + path.split("?")[0]
            if url not in seen:
                seen.add(url)
                found.append(url)
                if len(found) >= max_links:
                    return found
    return found

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

# ---- Debug utilities for Playwright dumps ----
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

    # html & screenshot
    try:
        (base.with_suffix(".html")).write_text(html or "", encoding="utf-8")
    except Exception as e:
        print(f"[warn] debug html write failed: {e}", file=sys.stderr)

    try:
        page.screenshot(path=str(base.with_suffix(".png")), full_page=True)
    except Exception as e:
        print(f"[warn] debug screenshot failed: {e}", file=sys.stderr)

    # collect light-weight response metadata + save JSON bodies
    info = {
        "status": resp_status,
        "notes": notes,
        "responses": [],
    }
    for r in responses:
        try:
            ctype = (r.headers.get("content-type") or "").lower()
            rec = {"url": r.url, "status": r.status, "content_type": ctype}
            info["responses"].append(rec)

            # Save JSON bodies
            if "application/json" in ctype:
                body = r.text()  # sync in Playwright Python
                if body and len(body) < 2_000_000:
                    jname = outdir / f"{ts}-{name}-{_pc_slug(r.url)}.json"
                    jname.write_text(body, encoding="utf-8")
        except Exception:
            continue

    try:
        (base.with_suffix(".info.json")).write_text(_json.dumps(info, indent=2), encoding="utf-8")
    except Exception as e:
        print(f"[warn] debug info write failed: {e}", file=sys.stderr)

# ---- Playwright render for a single URL (PC) ----
def fetch_pc_rendered(url: str, ua: str, timeout_seconds: int = 20):
    """
    Render Pokemon Center pages with Playwright and return (html, status, elapsed_ms).
    Dumps HTML/PNG/JSON XHRs to pc_debug/ when DEBUG_PC_DUMP=1.
    """
    from playwright.sync_api import sync_playwright
    import time as _time

    t0 = _time.perf_counter()
    html = None
    status = None
    waited_label = "domcontentloaded"
    all_responses = []

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=not PC_HEADED,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-gpu",
                ],
            )
            context = browser.new_context(
                user_agent=PC_REAL_UA,
                viewport={'width': 1366, 'height': 900},
                locale="en-US",
                timezone_id="America/New_York",
                java_script_enabled=True,
                extra_http_headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Upgrade-Insecure-Requests": "1",
                },
            )
            context.add_init_script("""
                Object.defineProperty(navigator,'webdriver',{get:()=>undefined});
                window.chrome = { runtime: {} };
                Object.defineProperty(navigator, 'languages', { get: () => ['en-US','en'] });
                Object.defineProperty(navigator, 'platform', { get: () => 'Win32' });
            """)

            page = context.new_page()

            main_response = None
            def _resp(r):
                nonlocal main_response, all_responses
                all_responses.append(r)
                if r.url.split("#")[0] == url.split("#")[0] and main_response is None:
                    main_response = r
            page.on("response", _resp)

            page.goto(url, wait_until="domcontentloaded", timeout=timeout_seconds * 1000)

            # Cookie banner (best-effort)
            for sel in [
                'button:has-text("Accept All")',
                'button:has-text("Accept all")',
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

            # Human-ish nudge if headed (helps some bot checks)
            if PC_HEADED:
                try:
                    page.mouse.move(200, 200)
                    page.mouse.wheel(0, 1000)
                except Exception:
                    pass

            # Try to let XHRs finish
            try:
                page.wait_for_load_state("networkidle", timeout=8000)
                waited_label = "networkidle"
            except Exception:
                try: page.mouse.wheel(0, 1600)
                except Exception: pass
                page.wait_for_timeout(2000)
                waited_label = "fallback-wait"

            if len((page.content() or "")) < 4000:
                page.wait_for_timeout(1500)

            html = page.content()
            status = main_response.status if main_response else 200

            # DEBUG DUMP
            _pc_dump(
                name=_pc_slug(url),
                page=page,
                html=html or "",
                resp_status=status,
                notes=f"waited={waited_label}",
                responses=all_responses,
            )

            context.close()
            browser.close()

    except Exception as e:
        print(f"[warn] Playwright fetch failed for {url}: {e}", file=sys.stderr)
        return None, None, None

    elapsed_ms = int((_time.perf_counter() - t0) * 1000)
    if len(html or "") < 5000:
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

def collect_pc_product_links_with_network(url: str, timeout_seconds: int = 20, max_links: int = 60) -> List[str]:
    """
    Open a Pokémon Center *category* URL in Playwright and capture product URLs
    by scanning the *network responses* (JSON/JS/HTML) for '/product/...' paths.
    """
    from playwright.sync_api import sync_playwright

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

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=not PC_HEADED,
                args=["--disable-blink-features=AutomationControlled", "--no-sandbox", "--disable-gpu"],
            )
            context = browser.new_context(
                user_agent=PC_REAL_UA,
                viewport={'width': 1366, 'height': 900},
                locale="en-US",
                timezone_id="America/New_York",
                java_script_enabled=True,
                extra_http_headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Upgrade-Insecure-Requests": "1",
                },
            )
            context.add_init_script("""
                Object.defineProperty(navigator,'webdriver',{get:()=>undefined});
                window.chrome = { runtime: {} };
                Object.defineProperty(navigator, 'languages', { get: () => ['en-US','en'] });
                Object.defineProperty(navigator, 'platform', { get: () => 'Win32' });
            """)

            page = context.new_page()

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

            # Human-ish moves help sometimes
            if PC_HEADED:
                try:
                    page.mouse.move(300, 300)
                    page.mouse.wheel(0, 1200)
                except Exception:
                    pass

            # Prefer networkidle to let feeds land
            try:
                page.wait_for_load_state("networkidle", timeout=8000)
            except Exception:
                page.wait_for_timeout(2500)

            context.close()
            browser.close()

    except Exception as e:
        print(f"[warn] Network link extraction failed for {url}: {e}", file=sys.stderr)

    if len(links) > max_links:
        links = links[:max_links]
    return links

def extract_pc_links_from_dom_with_playwright(url: str, timeout_seconds: int = 20) -> List[str]:
    """
    Simple DOM fallback: look for anchors or data-pdp-url in hydrated DOM.
    """
    from playwright.sync_api import sync_playwright

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

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=not PC_HEADED,
                args=["--disable-blink-features=AutomationControlled", "--no-sandbox", "--disable-gpu"],
            )
            context = browser.new_context(
                user_agent=PC_REAL_UA,
                viewport={'width': 1366, 'height': 900},
                locale="en-US",
                timezone_id="America/New_York",
                java_script_enabled=True,
            )
            context.add_init_script("Object.defineProperty(navigator,'webdriver',{get:()=>undefined})")
            page = context.new_page()
            page.goto(url, wait_until="domcontentloaded", timeout=timeout_seconds * 1000)

            # Cookie accept best-effort
            for sel in [
                'button:has-text("Accept All")', 'button:has-text("Accept Cookies")',
                '[data-testid="cookie-accept-all"]', '[id*="onetrust-accept"]'
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

            context.close()
            browser.close()
    except Exception as e:
        print(f"[warn] DOM link extraction failed for {url}: {e}", file=sys.stderr)

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
# Stock detection
# =========================

def detect_stock(html: str, t: Target) -> Optional[bool]:
    """
    Return True (in stock), False (OOS), or None (unknown).
    Prefers JSON/schema signals, then regex/contains according to config.
    """
    mode = (t.parse.mode or "contains").lower()
    low = html.lower()

    if re.search(r'"availability"\s*:\s*"[^"]*InStock', html, flags=re.I) or \
       re.search(r'"(availability_status|availability|inventory_status)"\s*:\s*"IN_STOCK"', html, flags=re.I):
        return True
    if re.search(r'"availability"\s*:\s*"[^"]*OutOfStock', html, flags=re.I) or \
       re.search(r'"(availability_status|availability|inventory_status)"\s*:\s*"(OUT_OF_STOCK|UNAVAILABLE)"', html, flags=re.I):
        return False

    if mode == "regex":
        pin = t.parse.pattern_in_stock
        pout = t.parse.pattern_out_of_stock
        has_in = bool(re.search(pin, html, flags=re.I | re.S)) if pin else False
        has_out = bool(re.search(pout, html, flags=re.I | re.S)) if pout else False
        if has_in and not has_out:
            return True
        if has_out and not has_in:
            return False
        return None

    def contains_any(text: str, needles: List[str]) -> bool:
        return any((n or "").lower() in text for n in (needles or []))

    has_in = contains_any(low, t.parse.in_stock_contains)
    has_out = contains_any(low, t.parse.out_of_stock_contains)
    if has_in and not has_out:
        return True
    if has_out and not has_in:
        return False
    return None

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
            # Render the category page (PC needs JS)
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

            # --- Extract product links from network (best) then fall back ---
            product_urls = collect_pc_product_links_with_network(
                t.url, timeout_seconds=cfg.timeout_seconds, max_links=60
            )

            if not product_urls:
                product_urls = extract_pc_links_from_dom_with_playwright(
                    t.url, timeout_seconds=cfg.timeout_seconds
                )

            if not product_urls:
                product_urls = extract_pc_product_links(cat_html, max_links=30)

            # Extra visibility
            if product_urls:
                preview = ", ".join(product_urls[:5])
                print(f"[debug] {t.name}: network-extracted {len(product_urls)} product URLs")
                print(f"[debug] {t.name}: first URLs -> {preview}")
            else:
                print(f"[info] No product links found in category: {t.name}")
                # Close the aggregate issue if it exists (nothing to buy)
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
        # --- END category path ---

        # ----- Single product / general URL path -----
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
