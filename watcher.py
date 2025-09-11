#!/usr/bin/env python3
import os, re, sys, time, json
import requests
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
import yaml

GITHUB_API = "https://api.github.com"

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
    expand: Optional[str] = None 

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
        # Return empty config but keep job alive
        return Config()
    except Exception as e:
        print(f"[error] Failed to parse {path}: {e}", file=sys.stderr)
        return Config()

    targets = []
    for t in (raw.get("targets") or []):
        parse = t.get("parse", {})
        tp = TargetParse(
            mode=(parse.get("mode") or "contains"),
            pattern_in_stock=parse.get("pattern_in_stock"),
            pattern_out_of_stock=parse.get("pattern_out_of_stock"),
            in_stock_contains=parse.get("in_stock_contains") or [],
            out_of_stock_contains=parse.get("out_of_stock_contains") or []
        )
        targets.append(Target(
            name=t.get("name", "Unnamed"),
            url=t.get("url", ""),
            parse=tp,
            priority_keywords=t.get("priority_keywords") or [],
            expand=t.get("expand")
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

def extract_pc_product_links(html: str, max_links: int = 30) -> List[str]:
    """
    Scrape Pokémon Center product links from a category page without extra deps.
    Looks for href="/product/....". Returns absolute URLs, de-duped.
    """
    links = re.findall(r'href="(/product/[^"]+)"', html)
    out, seen = [], set()
    for href in links:
        url = "https://www.pokemoncenter.com" + href.split("?")[0]
        if url not in seen:
            seen.add(url)
            out.append(url)
        if len(out) >= max_links:
            break
    return out

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
            elapsed_ms = int((time.time() - start) * 1000)
            print(f"[warn] fetch attempt {attempt+1}/{retries+1} failed for {url}: {e}", file=sys.stderr)
            time.sleep(1.0)
    return None, None, None

# --- GitHub API helpers (required) ---
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

def detect_stock(html: str, t: Target) -> Optional[bool]:
    """Return True (in stock), False (OOS), or None (unknown).
       Uses positive AND negative cues; includes schema.org availability.
    """
    mode = (t.parse.mode or "contains").lower()
    low = html.lower()

    # Strong structured signals (if present)
    if re.search(r'"availability"\s*:\s*"[^"]*InStock', html, flags=re.I):
        print(f"[debug] {t.name}: schema.org availability -> InStock")
        return True
    if re.search(r'"availability"\s*:\s*"[^"]*OutOfStock', html, flags=re.I):
        print(f"[debug] {t.name}: schema.org availability -> OutOfStock")
        return False

    def contains_any(text: str, needles: List[str]) -> bool:
        return any(n.lower() in text for n in (needles or []))

    if mode == "regex":
        pin = t.parse.pattern_in_stock
        pout = t.parse.pattern_out_of_stock
        has_in = bool(re.search(pin, html, flags=re.I)) if pin else False
        has_out = bool(re.search(pout, html, flags=re.I)) if pout else False
        print(f"[debug] {t.name}: regex has_in={has_in} has_out={has_out}")
        if has_in and not has_out:
            return True
        if has_out and not has_in:
            return False
        return None

    # mode == "contains"
    has_in = contains_any(low, t.parse.in_stock_contains)
    has_out = contains_any(low, t.parse.out_of_stock_contains)
    print(f"[debug] {t.name}: contains has_in={has_in} has_out={has_out}")
    if has_in and not has_out:
        return True
    if has_out and not has_in:
        return False
    return None

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
            timeout=15
        )
    except Exception as e:
        print(f"[warn] telegram failed: {e}", file=sys.stderr)

def safe_main():
    # env always present in Actions; we won’t hard-exit if missing
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GITHUB_TOKEN", "")

    cfg = load_config("targets.yaml")
    if not cfg.targets:
        print("[warn] No targets found in targets.yaml. Nothing to check this run.", file=sys.stderr)
        return

    label = "restockwatch"

    # Best-effort: ensure label exists
    _ = gh_call("POST", f"/repos/{repo}/labels", token,
                {"name": label, "color": "0E8A16", "description": "Auto-created by restock watcher"})

    open_issues = list_open_issues(repo, token, label=label)

    for t in cfg.targets:
        if not t.url:
            print(f"[warn] Skipping target with empty URL: {t.name}", file=sys.stderr)
            continue
        # --- NEW: category expansion for Pokémon Center ---
        if (t.expand or "").lower() == "pc_category":
            # Fetch category page once
            cat_html, cat_status, cat_elapsed = fetch_html_with_retries(
                t.url, timeout=cfg.timeout_seconds, ua=cfg.user_agent, retries=2
            )
            if cat_html is None:
                print(f"[warn] Could not fetch category {t.name}; skipping.", file=sys.stderr)
                continue

            product_urls = extract_pc_product_links(cat_html, max_links=30)
            if not product_urls:
                print(f"[info] No product links found in category: {t.name}")
                continue

            print(f"[debug] {t.name}: found {len(product_urls)} product URLs")

            # Check each product page using the SAME parse rules from this target
            for purl in product_urls:
                p_html, p_status, p_elapsed = fetch_html_with_retries(
                    purl, timeout=cfg.timeout_seconds, ua=cfg.user_agent, retries=2
                )
                if p_html is None:
                    continue
                state = detect_stock(p_html, t)  # reuse this target's parse rules
                print(f"[debug] {t.name}: detect_stock -> {state}")
                stock_key = f"[{t.name}] {purl}"  # unique per product URL under this category
                existing_stock = find_issue_by_key(open_issues, stock_key)

                if state is True:
                    title = f"✅ IN STOCK {stock_key}"
                    body = f"Appears IN STOCK.\n\nURL: {purl}\n\n_(Auto by RestockWatch)_"
                    if not existing_stock:
                        create_issue(repo, token, title, body, labels=[label])
                        maybe_send_pushover(cfg.pushover_token, cfg.pushover_user, title, purl, purl)
                        maybe_send_telegram(cfg.telegram_bot_token, cfg.telegram_chat_id, title, purl, purl)
                        print(f"[alert] opened issue for {purl}")
                elif state is False:
                    if existing_stock:
                        close_issue(repo, token, existing_stock["number"])
                        print(f"[info] closed issue for {purl} (OOS)")
                else:
                    # Unknown—do nothing
                    pass

            # Done with this category target; move to next target
            continue
        # --- END NEW ---
                    
        # 1) Fetch (returns body, status code, and elapsed ms)
        html, status, elapsed_ms = fetch_html_with_retries(
            t.url,
            timeout=cfg.timeout_seconds,
            ua=cfg.user_agent,
            retries=2
        )
        if html is None:
            print(f"[warn] Could not fetch {t.name}; skipping.", file=sys.stderr)
            continue
            
        # Debug (optional): show we actually got content and what URL we checked
        print(f"[debug] {t.name}: fetched {len(html)} bytes from {t.url}")

        # 2) Traffic spike heuristics (optional early heads-up)
        TRAFFIC_LATENCY_MS = 2500  # adjust if you like
        HIGH_TRAFFIC_STATUSES = {429, 503}

        if (status in HIGH_TRAFFIC_STATUSES) or (elapsed_ms is not None and elapsed_ms > TRAFFIC_LATENCY_MS):
            traffic_key = f"[TRAFFIC] {t.name}"
            traffic_title = f"⚠️ High traffic/limited availability detected {traffic_key}"
            traffic_body = (
                f"Detected potential high traffic on: {t.name}\n\n"
                f"URL: {t.url}\n"
                f"HTTP status: {status}\n"
                f"Latency: {elapsed_ms} ms\n\n"
                f"_(Auto by RestockWatch)_"
            )
            existing_traffic = find_issue_by_key(open_issues, traffic_key)
            if not existing_traffic:
                create_issue(repo, token, traffic_title, traffic_body, labels=[label])
                maybe_send_pushover(cfg.pushover_token, cfg.pushover_user, traffic_title, t.url, t.url)
                maybe_send_telegram(cfg.telegram_bot_token, cfg.telegram_chat_id, traffic_title, t.url, t.url)
                print(f"[info] opened traffic issue for {t.name}")
            else:
                print(f"[info] traffic issue already open for {t.name}")

        # 3) Normal stock detection
        state = detect_stock(html, t)
        stock_key = f"[{t.name}]"
        existing_stock = find_issue_by_key(open_issues, stock_key)

        if state is True:
            title = f"✅ IN STOCK {stock_key}"
            body = f"{t.name} appears to be IN STOCK.\n\nURL: {t.url}\n\n_(Auto by RestockWatch)_"
            if not existing_stock:
                create_issue(repo, token, title, body, labels=[label])
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
                print(f"[info] OOS and no open issue for {t.name}")

        else:
            print(f"[info] Unknown state for {t.name} (no action)")

if __name__ == "__main__":
    try:
        safe_main()
    except Exception as e:
        # Never fail the job hard; log the error instead
        print(f"[fatal] Uncaught error: {e}", file=sys.stderr)
