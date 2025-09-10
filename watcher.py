#!/usr/bin/env python3
import os, re, sys, time, json
import requests
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
import yaml

GITHUB_API = "https://api.github.com"

@dataclass
class TargetParse:
    mode: str = "selector_text"   # "regex" or "contains" (simplified for GH runner)
    # For "regex" mode
    pattern_in_stock: Optional[str] = None
    pattern_out_of_stock: Optional[str] = None
    # For "contains" mode
    in_stock_contains: List[str] = field(default_factory=list)
    out_of_stock_contains: List[str] = field(default_factory=list)

@dataclass
class Target:
    name: str
    url: str
    parse: TargetParse
    priority_keywords: List[str] = field(default_factory=list)

@dataclass
class Config:
    poll_interval_seconds: int = 120
    timeout_seconds: int = 20
    user_agent: str = "RestockWatch-GHA/1.0"
    targets: List[Target] = field(default_factory=list)
    # Optional: these only work if secrets are added
    pushover_token: Optional[str] = None
    pushover_user: Optional[str] = None
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None

def load_config(path: str) -> Config:
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    targets = []
    for t in raw.get("targets", []):
        parse = t.get("parse", {})
        tp = TargetParse(
            mode=parse.get("mode", "contains"),
            pattern_in_stock=parse.get("pattern_in_stock"),
            pattern_out_of_stock=parse.get("pattern_out_of_stock"),
            in_stock_contains=parse.get("in_stock_contains", []) or [],
            out_of_stock_contains=parse.get("out_of_stock_contains", []) or []
        )
        targets.append(Target(
            name=t.get("name"),
            url=t.get("url"),
            parse=tp,
            priority_keywords=t.get("priority_keywords", []) or []
        ))
    cfg = Config(
        poll_interval_seconds=raw.get("poll_interval_seconds", 120),
        timeout_seconds=raw.get("timeout_seconds", 20),
        user_agent=raw.get("user_agent", "RestockWatch-GHA/1.0"),
        targets=targets,
        pushover_token=os.environ.get("PUSHOVER_TOKEN"),
        pushover_user=os.environ.get("PUSHOVER_USER"),
        telegram_bot_token=os.environ.get("TELEGRAM_BOT_TOKEN"),
        telegram_chat_id=os.environ.get("TELEGRAM_CHAT_ID"),
    )
    return cfg

def fetch_html(url: str, timeout: int, ua: str) -> str:
    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
    r.raise_for_status()
    return r.text

def detect_stock(html: str, t: Target) -> Optional[bool]:
    mode = (t.parse.mode or "contains").lower()
    low = html.lower()
    if mode == "regex":
        if t.parse.pattern_in_stock and re.search(t.parse.pattern_in_stock, html, flags=re.I):
            return True
        if t.parse.pattern_out_of_stock and re.search(t.parse.pattern_out_of_stock, html, flags=re.I):
            return False
        return None
    # default "contains"
    if t.parse.in_stock_contains:
        for s in t.parse.in_stock_contains:
            if s.lower() in low:
                return True
    if t.parse.out_of_stock_contains:
        for s in t.parse.out_of_stock_contains:
            if s.lower() in low:
                return False
    return None

def gh_get(path: str, token: str) -> Any:
    h = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    r = requests.get(GITHUB_API + path, headers=h, timeout=20)
    r.raise_for_status()
    return r.json()

def gh_post(path: str, token: str, payload: Dict[str, Any]) -> Any:
    h = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    r = requests.post(GITHUB_API + path, headers=h, json=payload, timeout=20)
    r.raise_for_status()
    return r.json()

def gh_patch(path: str, token: str, payload: Dict[str, Any]) -> Any:
    h = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    r = requests.patch(GITHUB_API + path, headers=h, json=payload, timeout=20)
    r.raise_for_status()
    return r.json()

def list_open_issues(repo: str, token: str, label: str = "restockwatch") -> List[Dict[str, Any]]:
    issues = gh_get(f"/repos/{repo}/issues?state=open&labels={label}", token)
    return issues

def find_issue_by_key(open_issues: List[Dict[str, Any]], key: str) -> Optional[Dict[str, Any]]:
    for i in open_issues:
        if key in i.get("title", ""):
            return i
    return None

def create_issue(repo: str, token: str, title: str, body: str, labels: List[str]):
    payload = {"title": title, "body": body, "labels": labels}
    gh_post(f"/repos/{repo}/issues", token, payload)

def close_issue(repo: str, token: str, issue_number: int):
    gh_patch(f"/repos/{repo}/issues/{issue_number}", token, {"state": "closed"})

def maybe_send_pushover(token: Optional[str], user: Optional[str], title: str, message: str, url: Optional[str] = None):
    if not token or not user:
        return
    data = {"token": token, "user": user, "title": title, "message": message}
    if url: data["url"] = url
    try:
        requests.post("https://api.pushover.net/1/messages.json", data=data, timeout=15)
    except Exception as e:
        print(f"[warn] pushover failed: {e}", file=sys.stderr)

def maybe_send_telegram(bot_token: Optional[str], chat_id: Optional[str], title: str, message: str, url: Optional[str] = None):
    if not bot_token or not chat_id:
        return
    text = f"*{title}*\n{message}"
    if url: text += f"\n{url}"
    try:
        requests.post(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            data={"chat_id": chat_id, "text": text, "parse_mode": "Markdown"},
            timeout=15
        )
    except Exception as e:
        print(f"[warn] telegram failed: {e}", file=sys.stderr)

def main():
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    if not repo or not token:
        print("This script is intended to run inside GitHub Actions.", file=sys.stderr)
        sys.exit(1)

    cfg = load_config("targets.yaml")
    label = "restockwatch"

    # Ensure label exists (best-effort)
    try:
        # try to create label (ignore if exists)
        requests.post(
            f"{GITHUB_API}/repos/{repo}/labels",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
            json={"name": label, "color": "0E8A16", "description": "Auto-created by restock watcher"},
            timeout=15
        )
    except Exception:
        pass

    open_issues = list_open_issues(repo, token, label=label)
    for t in cfg.targets:
        try:
            html = fetch_html(t.url, timeout=cfg.timeout_seconds, ua=cfg.user_agent)
            state = detect_stock(html, t)
        except Exception as e:
            print(f"[error] fetch/detect failed for {t.name}: {e}", file=sys.stderr)
            state = None

        key = f"[{t.name}]"
        existing = find_issue_by_key(open_issues, key)

        if state is True:
            title = f"✅ IN STOCK {key}"
            body = f"{t.name} appears to be IN STOCK.\n\nURL: {t.url}\n\n_(Auto-created by RestockWatch)_"
            if not existing:
                create_issue(repo, token, title, body, labels=[label])
                maybe_send_pushover(cfg.pushover_token, cfg.pushover_user, title, t.url, t.url)
                maybe_send_telegram(cfg.telegram_bot_token, cfg.telegram_chat_id, title, t.url, t.url)
                print(f"[alert] opened issue for {t.name}")
            else:
                print(f"[info] already open: {t.name}")
        elif state is False:
            if existing:
                close_issue(repo, token, existing["number"])
                print(f"[info] closed issue for {t.name} (now OOS)")
            else:
                print(f"[info] OOS and no open issue for {t.name}")
        else:
            print(f"[info] Unknown state for {t.name} (no change)")

if __name__ == "__main__":
    main()
