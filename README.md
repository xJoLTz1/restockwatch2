# Restock Watch (GitHub Actions)

**Zero-maintenance alerts**. This runs in GitHub Actions every 3 minutes and:
- Checks the product URLs in `targets.yaml`
- If a product looks **IN STOCK**, it opens a GitHub Issue titled `✅ IN STOCK [<name>]`
- GitHub emails you automatically for new issues (no secrets needed)
- When it goes **OOS**, the issue is auto-closed

## Quick Start (no secrets, ~2 minutes)
1. Create a new repo on GitHub.
2. Upload these four files (or upload the provided ZIP):
   - `watcher.py`
   - `targets.yaml`
   - `requirements.txt`
   - `.github/workflows/watch.yml`
3. Commit to `main`. Actions will start automatically.
4. Edit `targets.yaml` in the GitHub web UI and put your real product URLs + match rules.
5. Sit back. When something flips to **IN STOCK**, you'll get an email from GitHub about the new Issue.

> Tip: Make sure your GitHub email notifications are on (they are by default).

## Optional: Push notifications
If you want device push alerts:
1. **Pushover** – add repository secrets:
   - `PUSHOVER_TOKEN`
   - `PUSHOVER_USER`
2. **Telegram** – add repository secrets:
   - `TELEGRAM_BOT_TOKEN`
   - `TELEGRAM_CHAT_ID`

The workflow already passes these env vars. If set, you'll get push alerts in addition to GitHub Issues.

## Tuning detection
- `mode: "contains"` → simple text match on page HTML (faster/easier)
  - `in_stock_contains`: strings like `"Add to Cart"`
  - `out_of_stock_contains`: strings like `"Sold Out"`
- `mode: "regex"` → advanced regular expressions for tougher sites

> This template intentionally avoids heavy headless browsers. If a site renders stock text via JS only, consider swapping a server-rendered URL (e.g., JSON endpoint) or we can add Playwright later.

## Safety & Rate limits
Runs every 3 minutes by default. You can change the cron in `.github/workflows/watch.yml`.
Keep target lists reasonable to avoid being blocked by retailers.

## Notes
- This uses GitHub's built-in `GITHUB_TOKEN` and Issue permissions. No personal tokens required.
- It doesn't store state; the open Issue is treated as the "in-stock" state indicator.
- When OOS, the issue is closed automatically so a future in-stock will create a fresh one.
