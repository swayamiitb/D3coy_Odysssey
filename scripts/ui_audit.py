"""Click through the whole interface like an analyst would, on a private copy of the data, and report anything broken.

Run (API and dashboard up):  python scripts/ui_audit.py   (system Python with Playwright; drives the installed Edge)

A second API instance (port 8001) serves copies of data/ews.db and data/cache.db with the live engine on; the
browser's /api calls are routed to it, so approvals, acknowledgements, case work and drills do not touch the demo
data. Every page error, console error and failed request is collected, and each step asserts what should appear.
Screenshots of each state land in the scratch folder given by --shots (default: a temp folder).
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from playwright.sync_api import Page, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
UI = "http://127.0.0.1:5173"
COPY_API = "http://127.0.0.1:8001"
RESULTS: list[tuple[bool, str, str]] = []


def step(name: str):
    def wrap(fn):
        def run(page: Page, *a):
            try:
                detail = fn(page, *a) or ""
                RESULTS.append((True, name, detail))
            except Exception as exc:  # noqa: BLE001 - record and continue the tour
                RESULTS.append((False, name, f"{type(exc).__name__}: {str(exc).splitlines()[0][:220]}"))
                page.keyboard.press("Escape")
        return run
    return wrap


def start_copy_api(tmp: Path) -> subprocess.Popen:
    for name in ("ews.db", "cache.db"):
        a, b = sqlite3.connect(ROOT / "data" / name), sqlite3.connect(tmp / name)
        a.backup(b)
        a.close()
        b.close()
    env = {**os.environ, "ODYSSEY_DB": str(tmp / "ews.db"), "ODYSSEY_CACHE": str(tmp / "cache.db"), "ODYSSEY_LIVE": "1"}
    proc = subprocess.Popen([str(ROOT / ".venv" / "Scripts" / "python.exe"), "-m", "uvicorn", "backend.app.main:app",
                             "--host", "127.0.0.1", "--port", "8001"], cwd=ROOT, env=env,
                            stdout=open(tmp / "api.log", "w"), stderr=subprocess.STDOUT)
    import httpx
    for _ in range(60):
        try:
            if httpx.get(f"{COPY_API}/api/health", timeout=2).status_code == 200:
                return proc
        except httpx.HTTPError:
            time.sleep(1)
    raise RuntimeError("copy API did not start")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--shots", default=tempfile.mkdtemp(prefix="odyssey-ui-"))
    args = ap.parse_args()
    shots = Path(args.shots)
    shots.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="odyssey-ui-data-"))
    api = start_copy_api(tmp)
    errors: list[str] = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(channel="msedge", headless=True)
            page = browser.new_page(viewport={"width": 1600, "height": 1000})
            page.route("**/api/**", lambda route: route.continue_(url=route.request.url.replace(UI, COPY_API)))
            page.on("pageerror", lambda e: errors.append(f"page error: {e}"))
            page.on("console", lambda m: m.type == "error" and errors.append(f"console: {m.text[:200]}"))
            page.on("response", lambda r: r.status >= 500 and errors.append(f"HTTP {r.status} {r.url}"))
            page.set_default_timeout(15000)

            def go(view: str, tab: str | None = None) -> None:
                # the live views poll every few seconds, so "network idle" may never come: wait for the page header
                page.goto(f"{UI}/?view={view}{'&tab=' + tab if tab else ''}&nolive", wait_until="domcontentloaded")
                page.get_by_role("heading", level=1).first.wait_for()
                page.wait_for_timeout(1200)

            def shot(name: str) -> None:
                page.screenshot(path=str(shots / f"{name}.png"), full_page=True)

            def toast(text: str) -> None:
                page.get_by_text(text, exact=False).first.wait_for(timeout=15000)

            # ---------------------------------------------------------------- Now
            @step("Now: hero, trip card, live strip, map, up next")
            def now_loads(page):
                go("now")
                page.get_by_role("heading", level=1).first.wait_for()
                page.get_by_text("Live", exact=True).first.wait_for()
                page.get_by_text("Across India").wait_for()
                assert page.get_by_role("button", name="Why this warning?").count() == 1
                shot("now")
                return page.get_by_role("heading", level=1).first.inner_text()
            now_loads(page)

            @step("Now: 'Why this warning?' opens the evidence sheet")
            def why(page):
                page.get_by_role("button", name="Why this warning?").click()
                page.locator("aside").filter(has_text="CVE-").first.wait_for()
                shot("alert-sheet")
                page.mouse.click(30, 500)
                page.locator("aside").filter(has_text="CVE-").first.wait_for(state="detached")
            why(page)

            @step("Now: CERT-In report draft opens and closes")
            def certin(page):
                page.get_by_role("button", name="CERT-In report").click()
                page.get_by_text("CERT-In", exact=False).nth(1).wait_for()
                shot("certin")
                page.mouse.click(10, 10)
            certin(page)

            @step("Now: acknowledge the top warning")
            def ack(page):
                page.get_by_role("button", name="Acknowledge", exact=True).click()
                toast("Acknowledged")
            ack(page)

            @step("Now: approve the waiting decision")
            def approve(page):
                page.get_by_role("button", name="Approve & send").first.click()
                page.wait_for_timeout(1500)
            approve(page)

            # ---------------------------------------------------------------- SOC
            @step("SOC overview: all decisions sheet, reject with a reason")
            def soc_decisions(page):
                go("soc", "overview")
                page.get_by_role("button", name="See all").first.click()
                sheet = page.locator("aside").filter(has_text="Needs your decision")
                sheet.wait_for()
                sheet.get_by_role("button", name="Reject").first.click()
                sheet.get_by_role("button", name="False positive").first.click()
                page.wait_for_timeout(1200)
                shot("soc-decisions")
                page.keyboard.press("Escape")
            soc_decisions(page)

            @step("SOC overview: replay sheet plays")
            def replay(page):
                page.get_by_role("button", name="Replay").first.click()
                page.get_by_role("button", name="Replay since go-live").click()
                page.wait_for_timeout(1500)
                shot("replay")
                page.keyboard.press("Escape")
            replay(page)

            @step("SOC overview: shift handover is written")
            def handover(page):
                page.get_by_role("button", name="Write handover").click()
                page.get_by_text("open cases", exact=False).first.wait_for()
                page.locator("aside pre").wait_for()
                text = page.locator("aside pre").inner_text()
                page.keyboard.press("Escape")
                return text.splitlines()[0][:90]
            handover(page)

            @step("SOC warnings: chips, sector filter, more, open a warning")
            def warnings(page):
                go("soc", "warnings")
                page.get_by_role("button", name="Critical", exact=True).click()
                page.locator("select").select_option("BFSI")
                page.wait_for_timeout(800)
                shown = page.get_by_text("Showing", exact=False).inner_text()
                page.locator("main button").filter(has_text="CVE-").first.click()
                page.locator("aside").filter(has_text="CVE-").first.wait_for()
                page.mouse.click(30, 500)
                return shown
            warnings(page)

            @step("SOC cases: start, tick a step, note, assign")
            def cases(page):
                go("soc", "cases")
                page.get_by_role("button", name="Start response").click()
                toast("Start response")
                page.get_by_text("Isolate the affected host", exact=False).click()
                toast("Step done")
                page.get_by_placeholder("Add a note for the team…").fill("UI audit: isolation confirmed by the utility.")
                page.get_by_role("button", name="Add", exact=True).click()
                toast("Note added")
                page.get_by_text("UI audit: isolation confirmed", exact=False).first.wait_for()
                shot("case")
            cases(page)

            @step("SOC log and system: render and open every system sheet")
            def log_system(page):
                go("soc", "log")
                page.get_by_text("Everything Odyssey did").first.wait_for()
                go("soc", "system")
                page.get_by_text("Vital signs").first.wait_for()
                for title in ("AI jobs, timed and checked", "Typical API response", "Audit-trail events", "Last full rebuild"):
                    page.get_by_role("button").filter(has_text=title).click()
                    page.locator("aside").first.wait_for()
                    page.keyboard.press("Escape")
                    page.locator("aside").first.wait_for(state="detached")
            log_system(page)

            # ---------------------------------------------------------------- Intel
            @step("Intel: overview sheets, threats tiles, risk plan")
            def intel(page):
                go("intel", "overview")
                page.get_by_role("button", name="See all").first.click()
                page.locator("aside table").wait_for()
                page.keyboard.press("Escape")
                go("intel", "threats")
                for cta in ("See the grid", "See campaigns", "See advisories", "See sources"):
                    page.get_by_role("button").filter(has_text=cta).click()
                    page.locator("aside").first.wait_for()
                    page.keyboard.press("Escape")
                    page.locator("aside").first.wait_for(state="detached")
                go("intel", "risk")
                page.get_by_text("Upgrade", exact=False).first.wait_for()
                shot("intel-risk")
            intel(page)

            @step("Intel advisories: inbox, how it was read, paste and analyse")
            def advisories(page):
                go("intel", "advisories")
                page.get_by_text("Who must act").wait_for()
                page.get_by_role("button", name="How Odyssey read it").click()
                page.locator("aside").filter(has_text="Entities").wait_for()
                page.keyboard.press("Escape")
                page.get_by_placeholder("A CERT-In note", exact=False).fill(
                    "Threat actors are exploiting CVE-2024-3400 in Palo Alto Networks PAN-OS GlobalProtect (PAN-OS 10.2, 11.0 "
                    "and 11.1). Attackers used 203.0.113.50 and the domain paloalto-update-check.net. Upgrade to 11.1.2-h3.")
                page.get_by_role("button", name="Analyse").click()
                page.get_by_text("Pasted advisory").wait_for(timeout=120000)
                shot("advisory-pasted")
                return page.locator("main").get_by_text("assets exposed", exact=False).first.inner_text()
            advisories(page)

            # ---------------------------------------------------------------- Organisations
            @step("Organisations: switch org, every tab, open a warning")
            def orgs(page):
                go("orgs")
                page.locator("aside button").nth(3).click()
                page.wait_for_timeout(1500)
                for tab in ("Risk plan", "What outsiders see", "Inbox", "Overview"):
                    page.locator("main").get_by_role("button", name=tab, exact=True).click()
                    page.wait_for_timeout(700)
                page.locator("main button").filter(has_text="CVE-").first.click()
                page.locator("aside").filter(has_text="CVE-").first.wait_for()
                page.mouse.click(30, 500)
                shot("org")
            orgs(page)

            # ---------------------------------------------------------------- Proof
            @step("Proof: every claim card opens its evidence; how it works renders")
            def proof(page):
                go("proof")
                cards = page.locator("main button").filter(has_text="Details")
                n = cards.count()
                for i in range(n):
                    cards.nth(i).click()
                    page.locator("aside").first.wait_for()
                    page.keyboard.press("Escape")
                    page.locator("aside").first.wait_for(state="detached")
                page.get_by_role("button").filter(has_text="Run them now").click()
                page.locator("aside").filter(has_text="Test bench").wait_for()
                page.keyboard.press("Escape")
                go("proof", "how")
                page.get_by_text("From signal to action").wait_for()
                return f"{n + 1} evidence sheets opened"
            proof(page)

            # ---------------------------------------------------------------- Live
            @step("Live: start a drill and watch it detected end to end")
            def drill(page):
                go("live")
                page.get_by_text("The pipeline, right now").wait_for()
                page.get_by_role("button", name="Start").nth(1).click()
                page.get_by_text("Detected", exact=True).first.wait_for(timeout=60000)
                shot("live-drill")
                return page.locator("main").get_by_text("detected in", exact=False).first.inner_text()
            drill(page)

            @step("Footer: links navigate")
            def footer(page):
                page.locator("footer").get_by_role("button", name="Risk plan").click()
                page.get_by_text("The fewest changes", exact=False).wait_for()
            footer(page)
            browser.close()
    finally:
        api.terminate()
    for e in dict.fromkeys(errors):
        RESULTS.append((False, "browser", e))
    width = max(len(n) for _, n, _ in RESULTS)
    for ok, name, detail in RESULTS:
        print(f"{'PASS' if ok else 'FAIL'}  {name.ljust(width)}  {detail}")
    failed = sum(1 for ok, *_ in RESULTS if not ok)
    print(f"\n{len(RESULTS) - failed} passed, {failed} failed · screenshots in {shots}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
