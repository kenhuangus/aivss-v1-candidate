#!/usr/bin/env python3
"""Automated QA test script for AIVSS 1.0 slides deck using Playwright."""
import asyncio
import os
import sys
from playwright.async_api import async_playwright

SLIDES_PATH = r"C:\Users\kenhu\aivss-v1-candidate\slides.html"
SCREENSHOTS_DIR = r"C:\Users\kenhu\aivss-v1-candidate\docs\qa_screenshots"
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

async def run_qa():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        # 1920x1080 desktop presentation resolution
        page = await browser.new_page(viewport={"width": 1920, "height": 1080})
        
        file_url = f"file:///{SLIDES_PATH.replace(os.sep, '/')}"
        print(f"Loading {file_url}...")
        
        errors = []
        page.on("console", lambda msg: errors.append(f"Console {msg.type}: {msg.text}") if msg.type == "error" else None)
        page.on("pageerror", lambda err: errors.append(f"Page error: {err}"))

        await page.goto(file_url, wait_until="networkidle")
        await asyncio.sleep(0.5)

        total_slides = await page.evaluate("slidesData.length")
        print(f"Detected {total_slides} slides.")

        overflow_issues = []

        for i in range(1, total_slides + 1):
            await page.evaluate(f"renderSlide({i - 1})")
            await asyncio.sleep(0.15)

            # Measure body clientHeight vs scrollHeight
            metrics = await page.evaluate("""() => {
                const body = document.getElementById('slide-body');
                const wrap = document.getElementById('slide-content-wrap') || body;
                const scale = getComputedStyle(body).getPropertyValue('--fit-scale').trim();
                return {
                    clientHeight: body.clientHeight,
                    scrollHeight: body.scrollHeight,
                    wrapHeight: wrap.offsetHeight,
                    scale: scale,
                    title: document.getElementById('slide-title').innerText
                };
            }""")

            is_overflow = metrics["scrollHeight"] > metrics["clientHeight"] + 4
            status = "OVERFLOW!" if is_overflow else "OK"
            if is_overflow:
                overflow_issues.append((i, metrics))

            print(f"Slide {i:02d} [{status}]: scale={metrics['scale']} | clientH={metrics['clientHeight']} scrollH={metrics['scrollHeight']} | {metrics['title'][:40]}")

            # Take screenshot of selected representative slides
            if i in [1, 2, 3, 4, 9, 14, 15, 17, 18, 19, 20, 23]:
                shot_path = os.path.join(SCREENSHOTS_DIR, f"slide_{i:02d}.png")
                await page.screenshot(path=shot_path)
                print(f"  -> Saved screenshot: {shot_path}")

        await browser.close()

        print("\n--- QA SUMMARY ---")
        if errors:
            print(f"JavaScript Errors ({len(errors)}):")
            for e in errors:
                print("  ", e)
        else:
            print("JavaScript Errors: 0")

        if overflow_issues:
            print(f"Overflow Issues ({len(overflow_issues)}):")
            for num, m in overflow_issues:
                print(f"  Slide {num}: scrollH={m['scrollHeight']} > clientH={m['clientHeight']}")
        else:
            print("Vertical Overflows: 0 (PASSED!)")

        if not errors and not overflow_issues:
            print("\nALL 23 SLIDES PASSED QA SUCCESSFULLY!")
            return 0
        else:
            return 1

if __name__ == "__main__":
    code = asyncio.run(run_qa())
    sys.exit(code)
