import asyncio
from playwright.async_api import async_playwright
import os

async def run():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()
        
        # Capture console logs
        page.on("console", lambda msg: print(f"CONSOLE [{msg.type}]: {msg.text}"))
        page.on("pageerror", lambda err: print(f"PAGE ERROR: {err}"))
        
        # Open local HTML file to test Javascript execution and bypass auth
        file_path = f"file:///{os.path.abspath('templates/index.html').replace(os.sep, '/')}"
        print(f"Opening {file_path}")
        await page.goto(file_path)
        
        # Wait a few seconds
        await asyncio.sleep(5)
        print("Done.")
        await browser.close()

if __name__ == "__main__":
    asyncio.run(run())
