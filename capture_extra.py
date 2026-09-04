import asyncio
import os
from playwright.async_api import async_playwright

output_dir = r"C:\Users\vadla\.gemini\antigravity\brain\4ac1911d-3e7c-47aa-a9c0-1e5d0c2bed4c\screenshots"
os.makedirs(output_dir, exist_ok=True)

async def capture_extra():
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            executable_path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            headless=True
        )

        # 1. Capture Officer Setup Screen
        ctx_setup = await browser.new_context(viewport={"width": 1440, "height": 900}, device_scale_factor=1.5)
        await ctx_setup.add_init_script("""
            localStorage.setItem('trudok_officer_profile', JSON.stringify({
                name: '',
                badgeId: '',
                checkpoint: '',
                completedOnboarding: true,
                completedSetup: false
            }));
        """)
        page_setup = await ctx_setup.new_page()
        await page_setup.goto("https://verilens-nu.vercel.app/setup", wait_until="networkidle")
        await page_setup.wait_for_timeout(2000)
        setup_path = os.path.join(output_dir, "08_officer_setup.png")
        await page_setup.screenshot(path=setup_path, full_page=True)
        print("Captured Setup:", setup_path)
        await ctx_setup.close()

        # 2. Capture Analysis Dossier Page
        ctx_analysis = await browser.new_context(viewport={"width": 1440, "height": 900}, device_scale_factor=1.5)
        await ctx_analysis.add_init_script("""
            localStorage.setItem('trudok_officer_profile', JSON.stringify({
                name: 'Inspector Vikram Sharma',
                badgeId: 'SSB-OFFICER-77',
                checkpoint: 'Raxaul Border Corridor #04',
                completedOnboarding: true,
                completedSetup: true
            }));
        """)
        page_analysis = await ctx_analysis.new_page()
        # Direct URL to existing scan record
        await page_analysis.goto("https://verilens-nu.vercel.app/analysis/DOC-BF87", wait_until="networkidle")
        await page_analysis.wait_for_timeout(2500)
        analysis_path = os.path.join(output_dir, "03_analysis_dossier.png")
        await page_analysis.screenshot(path=analysis_path, full_page=True)
        print("Captured Analysis Dossier:", analysis_path)
        await ctx_analysis.close()

        await browser.close()

if __name__ == '__main__':
    asyncio.run(capture_extra())
