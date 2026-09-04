import asyncio
import os
import json
from playwright.async_api import async_playwright
from PIL import Image

async def capture_all():
    print("=====================================================")
    print("CAPTURING TRUDOK HIGH-RESOLUTION UI/UX SCREENSHOTS")
    print("=====================================================")

    output_dir = r"C:\Users\vadla\.gemini\antigravity\brain\4ac1911d-3e7c-47aa-a9c0-1e5d0c2bed4c\screenshots"
    os.makedirs(output_dir, exist_ok=True)

    # Sample passport image
    test_img_path = os.path.abspath("sample_test_passport.jpg")
    img = Image.new("RGB", (600, 400), color=(242, 242, 242))
    img.save(test_img_path, format="JPEG")

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            executable_path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            headless=True
        )

        # 1. Capture Onboarding Screen (Empty state)
        context_onboarding = await browser.new_context(viewport={"width": 1440, "height": 900}, device_scale_factor=1.5)
        page_onboarding = await context_onboarding.new_page()
        await page_onboarding.goto("https://verilens-nu.vercel.app/onboarding", wait_until="networkidle")
        await page_onboarding.wait_for_timeout(1500)
        onboarding_path = os.path.join(output_dir, "07_onboarding.png")
        await page_onboarding.screenshot(path=onboarding_path, full_page=True)
        print(f"[Captured] Onboarding: {onboarding_path}")
        await context_onboarding.close()

        # 2. Main Authenticated Context
        context = await browser.new_context(viewport={"width": 1440, "height": 900}, device_scale_factor=1.5)
        await context.add_init_script("""
            localStorage.setItem('trudok_officer_profile', JSON.stringify({
                name: 'Inspector Vikram Sharma',
                badgeId: 'SSB-OFFICER-77',
                checkpoint: 'Raxaul Border Corridor #04',
                completedOnboarding: true,
                completedSetup: true
            }));
        """)

        page = await context.new_page()

        # Screen A: Dashboard
        print("Navigating to Dashboard...")
        await page.goto("https://verilens-nu.vercel.app/dashboard", wait_until="networkidle")
        await page.wait_for_timeout(2000)
        dash_path = os.path.join(output_dir, "01_dashboard.png")
        await page.screenshot(path=dash_path, full_page=True)
        print(f"[Captured] Dashboard: {dash_path}")

        # Screen B: Scanner
        print("Navigating to Scanner...")
        await page.goto("https://verilens-nu.vercel.app/scan", wait_until="networkidle")
        await page.wait_for_timeout(2000)
        scan_path = os.path.join(output_dir, "02_scanner.png")
        await page.screenshot(path=scan_path, full_page=True)
        print(f"[Captured] Scanner: {scan_path}")

        # Screen C: Perform Scan & Capture Live Analysis Dossier
        print("Uploading document and running analysis...")
        file_input = page.locator('#scanner-file-picker')
        await file_input.wait_for(state="attached", timeout=10000)
        await file_input.set_input_files(test_img_path)
        await page.wait_for_timeout(1500)

        analyze_btn = page.locator('button:has-text("Run Forensic Screening")')
        await analyze_btn.wait_for(state="visible", timeout=10000)
        await analyze_btn.click()

        try:
            await page.wait_for_url(lambda u: "/analysis/" in u, timeout=35000)
            print(f"Reached Analysis page: {page.url}")
            await page.wait_for_timeout(3000)
            analysis_path = os.path.join(output_dir, "03_analysis_dossier.png")
            await page.screenshot(path=analysis_path, full_page=True)
            print(f"[Captured] Analysis Dossier: {analysis_path}")
        except Exception as e:
            print(f"Analysis wait error: {e}")

        # Screen D: Investigation Trail
        print("Navigating to Investigation Trail...")
        await page.goto("https://verilens-nu.vercel.app/investigate", wait_until="networkidle")
        await page.wait_for_timeout(2000)
        
        # Type a search query to show results
        search_input = page.locator('input[type="text"], input[placeholder*="Search"]')
        if await search_input.count() > 0:
            await search_input.first.fill("SCN")
            await page.keyboard.press("Enter")
            await page.wait_for_timeout(1000)

        investigate_path = os.path.join(output_dir, "04_investigation_trail.png")
        await page.screenshot(path=investigate_path, full_page=True)
        print(f"[Captured] Investigation Trail: {investigate_path}")

        # Screen E: Flagged Records
        print("Navigating to Flagged Records...")
        await page.goto("https://verilens-nu.vercel.app/flagged", wait_until="networkidle")
        await page.wait_for_timeout(2000)
        flagged_path = os.path.join(output_dir, "05_flagged_records.png")
        await page.screenshot(path=flagged_path, full_page=True)
        print(f"[Captured] Flagged Records: {flagged_path}")

        # Screen F: Officer Settings / Profile
        print("Navigating to Profile / Settings...")
        await page.goto("https://verilens-nu.vercel.app/profile", wait_until="networkidle")
        await page.wait_for_timeout(2000)
        profile_path = os.path.join(output_dir, "06_officer_profile.png")
        await page.screenshot(path=profile_path, full_page=True)
        print(f"[Captured] Officer Profile: {profile_path}")

        await browser.close()
        print("\nALL UI/UX SCREENSHOTS CAPTURED SUCCESSFULLY!")

if __name__ == '__main__':
    asyncio.run(capture_all())
