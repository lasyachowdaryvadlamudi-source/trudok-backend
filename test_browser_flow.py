import asyncio
import os
import sys
from playwright.async_api import async_playwright

async def run():
    print("=====================================================")
    print("TRUDOK AUTOMATED HEADLESS BROWSER USER FLOW TEST")
    print("=====================================================")

    # Create sample test passport image
    from PIL import Image
    test_img_path = os.path.abspath("sample_test_passport.jpg")
    img = Image.new("RGB", (600, 400), color=(240, 240, 240))
    img.save(test_img_path, format="JPEG")
    print(f"Created sample document image: {test_img_path}")

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            executable_path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            headless=True
        )
        context = await browser.new_context(viewport={"width": 1280, "height": 800})
        
        # Pre-seed officer login state so app does not redirect to /onboarding
        await context.add_init_script("""
            localStorage.setItem('trudok_officer_profile', JSON.stringify({
                name: 'Inspector V. Sharma',
                badgeId: 'SSB-OFFICER-01',
                checkpoint: 'Raxaul Border Post #04',
                completedOnboarding: true,
                completedSetup: true
            }));
        """)

        page = await context.new_page()

        # Track network calls
        api_requests = []
        api_responses = []

        page.on("request", lambda req: (
            api_requests.append(req.url),
            print(f"-> [Network Request] {req.method} {req.url}")
        ) if "trudok-backend" in req.url else None)

        page.on("response", lambda res: (
            api_responses.append({
                "url": res.url,
                "status": res.status,
                "ok": res.ok
            }),
            print(f"<- [Network Response] {res.status} {res.url}")
        ) if "trudok-backend" in res.url else None)

        page.on("console", lambda msg: print(f"Browser Console [{msg.type}]: {msg.text}") if "trudok" in msg.text.lower() or "error" in msg.type.lower() else None)

        print("\n1. Navigating to https://verilens-nu.vercel.app/scan ...")
        await page.goto("https://verilens-nu.vercel.app/scan", wait_until="networkidle")
        await page.wait_for_timeout(2000)

        title = await page.title()
        print(f"Page loaded successfully: {page.url} | Title: {title}")

        # Select 'National ID' document type button
        print("\n2. Selecting 'National ID' document card...")
        nid_btn = page.locator('button:has-text("National ID")')
        await nid_btn.click()
        await page.wait_for_timeout(1000)

        # Upload the test file to the hidden file picker
        test_img_path = os.path.abspath("test_aadhaar_sample.png")
        print(f"\n3. Uploading test Aadhaar image ({test_img_path}) to #scanner-file-picker...")
        file_input = page.locator('#scanner-file-picker')
        await file_input.wait_for(state="attached", timeout=10000)
        await file_input.set_input_files(test_img_path)
        await page.wait_for_timeout(1500)

        # Look for submit / analyze button
        print("\n4. Submitting document for analysis...")
        analyze_btn = page.locator('button:has-text("Run Forensic Screening")')
        await analyze_btn.wait_for(state="visible", timeout=10000)
        btn_text = await analyze_btn.text_content()
        print(f"Found and clicking action button: '{btn_text.strip()}'")
        await analyze_btn.click()

        print("\n5. Waiting for screening analysis completion and transition to /analysis/:id...")
        # Wait up to 35 seconds for analysis page
        try:
            await page.wait_for_url(lambda u: "/analysis/" in u, timeout=35000)
            print(f"Successfully transitioned to analysis page: {page.url}")
        except Exception as e:
            print(f"URL transition wait note: {e}. Current URL: {page.url}")

        await page.wait_for_timeout(4000)

        # Take screenshot of the result
        screenshot_path = r"C:\Users\vadla\.gemini\antigravity\brain\4ac1911d-3e7c-47aa-a9c0-1e5d0c2bed4c\e2e_live_test_screenshot.png"
        await page.screenshot(path=screenshot_path, full_page=True)
        print(f"Captured full-page screenshot: {screenshot_path}")

        # Inspect page content
        body_text = await page.inner_text("body")

        has_fallback_banner = (
            "Backend unavailable" in body_text 
            or "Simulated Fallback Mode" in body_text 
            or "client-side fallback" in body_text.lower()
            or "screening server unreachable" in body_text.lower()
        )

        has_verdict = (
            "Verdict" in body_text 
            or "Risk Score" in body_text 
            or "Verified" in body_text 
            or "Flagged" in body_text
        )

        has_extracted_name = "RAJESH KUMAR SHARMA" in body_text.upper()
        has_extracted_number = "4521 8892 1039" in body_text or "452188921039" in body_text

        print("\n=====================================================")
        print("HEADLESS BROWSER TEST RESULTS:")
        print("=====================================================")
        print(f"Extracted Name ('RAJESH KUMAR SHARMA') Visible in UI: {has_extracted_name}")
        print(f"Extracted Number ('4521 8892 1039') Visible in UI: {has_extracted_number}")

        print("\n=====================================================")
        print("HEADLESS BROWSER TEST RESULTS:")
        print("=====================================================")
        print("Backend API Requests Triggered:", len(api_requests))
        for r in api_requests:
            print(f"  -> Request URL: {r}")
        print("Backend API Responses Received:", len(api_responses))
        for resp in api_responses:
            print(f"  -> Response: {resp['status']} | {resp['url']}")

        print(f"\nAnalysis Page URL: {page.url}")
        print(f"Fallback/Unavailable Banner Detected: {has_fallback_banner}")
        print(f"Real Verdict & Analysis Data Visible: {has_verdict}")

        if not has_fallback_banner and len(api_responses) > 0 and all(r['ok'] for r in api_responses):
            print("\n>>> OVERALL RESULT: FULLY CONNECTED & WORKING END-TO-END! <<<")
        else:
            print(f"\n>>> OVERALL RESULT: {'CONNECTED' if not has_fallback_banner else 'FALLBACK DETECTED'} <<<")

        await browser.close()

if __name__ == '__main__':
    asyncio.run(run())
