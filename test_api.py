import io
import requests
from PIL import Image, ImageDraw

BASE_URL = "http://127.0.0.1:8000"

def create_sample_passport_image() -> bytes:
    """Creates a sample synthetic passport image in memory for testing."""
    img = Image.new("RGB", (640, 450), color=(245, 241, 232))
    draw = ImageDraw.Draw(img)

    # Document Header
    draw.rectangle([(20, 20), (620, 60)], fill=(11, 37, 69))
    draw.text((30, 30), "REPUBLIC OF ELDORIA PASSPORT", fill=(244, 180, 0))

    # Photo Box
    draw.rectangle([(40, 80), (180, 260)], fill=(30, 30, 30), outline=(244, 180, 0), width=2)

    # Text fields
    draw.text((210, 90), "SURNAME / NOM: KOWALSKI", fill=(0, 0, 0))
    draw.text((210, 120), "GIVEN NAMES: DARIUS VANCE", fill=(0, 0, 0))
    draw.text((210, 150), "PASSPORT NO: EL-84920194", fill=(0, 0, 0))
    draw.text((210, 180), "NATIONALITY: ELDORIA", fill=(0, 0, 0))
    draw.text((210, 210), "DATE OF BIRTH: 14 AUG 1984", fill=(0, 0, 0))
    draw.text((210, 240), "EXPIRY DATE: 22 NOV 2029", fill=(0, 0, 0))

    # MRZ bottom lines
    draw.rectangle([(20, 350), (620, 430)], fill=(10, 10, 10))
    draw.text((30, 360), "P<ELDKOWALSKI<<DARIUS<VANCE<<<<<<<<<<<<<", fill=(46, 147, 60))
    draw.text((30, 390), "EL849201948ELD8408142M2911225<<<<<<<<<<<8", fill=(46, 147, 60))

    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=95)
    return buf.getvalue()

def run_tests():
    print("Testing 1: GET /api/health")
    try:
        r = requests.get(f"{BASE_URL}/api/health", timeout=5)
        print(f"Health Check: Status {r.status_code}, Response: {r.json()}")
        assert r.status_code == 200
    except Exception as e:
        print(f"Health Check Failed: {e}")
        return

    sample_img_bytes = create_sample_passport_image()

    print("\nTesting 2: POST /api/tamper-check (Error Level Analysis)")
    files = {"file": ("passport.jpg", sample_img_bytes, "image/jpeg")}
    r = requests.post(f"{BASE_URL}/api/tamper-check", files=files, timeout=10)
    print(f"Tamper Check: Status {r.status_code}")
    res = r.json()
    print(f"  Tamper Score: {res.get('tamperScore')}")
    print(f"  Heatmap Base64 Length: {len(res.get('heatmapImageBase64', ''))}")
    print(f"  Flagged Regions: {len(res.get('flaggedRegions', []))}")
    assert r.status_code == 200

    print("\nTesting 3: POST /api/extract (OCR)")
    files = {"file": ("passport.jpg", sample_img_bytes, "image/jpeg")}
    r = requests.post(f"{BASE_URL}/api/extract", files=files, timeout=10)
    print(f"OCR Extraction: Status {r.status_code}")
    res = r.json()
    print(f"  Extracted Fields: {res.get('extractedFields')}")
    assert r.status_code == 200

    print("\nTesting 4: POST /api/analyze (Unified Composite Analysis)")
    files = {"file": ("passport.jpg", sample_img_bytes, "image/jpeg")}
    r = requests.post(f"{BASE_URL}/api/analyze", files=files, timeout=10)
    print(f"Full Analyze: Status {r.status_code}")
    res = r.json()
    print(f"  Document ID: {res.get('id')}")
    print(f"  Scan ID: {res.get('scanId')}")
    print(f"  Composite Risk Score: {res.get('riskScore')}")
    print(f"  Verdict: {res.get('verdict')}")
    print(f"  Forensic Findings Count: {len(res.get('forensicFindings', []))}")
    print(f"  Extracted vs Verified Rows: {len(res.get('extractedVsVerified', []))}")
    assert r.status_code == 200

    print("\nAll Backend Module Tests Succeeded with 100% Pass Rate!")

if __name__ == "__main__":
    run_tests()
