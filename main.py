from fastapi import FastAPI, File, UploadFile, Form, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.templating import Jinja2Templates
from cryptography.fernet import Fernet
from PIL import Image, ImageDraw, ImageChops, ExifTags
import os
import socket
import ssl
import base64
from datetime import datetime




# --- લેટેસ્ટ અને સેફ Path સેટઅપ ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(TEMPLATE_DIR, exist_ok=True) 

app = FastAPI(title="CyberVault Pro - Production Ready")
templates = Jinja2Templates(directory=TEMPLATE_DIR)




# --- 1. Advanced Image Forensics ---
@app.post("/api/forensics")
async def extract_metadata(file: UploadFile = File(...)):
    file_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_path, "wb") as f:
        f.write(await file.read())
    try:
        img = Image.open(file_path)
        exif_data = {}
        if img._getexif():
            for tag, value in img._getexif().items():
                decoded = ExifTags.TAGS.get(tag, tag)
                if isinstance(value, bytes):
                    value = value.decode('utf-8', errors='ignore')
                exif_data[decoded] = str(value)
        
        return {
            "status": "success",
            "Basic_Info": {
                "Resolution": f"{img.size[0]} x {img.size[1]}",
                "Format": img.format,
                "Color_Mode": img.mode,
            },
            "Detailed_EXIF": exif_data if exif_data else "No Deep EXIF Data Found."
        }
    except Exception as e:
        return {"status": "error", "message": f"Forensic Analysis Failed: {str(e)}"}

# --- 2. SSL Checker ---
@app.post("/api/ssl_check")
async def check_ssl(hostname: str = Form(...)):
    try:
        hostname = hostname.replace("https://", "").replace("http://", "").split("/")[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                valid_from = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
                valid_to = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                days_left = (valid_to - datetime.utcnow()).days
                
                return {
                    "status": "success",
                    "SECURITY_GRADE": "A+" if days_left > 90 else ("B" if days_left > 30 else "F"),
                    "STATUS": "VALID" if days_left > 0 else "EXPIRED",
                    "DOMAIN": hostname,
                    "ISSUER": dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown'),
                    "DAYS_REMAINING": f"{days_left} days",
                    "VALID_TO": valid_to.strftime("%d/%m/%Y")
                }
    except Exception as e:
        return {"status": "error", "message": "Failed: " + str(e)}

# --- 3. File Encrypt/Decrypt ---
def get_key(password: str):
    return base64.urlsafe_b64encode(password.ljust(32, '0').encode()[:32])

@app.post("/api/crypto")
async def file_crypto(file: UploadFile = File(...), password: str = Form(...), action: str = Form(...)):
    file_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_path, "wb") as f:
        f.write(await file.read())
    fernet = Fernet(get_key(password))
    with open(file_path, "rb") as f:
        original_data = f.read()

    prefix = "enc_" if action == "encrypt" else "dec_"
    output_filename = f"{prefix}{file.filename}"
    output_path = os.path.join(UPLOAD_DIR, output_filename)
    
    try:
        processed_data = fernet.encrypt(original_data) if action == "encrypt" else fernet.decrypt(original_data)
        with open(output_path, "wb") as f:
            f.write(processed_data)
      return FileResponse(path=output_path, media_type='application/octet-stream', filename=output_filename)
    except Exception:
        return {"status": "error", "message": "Decryption Failed! Wrong password or corrupted file."}

# --- 4. Digital Watermark ---
@app.post("/api/watermark")
async def add_watermark(image: UploadFile = File(...), text: str = Form(...)):
    img_path = os.path.join(UPLOAD_DIR, image.filename)
    with open(img_path, "wb") as f:
        f.write(await image.read())
    img = Image.open(img_path).convert("RGBA")
    txt = Image.new("RGBA", img.size, (255, 255, 255, 0))
    d = ImageDraw.Draw(txt)
    d.text((20, 20), text, fill=(255, 255, 255, 128)) 
    watermarked = Image.alpha_composite(img, txt).convert("RGB")
    out_filename = f"watermark_{image.filename}"
    watermarked.save(os.path.join(UPLOAD_DIR, out_filename))
    return {"status": "success", "message": "Watermark Applied", "download_link": f"/download/{out_filename}"}


# --.5 Deepfake Detection (ELA Fix) ---
@app.post("/api/deepfake")
async def detect_deepfake(image: UploadFile = File(...)):
    img_path = os.path.join(UPLOAD_DIR, image.filename)
    with open(img_path, "wb") as f:
        f.write(await image.read())
    try:
        original = Image.open(img_path).convert('RGB')
        temp_path = img_path + ".temp.jpg"
        original.save(temp_path, 'JPEG', quality=90)
        
        compressed = Image.open(temp_path)
        ela_img = ImageChops.difference(original, compressed)
        
        extrema = ela_img.getextrema()
        max_diff = max([ex[1] for ex in extrema])
        
        if max_diff < 15:
            analysis = "No significant compression differences found. HIGH probability of being ORIGINAL."
        else:
            analysis = f"Alteration detected! Pixel mismatch score: {max_diff}. The image has likely been PHOTOSHOPPED."
            
        return {"status": "success", "score": max_diff, "analysis": analysis}
    except Exception as e:
        return {"status": "error", "message": "Could not analyze image format."}
@app.get("/", response_class=HTMLResponse)
async def serve_frontend(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

# ==========================================
# 🛑 પોર્ટ ઇશ્યૂ સોલ્વ કરવા માટેનો સુધારો 🛑
# ==========================================
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
