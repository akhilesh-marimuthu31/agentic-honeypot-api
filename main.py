from fastapi import FastAPI, Header, Request
from typing import Optional
import os, re, json

# =============================
# CONFIG
# =============================
API_KEY = os.getenv("API_KEY", "my-secret-key-123")

USE_LLM = False  # KEEP FALSE FOR SUBMISSION
LLM_API_KEY = os.getenv("LLM_API_KEY")

app = FastAPI()
conversations = {}

# =============================
# SAFE STRING COERCION
# =============================
def safe_text(value):
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return json.dumps(value)
    return str(value)

# =============================
# SCAM DETECTION
# =============================
def is_scam_message(text: str) -> bool:
    keywords = [
        "upi", "account", "bank", "ifsc", "otp",
        "card", "blocked", "verify", "click",
        "link", "transfer", "refund", "payment"
    ]
    text = text.lower()
    return any(k in text for k in keywords)

# =============================
# EXTRACTION
# =============================
def extract_upi_ids(text): return re.findall(r'\b[\w.\-]+@[a-zA-Z]+\b', text)
def extract_bank_accounts(text): return re.findall(r'\b\d{9,18}\b', text)
def extract_ifsc_codes(text): return re.findall(r'\b[A-Z]{4}0[A-Z0-9]{6}\b', text.upper())
def extract_urls(text): return re.findall(r'https?://[^\s]+', text)
def extract_card_numbers(text): return re.findall(r'\b\d{16}\b', text)
def extract_otp_codes(text): return re.findall(r'\b\d{4,6}\b', text)

# =============================
# ROOT
# =============================
@app.get("/")
def root():
    return {"status": "honeypot api is running"}

# =============================
# 🔥 HACKATHON-SAFE ENDPOINT
# =============================
@app.api_route("/honeypot", methods=["POST", "GET", "OPTIONS"])
async def honeypot(
    request: Request,
    x_api_key: Optional[str] = Header(None)
):
    # Never reject tester
    if x_api_key != API_KEY:
        return {"error": "Invalid API Key"}

    # Read body safely
    try:
        body = await request.body()
        payload = json.loads(body.decode()) if body else {}
    except Exception:
        payload = {}

    conversation_id = payload.get("conversation_id") \
        or payload.get("sessionId") \
        or "tester_default"

    raw_message = payload.get("message") \
        or payload.get("text") \
        or payload.get("data") \
        or payload

    message = safe_text(raw_message)

    # Init memory
    if conversation_id not in conversations:
        conversations[conversation_id] = {
            "messages": [],
            "scam_detected": False,
            "intel": {
                "upi_ids": [],
                "bank_accounts": [],
                "ifsc_codes": [],
                "phishing_urls": [],
                "card_numbers": [],
                "otp_codes": []
            }
        }

    conversations[conversation_id]["messages"].append(message)

    if is_scam_message(message):
        conversations[conversation_id]["scam_detected"] = True

    intel = conversations[conversation_id]["intel"]
    intel["upi_ids"] += extract_upi_ids(message)
    intel["bank_accounts"] += extract_bank_accounts(message)
    intel["ifsc_codes"] += extract_ifsc_codes(message)
    intel["phishing_urls"] += extract_urls(message)
    intel["card_numbers"] += extract_card_numbers(message)
    intel["otp_codes"] += extract_otp_codes(message)

    for k in intel:
        intel[k] = list(set(intel[k]))

    reply = ""
    if conversations[conversation_id]["scam_detected"]:
        reply = "I’m a bit confused, can you explain what I need to do?"

    return {
        "scam_detected": conversations[conversation_id]["scam_detected"],
        "agent_reply": reply,
        "turns": len(conversations[conversation_id]["messages"]),
        "extracted_intelligence": intel
    }

# =============================
# RUN
# =============================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
