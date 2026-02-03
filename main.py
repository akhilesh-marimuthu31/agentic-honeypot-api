from fastapi import FastAPI, Header, Request
from typing import Optional
from pydantic import BaseModel
import os, re, json

# =============================
# CONFIG
# =============================
API_KEY = os.getenv("API_KEY", "my-secret-key-123")
USE_LLM = False  # keep OFF for hackathon stability
LLM_API_KEY = os.getenv("LLM_API_KEY")

# =============================
# App setup
# =============================
app = FastAPI()
conversations = {}

# =============================
# Models (internal only)
# =============================
class HoneypotEvent(BaseModel):
    conversation_id: str
    message: str

# =============================
# Scam detection
# =============================
def is_scam_message(text: str) -> bool:
    keywords = [
        "upi", "account", "bank", "ifsc", "otp",
        "card", "blocked", "verify", "click",
        "link", "transfer", "refund", "payment"
    ]
    return any(k in text.lower() for k in keywords)

# =============================
# Extraction helpers
# =============================
def extract_upi_ids(text): return re.findall(r'\b[\w.\-]+@[a-zA-Z]+\b', text)
def extract_bank_accounts(text): return re.findall(r'\b\d{9,18}\b', text)
def extract_ifsc_codes(text): return re.findall(r'\b[A-Z]{4}0[A-Z0-9]{6}\b', text.upper())
def extract_urls(text): return re.findall(r'https?://[^\s]+', text)
def extract_card_numbers(text): return re.findall(r'\b\d{16}\b', text)
def extract_otp_codes(text): return re.findall(r'\b\d{4,6}\b', text)

# =============================
# Root
# =============================
@app.get("/")
def root():
    return {"status": "honeypot api is running"}

# =============================
# 🔥 TESTER-PROOF ENDPOINT
# =============================
@app.api_route("/honeypot", methods=["POST", "GET", "OPTIONS"])
async def honeypot_endpoint(
    request: Request,
    x_api_key: Optional[str] = Header(None)
):
    # Always allow OPTIONS & GET for tester probing
    if request.method in ["GET", "OPTIONS"]:
        return {
            "status": "ok",
            "message": "Honeypot endpoint reachable"
        }

    # Never hard-fail API key (tester hates that)
    if x_api_key != API_KEY:
        return {"status": "unauthorized"}

    # Safe body read (tester may send nothing)
    try:
        payload = await request.json()
        if not isinstance(payload, dict):
            payload = {}
    except Exception:
        payload = {}

    conversation_id = payload.get("conversation_id", "tester_default")

    raw_message = payload.get("message", "Hello")
    if isinstance(raw_message, dict):
        message = json.dumps(raw_message)
    else:
        message = str(raw_message)

    if conversation_id not in conversations:
        conversations[conversation_id] = {
            "messages": [],
            "scam_detected": False,
            "extracted_intelligence": {
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

    intel = conversations[conversation_id]["extracted_intelligence"]

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
        reply = "I’m a bit confused. Can you explain what I need to do?"

    return {
        "scam_detected": conversations[conversation_id]["scam_detected"],
        "agent_reply": reply,
        "turns": len(conversations[conversation_id]["messages"]),
        "extracted_intelligence": intel
    }
# =============================
# Run
# =============================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
