from fastapi import FastAPI, Header, Request
from typing import Optional
import os, re, json
app = FastAPI()
API_KEY = os.getenv("API_KEY", "my-secret-key-123")
USE_LLM = False  # KEEP FALSE for submission stability


conversations = {}

# ---------------------------
# Utils
# ---------------------------
def safe_text(x):
    if isinstance(x, str):
        return x
    if isinstance(x, dict):
        return x.get("text", "")
    return ""

def is_scam_message(text: str) -> bool:
    keywords = [
        "upi", "account", "bank", "ifsc", "otp",
        "card", "blocked", "verify", "click",
        "link", "transfer", "refund", "payment"
    ]
    text = text.lower()
    return any(k in text for k in keywords)

def extract(pattern, text):
    return re.findall(pattern, text)

# ---------------------------
# Routes
# ---------------------------
@app.get("/")
def root():
    return {"status": "honeypot api is running"}

@app.api_route("/honeypot", methods=["POST", "GET", "OPTIONS"])
async def honeypot(request: Request, x_api_key: Optional[str] = Header(None)):
    if x_api_key != API_KEY:
        return {"error": "Invalid API Key"}

    # SAFE BODY READ
    try:
        raw = await request.body()
        payload = json.loads(raw.decode()) if raw else {}
    except:
        payload = {}

    conversation_id = payload.get("conversation_id") or payload.get("sessionId") or "tester"
    raw_message = payload.get("message", "Hello")

    # Normalize message safely
    if isinstance(raw_message, dict):
        message = raw_message.get("text", "")
    else:
        message = str(raw_message)


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
    intel["upi_ids"] += extract(r'[\w.\-]+@[a-zA-Z]+', message)
    intel["bank_accounts"] += extract(r'\b\d{9,18}\b', message)
    intel["ifsc_codes"] += extract(r'\b[A-Z]{4}0[A-Z0-9]{6}\b', message.upper())
    intel["phishing_urls"] += extract(r'https?://[^\s]+', message)
    intel["card_numbers"] += extract(r'\b\d{16}\b', message)
    intel["otp_codes"] += extract(r'\b\d{4,6}\b', message)

    for k in intel:
        intel[k] = list(set(intel[k]))

    reply = ""
    if conversations[conversation_id]["scam_detected"]:
        reply = "I’m confused, can you explain what I need to do next?"

    return {
        "scam_detected": conversations[conversation_id]["scam_detected"],
        "agent_reply": reply,
        "turns": len(conversations[conversation_id]["messages"]),
        "extracted_intelligence": intel
    }
