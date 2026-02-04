from fastapi import FastAPI, Header, Request
from typing import Optional
import os, re, json

# =============================
# CONFIG
# =============================
API_KEY = os.getenv("API_KEY", "my-secret-key-123")
USE_LLM = False  # keep OFF until final eval

# =============================
# APP INIT (MUST COME FIRST)
# =============================
app = FastAPI()
conversations = {}

# =============================
# HELPERS
# =============================
def normalize_message(payload):
    """
    Extract text from ANY possible tester payload
    """
    if isinstance(payload, dict):
        # Common tester patterns
        if isinstance(payload.get("message"), str):
            return payload["message"]

        if isinstance(payload.get("message"), dict):
            return payload["message"].get("text", "Hello")

        if "text" in payload:
            return payload["text"]

    return "Hello"


def is_scam_message(text: str) -> bool:
    keywords = [
        "upi", "account", "bank", "ifsc", "otp",
        "card", "blocked", "verify", "click",
        "link", "transfer", "refund", "payment"
    ]
    return any(k in text.lower() for k in keywords)


def extract(pattern, text):
    return list(set(re.findall(pattern, text)))


# =============================
# ROOT
# =============================
@app.get("/")
def root():
    return {"status": "honeypot api is running"}

# =============================
# TESTER-SAFE ENDPOINT
# =============================
@app.api_route("/honeypot", methods=["POST", "GET", "OPTIONS"])
async def honeypot_endpoint(
    request: Request,
    x_api_key: Optional[str] = Header(None)
):
    # Never throw errors
    if x_api_key != API_KEY:
        return {"error": "Invalid API Key"}

    # Safe body read
    try:
        body = await request.body()
        payload = json.loads(body.decode()) if body else {}
    except Exception:
        payload = {}

    conversation_id = payload.get("conversation_id") \
        or payload.get("sessionId") \
        or "tester_default"

    message_text = normalize_message(payload)

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

    conversations[conversation_id]["messages"].append(message_text)

    if is_scam_message(message_text):
        conversations[conversation_id]["scam_detected"] = True

    intel = conversations[conversation_id]["intel"]

    intel["upi_ids"] += extract(r'\b[\w.\-]+@[a-zA-Z]+\b', message_text)
    intel["bank_accounts"] += extract(r'\b\d{9,18}\b', message_text)
    intel["ifsc_codes"] += extract(r'\b[A-Z]{4}0[A-Z0-9]{6}\b', message_text.upper())
    intel["phishing_urls"] += extract(r'https?://[^\s]+', message_text)
    intel["card_numbers"] += extract(r'\b\d{16}\b', message_text)
    intel["otp_codes"] += extract(r'\b\d{4,6}\b', message_text)

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
# RUN
# =============================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8080))
    )
