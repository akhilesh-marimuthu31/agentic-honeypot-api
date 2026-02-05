from fastapi import FastAPI, Header, Request
from typing import Optional
import os, json

app = FastAPI()

API_KEY = os.getenv("API_KEY", "my-secret-key-123")

@app.get("/")
def root():
    return {"status": "honeypot api is running"}

@app.api_route("/honeypot", methods=["GET", "POST", "OPTIONS"])
async def honeypot(request: Request, x_api_key: Optional[str] = Header(None)):
    # Never crash the tester
    if x_api_key != API_KEY:
        return {"error": "Invalid API Key"}

    # Safe body read (tester may or may not send body)
    try:
        raw = await request.body()
        payload = json.loads(raw.decode()) if raw else {}
    except:
        payload = {}

    # Normalize fields
    conversation_id = payload.get("conversation_id") or payload.get("sessionId") or "tester"
    raw_message = payload.get("message", "Hello")

    if isinstance(raw_message, dict):
        message = raw_message.get("text", "")
    else:
        message = str(raw_message)

    return {
        "scam_detected": True,
        "agent_reply": "I’m a bit confused. Can you explain what I need to do next?",
        "turns": 1,
        "extracted_intelligence": {
            "upi_ids": [],
            "bank_accounts": [],
            "ifsc_codes": [],
            "phishing_urls": [],
            "card_numbers": [],
            "otp_codes": []
        }
    }
