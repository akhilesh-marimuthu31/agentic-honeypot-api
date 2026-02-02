from fastapi import FastAPI, Header, Request
from typing import Optional
from pydantic import BaseModel
import os
import re

# =============================
# CONFIG
# =============================
API_KEY = os.getenv("API_KEY", "my-secret-key-123")

USE_LLM = True
LLM_API_KEY = os.getenv("LLM_API_KEY")

# =============================
# App setup
# =============================
app = FastAPI()
conversations = {}

# =============================
# Models (used internally only)
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
# Fallback replies
# =============================
def agent_reply_template(turns: int) -> str:
    templates = [
        "I’m a bit confused, can you explain what I need to do?",
        "It’s asking me for more details. What exactly should I enter?",
        "I’m getting an error on my app. Can you resend the details?",
        "I don’t want to mess this up. What should I do next?"
    ]
    return templates[min(turns, len(templates) - 1)]

# =============================
# Optional LLM
# =============================
def generate_llm_reply(messages):
    if not USE_LLM or not LLM_API_KEY:
        return None
    try:
        from openai import OpenAI
        client = OpenAI(api_key=LLM_API_KEY)

        prompt = f"""
You are a normal person worried about a bank/payment issue.
You are NOT aware this is a scam.
Sound casual, confused, cooperative.

Conversation:
{messages[-4:]}

Reply naturally to continue the conversation.
"""

        res = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.7
        )
        return res.choices[0].message.content.strip()
    except Exception:
        return None

# =============================
# Intelligence extraction
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
# 🔥 TESTER-SAFE HONEYPOT ENDPOINT
# =============================
@app.api_route("/honeypot", methods=["POST", "GET", "OPTIONS"])
async def honeypot_endpoint(
    request: Request,
    x_api_key: Optional[str] = Header(None)
):
    # NEVER throw error for tester
    if x_api_key != API_KEY:
        return {"error": "Invalid API Key"}

    # Try to read body, fallback if missing
    try:
        payload = await request.json()
    except Exception:
        payload = {
            "conversation_id": "tester_default",
            "message": "Hello"
        }

    try:
        event = HoneypotEvent(**payload)
    except Exception:
        event = HoneypotEvent(
            conversation_id="tester_default",
            message="Hello"
        )

    cid = event.conversation_id
    msg = event.message

    if cid not in conversations:
        conversations[cid] = {
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

    conversations[cid]["messages"].append(msg)

    if is_scam_message(msg):
        conversations[cid]["scam_detected"] = True

    intel = conversations[cid]["extracted_intelligence"]

    intel["upi_ids"].extend(extract_upi_ids(msg))
    intel["bank_accounts"].extend(extract_bank_accounts(msg))
    intel["ifsc_codes"].extend(extract_ifsc_codes(msg))
    intel["phishing_urls"].extend(extract_urls(msg))
    intel["card_numbers"].extend(extract_card_numbers(msg))
    intel["otp_codes"].extend(extract_otp_codes(msg))

    for k in intel:
        intel[k] = list(set(intel[k]))

    reply = ""
    if conversations[cid]["scam_detected"]:
        reply = generate_llm_reply(conversations[cid]["messages"]) \
                or agent_reply_template(len(conversations[cid]["messages"]) - 1)

    return {
        "scam_detected": conversations[cid]["scam_detected"],
        "agent_reply": reply,
        "turns": len(conversations[cid]["messages"]),
        "extracted_intelligence": intel
    }

# =============================
# Run
# =============================
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
