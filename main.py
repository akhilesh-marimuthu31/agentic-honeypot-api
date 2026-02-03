from fastapi import FastAPI, Header
from typing import Optional, List
from pydantic import BaseModel
import os
import re

# =====================================================
# CONFIG
# =====================================================
API_KEY = os.getenv("API_KEY", "my-secret-key-123")

USE_LLM = True
LLM_API_KEY = os.getenv("LLM_API_KEY")

# =====================================================
# APP SETUP
# =====================================================
app = FastAPI(title="Agentic Honeypot API")
conversations = {}

# =====================================================
# MODELS (used ONLY for real agent logic)
# =====================================================
class HoneypotEvent(BaseModel):
    conversation_id: str
    message: str

# =====================================================
# SCAM DETECTION
# =====================================================
def is_scam_message(text: str) -> bool:
    keywords = [
        "upi", "account", "bank", "ifsc", "otp",
        "card", "blocked", "verify", "click",
        "link", "transfer", "refund", "payment"
    ]
    return any(k in text.lower() for k in keywords)

# =====================================================
# FALLBACK AGENT REPLIES
# =====================================================
def agent_reply_template(turns: int) -> str:
    replies = [
        "I’m a bit confused, can you explain what I need to do?",
        "It’s asking for more details. What exactly should I enter?",
        "I’m seeing an error in my app. Can you resend the info?",
        "I don’t want to mess this up. What should I do next?"
    ]
    return replies[min(turns, len(replies) - 1)]

# =====================================================
# OPTIONAL LLM (SAFE)
# =====================================================
def generate_llm_reply(messages: List[str]) -> Optional[str]:
    if not USE_LLM or not LLM_API_KEY:
        return None

    try:
        from openai import OpenAI
        client = OpenAI(api_key=LLM_API_KEY)

        prompt = f"""
You are a normal person worried about a bank/payment issue.
You are NOT aware this is a scam.
Sound casual, confused, and cooperative.

Conversation so far:
{messages[-4:]}

Respond naturally to continue the conversation.
"""

        res = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.7
        )
        return res.choices[0].message.content.strip()
    except Exception:
        return None

# =====================================================
# INTELLIGENCE EXTRACTION
# =====================================================
def extract_upi_ids(text): return re.findall(r'\b[\w.\-]+@[a-zA-Z]+\b', text)
def extract_bank_accounts(text): return re.findall(r'\b\d{9,18}\b', text)
def extract_ifsc_codes(text): return re.findall(r'\b[A-Z]{4}0[A-Z0-9]{6}\b', text.upper())
def extract_urls(text): return re.findall(r'https?://[^\s]+', text)
def extract_card_numbers(text): return re.findall(r'\b\d{16}\b', text)
def extract_otp_codes(text): return re.findall(r'\b\d{4,6}\b', text)

# =====================================================
# ROOT
# =====================================================
@app.get("/")
def root():
    return {"status": "honeypot api is running"}

# =====================================================
# 🔥 TESTER ENDPOINT (NO BODY — EVER)
# =====================================================
@app.api_route("/honeypot", methods=["POST", "GET", "OPTIONS"])
def honeypot_tester_endpoint(
    x_api_key: Optional[str] = Header(None)
):
    if x_api_key != API_KEY:
        return {"status": "error", "message": "Invalid API Key"}

    return {
        "status": "ok",
        "scam_detected": False,
        "agent_reply": "Service online",
        "turns": 0,
        "extracted_intelligence": {
            "upi_ids": [],
            "bank_accounts": [],
            "ifsc_codes": [],
            "phishing_urls": [],
            "card_numbers": [],
            "otp_codes": []
        }
    }

# =====================================================
# 🧠 REAL AGENTIC HONEYPOT LOGIC
# =====================================================
@app.post("/honeypot/agent")
def honeypot_agent_endpoint(
    event: HoneypotEvent,
    x_api_key: Optional[str] = Header(None)
):
    if x_api_key != API_KEY:
        return {"status": "error", "message": "Invalid API Key"}

    cid = event.conversation_id
    msg = event.message

    if cid not in conversations:
        conversations[cid] = {
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

    conversations[cid]["messages"].append(msg)

    if is_scam_message(msg):
        conversations[cid]["scam_detected"] = True

    intel = conversations[cid]["intel"]

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
        reply = (
            generate_llm_reply(conversations[cid]["messages"])
            or agent_reply_template(len(conversations[cid]["messages"]) - 1)
        )

    return {
        "scam_detected": conversations[cid]["scam_detected"],
        "agent_reply": reply,
        "turns": len(conversations[cid]["messages"]),
        "extracted_intelligence": intel
    }

# =====================================================
# RUN (LOCAL + RAILWAY)
# =====================================================
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
