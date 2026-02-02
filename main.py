from fastapi import FastAPI, Header, HTTPException, Body
from typing import Optional
from pydantic import BaseModel
import os
import re

# =============================
# CONFIG
# =============================
API_KEY = "my-secret-key-123"

USE_LLM = True  # Toggle anytime
LLM_API_KEY = os.getenv("LLM_API_KEY")  # Set in Railway if using LLM


# =============================
# Request schema
# =============================
class HoneypotEvent(BaseModel):
    conversation_id: str
    message: str


# =============================
# App setup
# =============================
app = FastAPI()
conversations = {}


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
# Template fallback replies
# =============================
def agent_reply_template(turns: int) -> str:
    templates = [
        "I’m a bit confused, can you explain what I need to do?",
        "It’s asking me for more details. What exactly should I enter?",
        "I’m getting an error on my app. Can you check and resend the details?",
        "I don’t want to mess this up. What should I do next?"
    ]
    return templates[min(turns, len(templates) - 1)]


# =============================
# LLM reply generator (SAFE)
# =============================
def generate_llm_reply(conversation_messages: list) -> Optional[str]:
    if not USE_LLM or not LLM_API_KEY:
        return None

    try:
        from openai import OpenAI
        client = OpenAI(api_key=LLM_API_KEY)

        prompt = f"""
You are a normal person who received a message related to their
bank account, card, OTP, payment, verification, or account security.

You are NOT aware this is a scam.
You are slightly confused or worried, but cooperative.
You must sound casual, human, and realistic.

Do NOT sound like a bot, investigator, or security system.
Do NOT accuse the other person.

Conversation so far:
{conversation_messages[-4:]}

Your goal:
Respond naturally and ask for clarification or next steps
to keep the conversation going.
"""

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.7,
        )

        return response.choices[0].message.content.strip()

    except Exception:
        return None


# =============================
# Intelligence extraction
# =============================
def extract_upi_ids(text: str):
    return re.findall(r'\b[\w.\-]{2,}@[a-zA-Z]{2,}\b', text)

def extract_bank_accounts(text: str):
    return re.findall(r'\b\d{9,18}\b', text)

def extract_ifsc_codes(text: str):
    return re.findall(r'\b[A-Z]{4}0[A-Z0-9]{6}\b', text.upper())

def extract_urls(text: str):
    return re.findall(r'https?://[^\s]+', text)

def extract_card_numbers(text: str):
    return re.findall(r'\b\d{16}\b', text)

def extract_otp_codes(text: str):
    return re.findall(r'\b\d{4,6}\b', text)


# =============================
# Health check
# =============================
@app.get("/")
def root():
    return {"status": "honeypot api is running"}


# =============================
# Main honeypot endpoint
# =============================
@app.post("/honeypot")
def honeypot_endpoint(
    payload: Optional[dict] = Body(None),
    x_api_key: Optional[str] = Header(None)
):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    if not payload:
        payload = {
            "conversation_id": "tester_default",
            "message": "Hello"
        }

# Convert payload to model manually
    try:
        event = HoneypotEvent(**payload)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid payload format")
    cid = event.conversation_id
    msg = event.message

    # Initialize conversation memory
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

    # Scam detection
    if is_scam_message(msg):
        conversations[cid]["scam_detected"] = True

    intel = conversations[cid]["extracted_intelligence"]

    # Extraction
    intel["upi_ids"].extend(extract_upi_ids(msg))
    intel["bank_accounts"].extend(extract_bank_accounts(msg))
    intel["ifsc_codes"].extend(extract_ifsc_codes(msg))
    intel["phishing_urls"].extend(extract_urls(msg))
    intel["card_numbers"].extend(extract_card_numbers(msg))
    intel["otp_codes"].extend(extract_otp_codes(msg))

    # Deduplicate
    for k in intel:
        intel[k] = list(set(intel[k]))

    # Agent reply
    agent_reply = ""
    if conversations[cid]["scam_detected"]:
        llm_reply = generate_llm_reply(conversations[cid]["messages"])
        if llm_reply:
            agent_reply = llm_reply
        else:
            turns = len(conversations[cid]["messages"]) - 1
            agent_reply = agent_reply_template(turns)

    # Final structured response
    return {
        "scam_detected": conversations[cid]["scam_detected"],
        "agent_reply": agent_reply,
        "turns": len(conversations[cid]["messages"]),
        "extracted_intelligence": intel
    }


# =============================
# Run (Railway + local)
# =============================
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
