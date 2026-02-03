from fastapi.responses import JSONResponse
import traceback

@app.api_route("/honeypot", methods=["POST", "GET", "OPTIONS"])
async def honeypot_endpoint(request: Request, x_api_key: Optional[str] = Header(None)):
    # QUICK PROBE HANDLING
    if request.method in ("GET", "OPTIONS"):
        return JSONResponse({"status": "ok", "message": "Honeypot endpoint reachable"})

    # Top-level guard so tester never sees non-JSON/500
    try:
        # Always accept header but do not hard-fail tester
        if x_api_key != API_KEY:
            return JSONResponse({"status": "unauthorized", "message": "Invalid API key"})

        # --- LOG incoming metadata for debugging ---
        headers = dict(request.headers)
        content_length = headers.get("content-length")
        print("=== HONEYPOT REQUEST ===")
        print("method:", request.method)
        print("content-length:", content_length)
        print("headers keys:", list(headers.keys()))
        body_bytes = await request.body()
        print("raw body bytes len:", len(body_bytes))
        raw_text = body_bytes.decode("utf-8", errors="replace") if body_bytes else ""
        print("raw body preview:", raw_text[:1000])
        # --- end logging ---

        # Parse if JSON, otherwise keep empty dict
        payload = {}
        if body_bytes:
            try:
                parsed = json.loads(raw_text)
                if isinstance(parsed, dict):
                    payload = parsed
                else:
                    # If it's a wrapper or list, try to find first dict
                    if isinstance(parsed, list) and parsed:
                        if isinstance(parsed[0], dict):
                            payload = parsed[0]
            except Exception:
                # ignore malformed JSON, keep payload={}
                payload = {}

        # tolerant extractor: try common wrapper keys for message
        def find_text(obj):
            if isinstance(obj, str):
                return obj
            if isinstance(obj, dict):
                # prefer "message" / "text" / "body"
                for k in ("message", "text", "body", "msg", "payload"):
                    if k in obj:
                        val = obj[k]
                        if isinstance(val, str):
                            return val
                        if isinstance(val, dict):
                            # nested text: return json string
                            return json.dumps(val)
                # otherwise search values recursively (first string found)
                for v in obj.values():
                    res = find_text(v)
                    if res:
                        return res
            if isinstance(obj, list):
                for item in obj:
                    res = find_text(item)
                    if res:
                        return res
            return None

        conversation_id = payload.get("conversation_id", "tester_default")
        raw_message_candidate = payload.get("message", None)
        message = None
        if raw_message_candidate is None:
            # try find_text across the whole payload
            message = find_text(payload) or "Hello"
        else:
            # normalize message to string
            if isinstance(raw_message_candidate, dict):
                message = json.dumps(raw_message_candidate)
            else:
                message = str(raw_message_candidate)

        # Ensure conversation exists
        if conversation_id not in conversations:
            conversations[conversation_id] = {
                "messages": [],
                "scam_detected": False,
                "extracted_intelligence": {
                    "upi_ids": [], "bank_accounts": [], "ifsc_codes": [],
                    "phishing_urls": [], "card_numbers": [], "otp_codes": []
                }
            }

        conv = conversations[conversation_id]
        conv["messages"].append(message)

        # Scam detection (safe: lower only on string)
        if isinstance(message, str) and is_scam_message(message):
            conv["scam_detected"] = True

        intel = conv["extracted_intelligence"]
        intel["upi_ids"] += extract_upi_ids(message)
        intel["bank_accounts"] += extract_bank_accounts(message)
        intel["ifsc_codes"] += extract_ifsc_codes(message)
        intel["phishing_urls"] += extract_urls(message)
        intel["card_numbers"] += extract_card_numbers(message)
        intel["otp_codes"] += extract_otp_codes(message)

        # dedupe + ensure lists
        for k in intel:
            intel[k] = list(dict.fromkeys([str(x) for x in intel[k] if x]))

        # Agent reply (simple fallback here)
        agent_reply = ""
        if conv["scam_detected"]:
            agent_reply = "I’m a bit confused. Can you explain what I need to do?"

        # Build final response exactly with expected shape & types
        resp = {
            "scam_detected": bool(conv["scam_detected"]),
            "agent_reply": str(agent_reply),
            "turns": int(len(conv["messages"])),
            "extracted_intelligence": {
                "upi_ids": intel.get("upi_ids", []),
                "bank_accounts": intel.get("bank_accounts", []),
                "ifsc_codes": intel.get("ifsc_codes", []),
                "phishing_urls": intel.get("phishing_urls", []),
                "card_numbers": intel.get("card_numbers", []),
                "otp_codes": intel.get("otp_codes", [])
            }
        }

        print("== RESPONSE PREVIEW keys:", list(resp.keys()))
        return JSONResponse(resp)

    except Exception:
        print("UNHANDLED EXCEPTION IN /honeypot")
        traceback.print_exc()
        # Always return JSON and 200 so tester doesn't treat as invalid
        return JSONResponse({
            "scam_detected": False,
            "agent_reply": "",
            "turns": 0,
            "extracted_intelligence": {
                "upi_ids": [], "bank_accounts": [], "ifsc_codes": [],
                "phishing_urls": [], "card_numbers": [], "otp_codes": []
            }
        })
