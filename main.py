from fastapi import FastAPI, Header, HTTPException
from typing import Optional

app = FastAPI()

API_KEY = "my-secret-key-123"

@app.get("/")
def root():
    return {"status": "honeypot api is running"}

@app.post("/honeypot")
def honeypot_endpoint(
    x_api_key: Optional[str] = Header(None)
):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    return {
        "message": "Honeypot endpoint reached successfully",
        "status": "ok"
    }
import os

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port)
