"""
FastAPI backend — exposes the phishing analyzer over HTTP.

The Streamlit UI and the Gmail add-on both call this service.
Run with: uvicorn api:app --reload --port 8000
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from phishing_analyzer import analyze_email

app = FastAPI(
    title="Email Phishing Detector API",
    description="Heuristic analysis of raw RFC 822 email content.",
    version="1.0.0",
)

# Open CORS so the Streamlit UI (localhost:8501) and Google Apps Script
# (via ngrok) can both reach this service without browser or server blocks.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    """The complete raw email text — headers and body — as it came off the wire."""
    raw_email: str = Field(
        ...,
        description="Complete raw email text (e.g., contents of a .eml file).",
    )


class AnalyzeResponse(BaseModel):
    is_phishing: bool
    risk_score: int = Field(..., ge=0, le=100)
    detected_indicators: list[str]


@app.get("/health")
def health() -> dict[str, str]:
    """Simple liveness check — used by ngrok and monitoring tools."""
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    """Analyze a raw email and return the phishing verdict, score, and indicators."""
    if not req.raw_email or not req.raw_email.strip():
        raise HTTPException(status_code=400, detail="raw_email must not be empty")
    try:
        result = analyze_email(req.raw_email)
    except Exception as exc:  # surface parse errors with a clear message rather than a 500
        raise HTTPException(
            status_code=422,
            detail=f"Could not parse email: {exc}",
        ) from exc
    return AnalyzeResponse(**result)
