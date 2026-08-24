"""
FastAPI backend for the SLM security analyzer.

Wires together the three pieces already built and tested standalone:
  prompt.py         -> builds the ThreatLens prompt from raw code
  ollama_client.py  -> sends that prompt to the local Qwen model
  schema.py         -> cleans, parses, and validates the model's output

Run with:
    uvicorn main:app --reload

Then test with:
    curl -X POST http://localhost:8000/analyze \
         -H "Content-Type: application/json" \
         -d '{"code": "import hashlib\ndef h(p):\n    return hashlib.md5(p.encode()).hexdigest()"}'
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from prompt import prompt_builder
from ollama_client import query_ollama, OllamaError
from schema import safe_parse, Finding
from regex_scanner import regex_scan, merge_findings
from context7_client import get_context7_docs

app = FastAPI(title="SLM Security Analyzer", version="0.1.0")

# Allow the standalone HTML frontend (any origin) to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    code: str = Field(..., min_length=1, description="Source code to analyze")


class AnalyzeResponse(BaseModel):
    findings: list[Finding]


@app.get("/health")
def health():
    """Basic liveness check — does NOT confirm Ollama is reachable."""
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest):
    # 1. Deterministic regex scan — instant safety net (< 50ms)
    regex_findings = regex_scan(request.code)

    # 2. Context7 documentation lookup (graceful fallback if API key is missing or fails)
    doc_context = get_context7_docs(request.code)

    # 3. LLM analysis with injected Context7 context
    prompt = prompt_builder(request.code, doc_context=doc_context)

    try:
        raw_output = query_ollama(prompt)
    except OllamaError as e:
        # Ollama unreachable, timed out, or returned something unusable.
        # If we have regex findings, return those rather than a hard failure.
        if regex_findings:
            return AnalyzeResponse(
                findings=[Finding.model_validate(f) for f in regex_findings]
            )
        # 503 = "the thing we depend on isn't available right now."
        raise HTTPException(status_code=503, detail=str(e))

    llm_findings, error = safe_parse(raw_output)

    if error is not None:
        # Model responded but output didn't match schema.
        # If we have regex findings, return those as a fallback.
        if regex_findings:
            return AnalyzeResponse(
                findings=[Finding.model_validate(f) for f in regex_findings]
            )
        # 502 = model/prompt problem.
        raise HTTPException(
            status_code=502,
            detail={
                "message": "Model output failed validation",
                "error": error,
                "raw_output": raw_output,
            },
        )

    # 3. Merge: LLM findings take priority, regex fills gaps
    merged = merge_findings(llm_findings, regex_findings)
    return AnalyzeResponse(
        findings=[Finding.model_validate(f) for f in merged]
    )
