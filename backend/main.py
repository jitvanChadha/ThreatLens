"""
FastAPI backend for the SLM security analyzer with RAG Knowledge Base.

Wires together:
  prompt.py                 -> builds the ThreatLens prompt from raw code + RAG
  ollama_client.py          -> sends prompt to local Qwen model
  schema.py                 -> parses and validates model's output
  domain/ingestion/         -> multi-file & folder parsing & filtering
  domain/knowledge_base/    -> persistent ChromaDB vector store + RAG retriever
"""

import asyncio
import io
import zipfile
from typing import List, Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from prompt import prompt_builder
from ollama_client import query_ollama, OllamaError
from schema import safe_parse, Finding
from regex_scanner import regex_scan, merge_findings
from false_positive_filter import filter_false_positives
from context7_client import get_context7_docs

from domain.ingestion.ingestion_models import IngestResponse, FileResult
from domain.ingestion.file_filter import filter_files, filter_members
from domain.ingestion.file_reader import read_upload, read_bytes
from domain.ingestion.scanner import scan_files

from domain.knowledge_base.retriever import retrieve_context, search_knowledge_base
from domain.knowledge_base.indexer import index_files_async
from domain.knowledge_base.vector_store import count_collection, clear_user_code, seed_cwe_corpus
from domain.knowledge_base.embedder import get_model_name
from domain.knowledge_base.kb_models import KBStatusResponse, SearchResult, IndexResult

app = FastAPI(title="SLM Security Analyzer with RAG", version="0.3.0")

# Allow the standalone HTML frontend (any origin) to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    """Background startup task to ensure reference CWE corpus is seeded."""
    asyncio.create_task(asyncio.to_thread(seed_cwe_corpus))


# ---------------------------------------------------------------------------
# Shared analysis helper — uses regex + Context7 docs + RAG vector context
# ---------------------------------------------------------------------------

def _analyze_code(code: str) -> list[Finding]:
    """
    Run the full ThreatLens analysis pipeline on a single code string.
    Injects both external doc context and retrieved internal RAG knowledge.
    Returns a merged list of Finding objects (LLM + regex).
    """
    regex_findings = regex_scan(code)
    doc_context = get_context7_docs(code)
    rag_context = retrieve_context(code)
    prompt = prompt_builder(code, doc_context=doc_context, rag_context=rag_context)

    try:
        raw_output = query_ollama(prompt)
    except OllamaError as e:
        if regex_findings:
            validated_regex = filter_false_positives(regex_findings, code)
            return [Finding.model_validate(f) for f in validated_regex]
        raise

    llm_findings, error = safe_parse(raw_output)

    if error is not None:
        if regex_findings:
            validated_regex = filter_false_positives(regex_findings, code)
            return [Finding.model_validate(f) for f in validated_regex]
        raise HTTPException(
            status_code=502,
            detail={"message": "Model output failed validation", "error": error, "raw_output": raw_output},
        )

    merged = merge_findings(llm_findings, regex_findings)
    validated = filter_false_positives(merged, code)
    return [Finding.model_validate(f) for f in validated]


# ---------------------------------------------------------------------------
# Core Analyzer Endpoints
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    code: str = Field(..., min_length=1, description="Source code to analyze")


class AnalyzeResponse(BaseModel):
    findings: list[Finding]


@app.get("/health")
def health():
    """Basic liveness check."""
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest):
    try:
        findings = _analyze_code(request.code)
    except OllamaError as e:
        raise HTTPException(status_code=503, detail=str(e))
    return AnalyzeResponse(findings=findings)


# ---------------------------------------------------------------------------
# File Ingestion Endpoints (with automated RAG indexing)
# ---------------------------------------------------------------------------

@app.post("/ingest/files", response_model=IngestResponse)
async def ingest_files(
    background_tasks: BackgroundTasks,
    files: list[UploadFile] = File(..., description="One or more source-code files to scan"),
):
    """
    Upload individual source files for security analysis and auto-index into RAG storage.
    """
    allowed_uploads, skipped_reasons = filter_files(files)
    total = len(files)

    ingested = []
    extra_skips: list[str] = []

    for upload in allowed_uploads:
        file_obj = await read_upload(upload)
        if file_obj is None:
            extra_skips.append(f"{upload.filename}: binary or undecodable content")
        else:
            ingested.append(file_obj)

    # Queue background indexing to enrich the knowledge base for future RAG queries
    if ingested:
        background_tasks.add_task(index_files_async, ingested)

    results = await scan_files(ingested, _analyze_code)

    for reason in extra_skips:
        filename = reason.split(":")[0]
        results.append(FileResult(filename=filename, language="unknown", findings=[], error=reason))

    return IngestResponse(
        total_files=total,
        analysed=len(ingested),
        skipped=total - len(ingested),
        files=results,
    )


@app.post("/ingest/folder", response_model=IngestResponse)
async def ingest_folder(
    background_tasks: BackgroundTasks,
    folder: UploadFile = File(..., description="ZIP archive of the project folder to scan"),
):
    """
    Upload a ZIP of a whole project folder for security analysis and auto-indexing.
    """
    raw_zip = await folder.read()

    try:
        zf = zipfile.ZipFile(io.BytesIO(raw_zip))
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Uploaded file is not a valid ZIP archive.")

    members: list[tuple[str, bytes]] = []
    for info in zf.infolist():
        if info.is_dir():
            continue
        members.append((info.filename, zf.read(info.filename)))

    total = len(members)
    allowed_members, skipped_reasons = filter_members(members)

    ingested = []
    extra_skips: list[str] = []

    for name, data in allowed_members:
        file_obj = read_bytes(name, data)
        if file_obj is None:
            extra_skips.append(f"{name}: binary or undecodable content")
        else:
            ingested.append(file_obj)

    # Auto-index into RAG in background
    if ingested:
        background_tasks.add_task(index_files_async, ingested)

    results = await scan_files(ingested, _analyze_code)

    for reason in extra_skips:
        filename = reason.split(":")[0]
        results.append(FileResult(filename=filename, language="unknown", findings=[], error=reason))

    return IngestResponse(
        total_files=total,
        analysed=len(ingested),
        skipped=total - len(ingested),
        files=results,
    )


# ---------------------------------------------------------------------------
# RAG Knowledge Base Endpoints
# ---------------------------------------------------------------------------

@app.get("/kb/status", response_model=KBStatusResponse)
def get_kb_status():
    """Returns the current status and vector count of the knowledge base."""
    user_count = count_collection("user_code")
    cwe_count = count_collection("cwe_corpus")
    return KBStatusResponse(
        user_code_chunks=user_count,
        cwe_corpus_chunks=cwe_count,
        embedding_model=get_model_name(),
        status="ready",
    )


@app.get("/kb/search", response_model=List[SearchResult])
def search_kb(
    q: str = Query(..., min_length=1, description="Semantic search query string or code snippet"),
    n: int = Query(default=5, ge=1, le=20, description="Max results to return"),
    collection: Optional[str] = Query(default=None, description="'user_code' or 'cwe_corpus' or None for all"),
):
    """
    Semantically search indexed code chunks and vulnerability patterns.
    """
    return search_knowledge_base(query=q, n_results=n, collection=collection)


@app.post("/kb/index", response_model=List[IndexResult])
async def manual_index_files(
    files: list[UploadFile] = File(..., description="Source-code files to index into Knowledge Base"),
):
    """
    Explicitly index source files into vector storage without running an immediate scan.
    """
    allowed_uploads, _ = filter_files(files)
    ingested = []
    for upload in allowed_uploads:
        file_obj = await read_upload(upload)
        if file_obj:
            ingested.append(file_obj)

    if not ingested:
        return []

    return await index_files_async(ingested)


@app.delete("/kb/clear")
def clear_knowledge_base():
    """
    Clear all user codebase vector embeddings (keeps built-in CWE corpus intact).
    """
    clear_user_code()
    return {"status": "cleared", "message": "user_code vector collection cleared successfully"}
