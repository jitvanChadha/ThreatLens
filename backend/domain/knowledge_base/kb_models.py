"""
Pydantic models for the ThreatLens knowledge base and RAG vector store.
"""

from typing import Any, Dict, Optional, List
from pydantic import BaseModel, Field


class Chunk(BaseModel):
    id: str = Field(..., description="Unique identifier for chunk (hash of filename + index)")
    filename: str = Field(..., description="Source filename or identifier")
    language: str = Field(default="text", description="Programming language")
    chunk_index: int = Field(default=0, ge=0)
    content: str = Field(..., description="Raw text / code slice")
    start_line: int = Field(default=1, ge=1)
    end_line: int = Field(default=1, ge=1)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class IndexResult(BaseModel):
    filename: str
    chunks_indexed: int
    error: Optional[str] = None


class SearchResult(BaseModel):
    id: str
    filename: str
    language: str
    content: str
    distance: float = Field(..., description="Cosine / L2 distance from query vector")
    start_line: int
    end_line: int
    collection: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class KBStatusResponse(BaseModel):
    user_code_chunks: int
    cwe_corpus_chunks: int
    embedding_model: str
    status: str
