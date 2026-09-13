"""
Pydantic models for the ThreatLens file ingestion pipeline.

Three layers:
  IngestedFile   — a decoded source file ready for analysis
  FileResult     — analysis output for one file (findings + metadata)
  IngestResponse — the full API response for a batch scan
"""

from pydantic import BaseModel, Field
from schema import Finding  # reuse the validated Finding model from the main schema


class IngestedFile(BaseModel):
    filename: str = Field(..., description="Original filename / relative path inside ZIP")
    language: str = Field(..., description="Inferred language, e.g. 'python', 'javascript'")
    content: str = Field(..., description="Decoded UTF-8 source text")
    size_bytes: int = Field(..., ge=0)


class FileResult(BaseModel):
    filename: str
    language: str
    findings: list[Finding]
    error: str | None = Field(
        default=None,
        description="Set when the file could not be analysed (decode error, binary, etc.)",
    )


class IngestResponse(BaseModel):
    total_files: int = Field(..., description="Total files received (including skipped)")
    analysed: int = Field(..., description="Files that went through the LLM pipeline")
    skipped: int = Field(..., description="Files skipped due to extension, size, or decode errors")
    files: list[FileResult]
