"""
Strict output schema for the ThreatLens security analyzer.

Field names here match prompt.py's OUTPUT SCHEMA exactly:
cwe_id, vulnerability, severity, line_start, line_end, description, fix.
If you ever change one side, change the other — a mismatch here means
every response silently fails validation.
"""

import json
import re
from enum import Enum
from typing import List
from pydantic import BaseModel, Field, field_validator, ValidationError


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SupportedCWE(str, Enum):
    COMMAND_INJECTION = "CWE-78"
    HARDCODED_CREDENTIALS = "CWE-798"
    SQL_INJECTION = "CWE-89"
    XSS = "CWE-79"
    PATH_TRAVERSAL = "CWE-22"
    INSECURE_DESERIALIZATION = "CWE-502"
    SSRF = "CWE-918"
    WEAK_CRYPTO = "CWE-327"
    INSECURE_RANDOMNESS = "CWE-330"
    IMPROPER_INPUT_VALIDATION = "CWE-20"


class Finding(BaseModel):
    cwe_id: SupportedCWE
    vulnerability: str = Field(..., min_length=3, max_length=120)
    severity: Severity
    line_start: int = Field(..., ge=1)
    line_end: int = Field(..., ge=1)
    description: str = Field(..., min_length=5, max_length=600)
    fix: str = Field(..., min_length=3, max_length=600)
    source: str = Field(default="llm", description="Origin engine: 'llm' or 'regex'")

    @field_validator("line_end")
    @classmethod
    def end_after_start(cls, v, info):
        start = info.data.get("line_start")
        if start is not None and v < start:
            raise ValueError("line_end must be >= line_start")
        return v


# The model always returns a bare JSON array, not a wrapped object —
# so the "schema" for a whole response is just a list of Finding.
FindingsList = List[Finding]


_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


def strip_markdown_fences(raw: str) -> str:
    """
    Remove ```json / ``` fences if the model wraps its output in them,
    despite the prompt asking it not to. Safe no-op if there are none.
    """
    return _FENCE_RE.sub("", raw.strip()).strip()


def parse_and_validate(raw_output: str) -> FindingsList:
    """
    Take the raw text returned by Ollama, clean it, parse it as JSON,
    and validate it against the Finding schema.

    Raises:
        json.JSONDecodeError: if the cleaned text isn't valid JSON at all.
        pydantic.ValidationError: if it's valid JSON but doesn't match
            the expected finding shape (wrong field, wrong type, etc).
    """
    cleaned = strip_markdown_fences(raw_output)
    parsed = json.loads(cleaned)  # let JSONDecodeError propagate as-is

    if not isinstance(parsed, list):
        raise ValueError(
            f"Expected a JSON array of findings, got {type(parsed).__name__}"
        )

    return [Finding.model_validate(item) for item in parsed]


def safe_parse(raw_output: str):
    """
    Non-raising variant for API endpoints: returns (findings, error).
    Exactly one of the two will be None.
    """
    try:
        return parse_and_validate(raw_output), None
    except (json.JSONDecodeError, ValidationError, ValueError) as e:
        return None, str(e)
