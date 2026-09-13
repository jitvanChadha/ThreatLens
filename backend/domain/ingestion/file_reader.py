"""
Reads uploaded files (UploadFile or raw bytes) and decodes them to text.

Strategy:
  1. Try UTF-8 (covers the vast majority of source code)
  2. Fall back to latin-1 (lossless for arbitrary bytes — flags as non-UTF-8)
  3. If the content looks binary (>10% non-printable bytes), return None

Returns an IngestedFile on success, None if the file cannot be used.
"""

from fastapi import UploadFile
from domain.ingestion.ingestion_models import IngestedFile

# Language inferred from extension
_EXT_TO_LANG: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c",
    ".cc": "c",
    ".cpp": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".rs": "rust",
    ".sh": "shell",
    ".bash": "shell",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".json": "json",
}

# Threshold: if more than 10% of bytes are non-printable, treat as binary
_BINARY_THRESHOLD = 0.10


async def read_upload(upload: UploadFile) -> IngestedFile | None:
    """
    Async: read an UploadFile, decode it, return IngestedFile or None.
    """
    raw: bytes = await upload.read()
    filename = upload.filename or "unknown"
    return _decode(filename, raw)


def read_bytes(filename: str, raw: bytes) -> IngestedFile | None:
    """
    Sync: decode raw bytes from a ZIP member, return IngestedFile or None.
    """
    return _decode(filename, raw)


def _decode(filename: str, raw: bytes) -> IngestedFile | None:
    if _is_binary(raw):
        return None

    # Try UTF-8 first, fall back to latin-1
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")

    ext = _ext(filename)
    return IngestedFile(
        filename=filename,
        language=_EXT_TO_LANG.get(ext, "unknown"),
        content=text,
        size_bytes=len(raw),
    )


def _is_binary(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:4096]
    non_printable = sum(1 for b in sample if b < 9 or (13 < b < 32) or b == 127)
    return non_printable / len(sample) > _BINARY_THRESHOLD


def _ext(filename: str) -> str:
    if "." not in filename:
        return ""
    return "." + filename.rsplit(".", 1)[-1].lower()
