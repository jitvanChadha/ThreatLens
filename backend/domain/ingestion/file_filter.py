"""
Decides which uploaded files are eligible for security analysis.

Rules applied in order:
  1. Extension must be in ALLOWED_EXTENSIONS (source code, not binaries/data)
  2. File size must not exceed MAX_FILE_BYTES (default 500 KB)
  3. Total file count must not exceed MAX_FILES_PER_SCAN (default 50)

Returns two lists: (allowed, skipped_reasons).
"""

from fastapi import UploadFile

# Source-code extensions ThreatLens can meaningfully analyse
ALLOWED_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".go", ".java", ".rb", ".php",
    ".c", ".cpp", ".cc", ".h", ".hpp",
    ".cs", ".rs", ".sh", ".bash",
    ".yaml", ".yml", ".toml", ".json",  # config files — often hold secrets
}

MAX_FILE_BYTES = 500_000   # 500 KB
MAX_FILES_PER_SCAN = 50


def filter_files(
    uploads: list[UploadFile],
) -> tuple[list[UploadFile], list[str]]:
    """
    Filter a list of UploadFile objects to only those eligible for analysis.

    Returns:
        allowed  — UploadFile objects to proceed with
        skipped  — human-readable reason strings for rejected files
    """
    allowed: list[UploadFile] = []
    skipped: list[str] = []

    for upload in uploads[:MAX_FILES_PER_SCAN]:
        name = upload.filename or ""
        ext = _extension(name)

        if ext not in ALLOWED_EXTENSIONS:
            skipped.append(f"{name}: unsupported extension '{ext}'")
            continue

        # Size check: UploadFile.size is set by FastAPI when available
        size = upload.size
        if size is not None and size > MAX_FILE_BYTES:
            skipped.append(f"{name}: file too large ({size:,} bytes > {MAX_FILE_BYTES:,})")
            continue

        allowed.append(upload)

    # Any uploads beyond the per-scan cap go straight to skipped
    for upload in uploads[MAX_FILES_PER_SCAN:]:
        name = upload.filename or ""
        skipped.append(f"{name}: scan limit of {MAX_FILES_PER_SCAN} files reached")

    return allowed, skipped


def filter_members(
    members: list[tuple[str, bytes]],
) -> tuple[list[tuple[str, bytes]], list[str]]:
    """
    Same filtering logic for (name, raw_bytes) tuples extracted from a ZIP.
    Used by the /ingest/folder endpoint.
    """
    allowed: list[tuple[str, bytes]] = []
    skipped: list[str] = []

    for name, data in members[:MAX_FILES_PER_SCAN]:
        ext = _extension(name)

        if ext not in ALLOWED_EXTENSIONS:
            skipped.append(f"{name}: unsupported extension '{ext}'")
            continue

        if len(data) > MAX_FILE_BYTES:
            skipped.append(f"{name}: file too large ({len(data):,} bytes > {MAX_FILE_BYTES:,})")
            continue

        allowed.append((name, data))

    for name, _ in members[MAX_FILES_PER_SCAN:]:
        skipped.append(f"{name}: scan limit of {MAX_FILES_PER_SCAN} files reached")

    return allowed, skipped


def _extension(filename: str) -> str:
    """Return the lowercased file extension including the leading dot, or ''."""
    if "." not in filename:
        return ""
    return "." + filename.rsplit(".", 1)[-1].lower()
