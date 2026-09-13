"""
Security scanner for a batch of IngestedFile objects.

Calls the shared _analyze_code() helper (imported from main) for each file
and collects FileResult objects.

Ollama is a single-model server — parallel requests just queue up anyway —
so we run files sequentially inside asyncio.to_thread to avoid blocking
the FastAPI event loop.
"""

import asyncio
from domain.ingestion.ingestion_models import IngestedFile, FileResult


async def scan_files(
    ingested: list[IngestedFile],
    analyze_fn,          # callable: (code: str) -> list[Finding]
) -> list[FileResult]:
    """
    Run the security analyser over each IngestedFile sequentially.

    Args:
        ingested:    Files decoded and ready for analysis.
        analyze_fn:  The shared _analyze_code() helper from main.py.

    Returns:
        One FileResult per ingested file.
    """
    results: list[FileResult] = []

    for f in ingested:
        try:
            # Wrap the blocking LLM call so the event loop stays free
            findings = await asyncio.to_thread(analyze_fn, f.content)
            results.append(
                FileResult(filename=f.filename, language=f.language, findings=findings)
            )
        except Exception as exc:
            results.append(
                FileResult(
                    filename=f.filename,
                    language=f.language,
                    findings=[],
                    error=str(exc),
                )
            )

    return results
