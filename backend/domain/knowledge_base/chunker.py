"""
Semantic and line-aware source code chunker.

Breaks down source files into coherent chunks while preserving
line numbers and context for vulnerability mapping.
"""

import ast
import hashlib
import re
from typing import List
from domain.knowledge_base.kb_models import Chunk
from domain.ingestion.ingestion_models import IngestedFile

MAX_CHUNK_LINES = 100
DEFAULT_WINDOW_LINES = 50
OVERLAP_LINES = 10


def _generate_chunk_id(filename: str, chunk_index: int, content: str) -> str:
    h = hashlib.sha256(f"{filename}:{chunk_index}:{content}".encode("utf-8")).hexdigest()[:12]
    safe_name = re.sub(r"[^a-zA-Z0-9_\-.]", "_", filename)
    return f"{safe_name}_{chunk_index}_{h}"


def chunk_file(file: IngestedFile) -> List[Chunk]:
    """
    Split an IngestedFile into semantic Chunks with line tracking.
    """
    if file.language == "python":
        return _chunk_python(file)
    return _chunk_line_window(file)


def _chunk_python(file: IngestedFile) -> List[Chunk]:
    """
    Parse Python AST to extract functions, classes, and standalone code.
    Fallback to windowed chunking on SyntaxError.
    """
    lines = file.content.splitlines(keepends=True)
    if not lines:
        return []

    try:
        tree = ast.parse(file.content, filename=file.filename)
    except Exception:
        return _chunk_line_window(file)

    nodes_to_chunk = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            nodes_to_chunk.append(node)

    if not nodes_to_chunk:
        return _chunk_line_window(file)

    chunks: List[Chunk] = []
    covered_lines = set()
    chunk_idx = 0

    for node in nodes_to_chunk:
        start_line = getattr(node, "lineno", 1)
        end_line = getattr(node, "end_lineno", start_line)

        # Slice lines (1-indexed to 0-indexed)
        chunk_lines = lines[start_line - 1 : end_line]
        chunk_content = "".join(chunk_lines).strip()

        if not chunk_content:
            continue

        # If a single function is gigantic, sub-window it
        if len(chunk_lines) > MAX_CHUNK_LINES:
            sub_file = IngestedFile(
                filename=file.filename,
                language=file.language,
                content=chunk_content,
                size_bytes=len(chunk_content.encode("utf-8")),
            )
            sub_chunks = _chunk_line_window(sub_file, start_offset=start_line)
            for sc in sub_chunks:
                sc.chunk_index = chunk_idx
                chunk_idx += 1
                chunks.append(sc)
        else:
            chunks.append(
                Chunk(
                    id=_generate_chunk_id(file.filename, chunk_idx, chunk_content),
                    filename=file.filename,
                    language=file.language,
                    chunk_index=chunk_idx,
                    content=chunk_content,
                    start_line=start_line,
                    end_line=end_line,
                    metadata={
                        "filename": file.filename,
                        "language": file.language,
                        "name": getattr(node, "name", "anonymous"),
                        "type": type(node).__name__,
                    },
                )
            )
            chunk_idx += 1

        for ln in range(start_line, end_line + 1):
            covered_lines.add(ln)

    # Catch top-level module code not inside classes/functions if substantial
    all_lines = len(lines)
    uncovered_start = None
    for i in range(1, all_lines + 1):
        if i not in covered_lines:
            if uncovered_start is None:
                uncovered_start = i
        else:
            if uncovered_start is not None:
                uncovered_lines = lines[uncovered_start - 1 : i - 1]
                u_content = "".join(uncovered_lines).strip()
                if len(u_content) > 30:  # ignore empty spaces / comments
                    chunks.append(
                        Chunk(
                            id=_generate_chunk_id(file.filename, chunk_idx, u_content),
                            filename=file.filename,
                            language=file.language,
                            chunk_index=chunk_idx,
                            content=u_content,
                            start_line=uncovered_start,
                            end_line=i - 1,
                            metadata={"filename": file.filename, "language": file.language, "type": "module_scope"},
                        )
                    )
                    chunk_idx += 1
                uncovered_start = None

    if uncovered_start is not None:
        uncovered_lines = lines[uncovered_start - 1 : all_lines]
        u_content = "".join(uncovered_lines).strip()
        if len(u_content) > 30:
            chunks.append(
                Chunk(
                    id=_generate_chunk_id(file.filename, chunk_idx, u_content),
                    filename=file.filename,
                    language=file.language,
                    chunk_index=chunk_idx,
                    content=u_content,
                    start_line=uncovered_start,
                    end_line=all_lines,
                    metadata={"filename": file.filename, "language": file.language, "type": "module_scope"},
                )
            )

    return chunks if chunks else _chunk_line_window(file)


def _chunk_line_window(file: IngestedFile, start_offset: int = 1) -> List[Chunk]:
    """
    Sliding window chunking based on lines with overlap.
    """
    lines = file.content.splitlines(keepends=True)
    if not lines:
        return []

    chunks: List[Chunk] = []
    total_lines = len(lines)
    chunk_idx = 0
    step = DEFAULT_WINDOW_LINES - OVERLAP_LINES

    for i in range(0, total_lines, step):
        window_lines = lines[i : min(i + DEFAULT_WINDOW_LINES, total_lines)]
        chunk_content = "".join(window_lines).strip()
        if not chunk_content:
            continue

        start_ln = start_offset + i
        end_ln = start_offset + min(i + DEFAULT_WINDOW_LINES, total_lines) - 1

        chunks.append(
            Chunk(
                id=_generate_chunk_id(file.filename, chunk_idx, chunk_content),
                filename=file.filename,
                language=file.language,
                chunk_index=chunk_idx,
                content=chunk_content,
                start_line=start_ln,
                end_line=end_ln,
                metadata={"filename": file.filename, "language": file.language, "type": "window"},
            )
        )
        chunk_idx += 1
        if i + DEFAULT_WINDOW_LINES >= total_lines:
            break

    return chunks
