"""
ChromaDB Vector Store wrapper.

Manages persistent on-disk vector collections:
  1. `user_code`: chunks generated from uploaded files / workspaces
  2. `cwe_corpus`: reference vulnerable / safe security examples
"""

import os
import logging
from typing import List, Optional
import chromadb
from chromadb.config import Settings

from domain.knowledge_base.kb_models import Chunk, SearchResult
from domain.knowledge_base.embedder import embed_texts

logger = logging.getLogger("threatlens.vector_store")

PERSIST_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data", "chroma")

_CHROMA_CLIENT = None


def get_chroma_client():
    """Lazy-initialize persistent ChromaDB client."""
    global _CHROMA_CLIENT
    if _CHROMA_CLIENT is None:
        os.makedirs(PERSIST_DIR, exist_ok=True)
        _CHROMA_CLIENT = chromadb.PersistentClient(
            path=PERSIST_DIR,
            settings=Settings(anonymized_telemetry=False, allow_reset=True),
        )
    return _CHROMA_CLIENT


def get_collection(name: str):
    """Retrieve or create a collection configured for cosine similarity."""
    client = get_chroma_client()
    return client.get_or_create_collection(
        name=name,
        metadata={"hnsw:space": "cosine"},
    )


def upsert_chunks(collection_name: str, chunks: List[Chunk], embeddings: Optional[List[List[float]]] = None):
    """
    Store or update code chunks and their embeddings in ChromaDB.
    """
    if not chunks:
        return

    if embeddings is None:
        texts = [c.content for c in chunks]
        embeddings = embed_texts(texts)

    collection = get_collection(collection_name)

    ids = [c.id for c in chunks]
    documents = [c.content for c in chunks]
    metadatas = []

    for c in chunks:
        meta = {
            "filename": str(c.filename),
            "language": str(c.language),
            "start_line": int(c.start_line),
            "end_line": int(c.end_line),
            "chunk_index": int(c.chunk_index),
        }
        if c.metadata:
            for k, v in c.metadata.items():
                if isinstance(v, (str, int, float, bool)):
                    meta[k] = v
        metadatas.append(meta)

    collection.upsert(
        ids=ids,
        embeddings=embeddings,
        documents=documents,
        metadatas=metadatas,
    )


def query_similar(collection_name: str, query_embedding: List[float], n_results: int = 3) -> List[SearchResult]:
    """
    Query nearest chunks from specified collection.
    """
    collection = get_collection(collection_name)
    total_count = collection.count()
    if total_count == 0 or not query_embedding:
        return []

    actual_n = min(n_results, total_count)
    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=actual_n,
        include=["documents", "metadatas", "distances"],
    )

    hits: List[SearchResult] = []
    if not results or not results.get("ids") or not results["ids"][0]:
        return hits

    ids = results["ids"][0]
    docs = results["documents"][0] if results.get("documents") else []
    metas = results["metadatas"][0] if results.get("metadatas") else []
    dists = results["distances"][0] if results.get("distances") else []

    for i in range(len(ids)):
        meta = metas[i] if i < len(metas) else {}
        hits.append(
            SearchResult(
                id=ids[i],
                filename=str(meta.get("filename", "unknown")),
                language=str(meta.get("language", "python")),
                content=docs[i] if i < len(docs) else "",
                distance=float(dists[i]) if i < len(dists) else 1.0,
                start_line=int(meta.get("start_line", 1)),
                end_line=int(meta.get("end_line", 1)),
                collection=collection_name,
                metadata=meta,
            )
        )

    return hits


def count_collection(collection_name: str) -> int:
    try:
        col = get_collection(collection_name)
        return col.count()
    except Exception as e:
        logger.warning(f"Error counting collection {collection_name}: {e}")
        return 0


def clear_user_code():
    """Clear all indexed user code without removing cwe_corpus."""
    client = get_chroma_client()
    try:
        client.delete_collection(name="user_code")
    except Exception:
        pass
    # Re-create empty collection
    client.get_or_create_collection(name="user_code", metadata={"hnsw:space": "cosine"})


def seed_cwe_corpus():
    """
    Seed standard CWE reference examples from prompt.py into `cwe_corpus` if empty.
    """
    col = get_collection("cwe_corpus")
    if col.count() > 0:
        return

    logger.info("Seeding cwe_corpus with reference security examples...")
    from prompt import PROMPT_TEMPLATE

    # Extract example blocks from PROMPT_TEMPLATE
    example_sections = PROMPT_TEMPLATE.split("--- Example ")
    chunks_to_seed: List[Chunk] = []

    for idx, sec in enumerate(example_sections[1:], 1):
        lines = sec.strip().splitlines()
        header = lines[0] if lines else f"Example {idx}"
        cwe_match = header.split("—")[0].strip() if "—" in header else f"CWE-EX-{idx}"

        vuln_text = ""
        safe_text = ""

        if "VULNERABLE:" in sec and "Finding:" in sec:
            vuln_part = sec.split("VULNERABLE:")[1].split("Finding:")[0].strip()
            vuln_text = vuln_part

        if "SAFE:" in sec and "Finding:" in sec:
            safe_part = sec.split("SAFE:")[1].split("Finding:")[0].strip()
            safe_text = safe_part

        if vuln_text:
            chunks_to_seed.append(
                Chunk(
                    id=f"cwe_vuln_{idx}",
                    filename=f"reference_{cwe_match}_vulnerable.py",
                    language="python",
                    chunk_index=0,
                    content=vuln_text,
                    start_line=1,
                    end_line=len(vuln_text.splitlines()),
                    metadata={"cwe": cwe_match, "type": "vulnerable_example", "header": header},
                )
            )

        if safe_text:
            chunks_to_seed.append(
                Chunk(
                    id=f"cwe_safe_{idx}",
                    filename=f"reference_{cwe_match}_safe.py",
                    language="python",
                    chunk_index=1,
                    content=safe_text,
                    start_line=1,
                    end_line=len(safe_text.splitlines()),
                    metadata={"cwe": cwe_match, "type": "safe_example", "header": header},
                )
            )

    if chunks_to_seed:
        upsert_chunks("cwe_corpus", chunks_to_seed)
        logger.info(f"Successfully seeded {len(chunks_to_seed)} reference examples in cwe_corpus.")
