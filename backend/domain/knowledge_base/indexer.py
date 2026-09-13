"""
Indexer service for the ThreatLens knowledge base.

Processes IngestedFiles into semantic chunks, generates dense vector
embeddings, and writes them to the persistent vector store.
"""

import asyncio
import logging
from typing import List

from domain.ingestion.ingestion_models import IngestedFile
from domain.knowledge_base.kb_models import IndexResult
from domain.knowledge_base.chunker import chunk_file
from domain.knowledge_base.vector_store import upsert_chunks

logger = logging.getLogger("threatlens.indexer")


def index_files_sync(files: List[IngestedFile]) -> List[IndexResult]:
    """
    Synchronously chunk, embed, and store files into ChromaDB's user_code collection.
    """
    results: List[IndexResult] = []
    for file in files:
        try:
            chunks = chunk_file(file)
            if chunks:
                upsert_chunks("user_code", chunks)
                results.append(IndexResult(filename=file.filename, chunks_indexed=len(chunks)))
                logger.info(f"Indexed {len(chunks)} chunks from {file.filename}")
            else:
                results.append(IndexResult(filename=file.filename, chunks_indexed=0))
        except Exception as e:
            logger.error(f"Failed to index {file.filename}: {e}")
            results.append(IndexResult(filename=file.filename, chunks_indexed=0, error=str(e)))
    return results


async def index_files_async(files: List[IngestedFile]) -> List[IndexResult]:
    """
    Async background wrapper for indexing batch files without blocking the main event loop.
    """
    return await asyncio.to_thread(index_files_sync, files)
