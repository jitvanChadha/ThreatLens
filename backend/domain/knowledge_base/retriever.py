"""
RAG Retriever module for ThreatLens.

Queries vector collections using dense vector similarity to augment
LLM prompts with relevant codebase context and historical vulnerability patterns.
"""

import logging
from typing import List, Optional
from domain.knowledge_base.kb_models import SearchResult
from domain.knowledge_base.embedder import embed_query
from domain.knowledge_base.vector_store import query_similar, count_collection, seed_cwe_corpus

logger = logging.getLogger("threatlens.retriever")


def search_knowledge_base(
    query: str,
    n_results: int = 5,
    collection: Optional[str] = None,
) -> List[SearchResult]:
    """
    Perform semantic vector search across knowledge base collections.
    """
    if not query.strip():
        return []

    query_emb = embed_query(query)
    if not query_emb:
        return []

    hits: List[SearchResult] = []
    if collection:
        hits.extend(query_similar(collection, query_emb, n_results=n_results))
    else:
        # Search both collections and merge by lowest distance (highest similarity)
        user_hits = query_similar("user_code", query_emb, n_results=n_results)
        corpus_hits = query_similar("cwe_corpus", query_emb, n_results=n_results)
        hits = sorted(user_hits + corpus_hits, key=lambda x: x.distance)[:n_results]

    return hits


def retrieve_context(code: str, max_user_chunks: int = 2, max_cwe_chunks: int = 2) -> str:
    """
    Retrieve relevant code snippets and reference patterns to inject into the analysis prompt.
    """
    if not code.strip():
        return ""

    try:
        # Ensure seed data exists
        seed_cwe_corpus()

        query_emb = embed_query(code[:2000])  # embed representative slice
        if not query_emb:
            return ""

        user_hits = query_similar("user_code", query_emb, n_results=max_user_chunks)
        cwe_hits = query_similar("cwe_corpus", query_emb, n_results=max_cwe_chunks)

        sections = []

        if user_hits:
            user_snippets = []
            for h in user_hits:
                # distance threshold to avoid completely irrelevant context
                if h.distance < 0.85:
                    user_snippets.append(
                        f"File: {h.filename} (Lines {h.start_line}-{h.end_line})\n```\n{h.content}\n```"
                    )
            if user_snippets:
                sections.append(
                    "--- Relevant Codebase Context from Workspace ---\n" + "\n\n".join(user_snippets)
                )

        if cwe_hits:
            cwe_snippets = []
            for h in cwe_hits:
                if h.distance < 0.85:
                    cwe_snippets.append(
                        f"Reference Pattern [{h.metadata.get('cwe', 'CWE')}]:\n```\n{h.content}\n```"
                    )
            if cwe_snippets:
                sections.append(
                    "--- Similar Historical Vulnerability Patterns ---\n" + "\n\n".join(cwe_snippets)
                )

        return "\n\n".join(sections)
    except Exception as e:
        logger.warning(f"RAG retrieval encountered an issue: {e}")
        return ""
