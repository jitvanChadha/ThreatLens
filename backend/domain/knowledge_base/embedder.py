"""
Local offline sentence-transformers embedding wrapper.

Loads the model once as a singleton to avoid re-allocating memory
or reloading weights on every request.
"""

import os
import logging
from typing import List

logger = logging.getLogger("threatlens.embedder")

DEFAULT_MODEL_NAME = "all-MiniLM-L6-v2"

_MODEL_INSTANCE = None


def get_model():
    """Lazy-load the SentenceTransformer model singleton."""
    global _MODEL_INSTANCE
    if _MODEL_INSTANCE is None:
        model_name = os.environ.get("THREATLENS_EMBED_MODEL", DEFAULT_MODEL_NAME)
        logger.info(f"Loading embedding model: {model_name}...")
        from sentence_transformers import SentenceTransformer
        _MODEL_INSTANCE = SentenceTransformer(model_name)
        logger.info(f"Embedding model {model_name} loaded successfully.")
    return _MODEL_INSTANCE


def embed_texts(texts: List[str]) -> List[List[float]]:
    """
    Generate dense vector embeddings for a list of text strings.
    """
    if not texts:
        return []
    model = get_model()
    embeddings = model.encode(texts, normalize_embeddings=True, show_progress_bar=False)
    return embeddings.tolist()


def embed_query(query: str) -> List[float]:
    """
    Generate dense vector embedding for a single query text.
    """
    embeddings = embed_texts([query])
    return embeddings[0] if embeddings else []


def get_model_name() -> str:
    return os.environ.get("THREATLENS_EMBED_MODEL", DEFAULT_MODEL_NAME)
