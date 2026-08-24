"""
Thin client for talking to a locally-running Ollama server.

Assumes Ollama is already running on the default port (started
automatically when you `ollama run` or `ollama serve`). This file
does exactly one thing: send a prompt, get back the model's raw text.
Cleaning/validating that text is schema.py's job, not this file's.
"""

import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "qwen2.5-coder:7b"

# 7B on a laptop GPU can take a while on long prompts (our prompt is
# long — 10 CWEs of few-shot examples). Generous but not infinite.
REQUEST_TIMEOUT_SECONDS = 120


class OllamaError(Exception):
    """Raised when Ollama can't be reached or returns something unusable."""


def query_ollama(prompt: str, model: str = MODEL_NAME) -> str:
    """
    Send `prompt` to Ollama and return the model's raw generated text.

    Raises:
        OllamaError: connection failure, timeout, non-200 response,
            or a response missing the expected "response" field.
    """
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,  # get one complete JSON object back, not a stream of lines
    }

    try:
        resp = requests.post(
            OLLAMA_URL,
            json=payload,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except requests.exceptions.ConnectionError as e:
        raise OllamaError(
            "Could not connect to Ollama. Is it running? (try `ollama serve` "
            "or just `ollama run qwen2.5-coder:7b` in another terminal)"
        ) from e
    except requests.exceptions.Timeout as e:
        raise OllamaError(
            f"Ollama did not respond within {REQUEST_TIMEOUT_SECONDS}s. "
            "The prompt may be too long, or the model is still loading."
        ) from e

    if resp.status_code != 200:
        raise OllamaError(
            f"Ollama returned HTTP {resp.status_code}: {resp.text[:500]}"
        )

    data = resp.json()

    if "response" not in data:
        raise OllamaError(
            f"Unexpected Ollama response shape, missing 'response' key: {data}"
        )

    return data["response"]


if __name__ == "__main__":
    # Quick standalone smoke test — run this file directly:
    #   python ollama_client.py
    # before wiring anything else around it.
    test_prompt = (
        "Reply with exactly the text: OLLAMA_CLIENT_OK "
        "(no other words, no punctuation)."
    )
    try:
        result = query_ollama(test_prompt)
        print("Raw response from Ollama:")
        print(result)
    except OllamaError as e:
        print(f"OllamaError: {e}")
