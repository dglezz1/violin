"""Embedding backend for the semantic skill index.

Two providers are supported. The default reads a local ONNX model so that no
target-derived text ever leaves the host; the remote provider posts the same
text to an OpenRouter-compatible embeddings endpoint. Both return a plain list
of floats so the index stays provider-agnostic.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

DEFAULT_REMOTE_MODEL = "nvidia/llama-nemotron-embed-vl-1b-v2:free"
DEFAULT_LOCAL_MODEL_DIR = Path.home() / ".strix" / "embedding-models"
_REMOTE_URL = "https://openrouter.ai/api/v1/embeddings"
# The endpoint rejects inputs above 8192 tokens. Roughly four characters per
# token, minus headroom for the tokeniser's own special tokens.
_MAX_INPUT_CHARS = 24000
# The local model has 512 learned position embeddings, so a longer sequence
# cannot be broadcast into them.
_MAX_SEQUENCE_TOKENS = 512


class EmbeddingError(RuntimeError):
    """Raised when no embedding backend can serve a request."""


def _clip(text: str) -> str:
    """Trim one input to the size the endpoint accepts."""
    if len(text) <= _MAX_INPUT_CHARS:
        return text
    return text[:_MAX_INPUT_CHARS]


@dataclass(frozen=True)
class Embedding:
    """One vector plus the provider that produced it."""

    values: tuple[float, ...]
    provider: str
    model: str

    def __len__(self) -> int:
        return len(self.values)


def cosine(a: Sequence[float], b: Sequence[float]) -> float:
    """Cosine similarity of two equal-length vectors."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = 0.0
    norm_a = 0.0
    norm_b = 0.0
    for x, y in zip(a, b):
        dot += x * y
        norm_a += x * x
        norm_b += y * y
    if norm_a <= 0.0 or norm_b <= 0.0:
        return 0.0
    return dot / ((norm_a**0.5) * (norm_b**0.5))


class RemoteEmbedder:
    """Embeddings over an OpenRouter-compatible HTTP endpoint."""

    def __init__(
        self,
        model: str = DEFAULT_REMOTE_MODEL,
        api_key: str | None = None,
        timeout: float = 90.0,
        url: str = _REMOTE_URL,
    ) -> None:
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.url = url

    def _key(self) -> str:
        key = self.api_key or os.environ.get("OPENROUTER_API_KEY", "")
        if not key:
            raise EmbeddingError("no API key for the remote embedding provider")
        return key.strip()

    def embed(self, texts: Sequence[str]) -> list[Embedding]:
        if not texts:
            return []
        payload = json.dumps(
            {"model": self.model, "input": [_clip(text) for text in texts]}
        ).encode()
        last_error: Exception | None = None
        for attempt in range(4):
            request = urllib.request.Request(
                self.url,
                data=payload,
                headers={
                    "Authorization": f"Bearer {self._key()}",
                    "Content-Type": "application/json",
                },
            )
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    data = json.loads(response.read().decode())
                break
            except urllib.error.HTTPError as exc:
                detail = exc.read().decode(errors="replace")[:200]
                # The free tier cold-starts: the first calls answer 504 while the
                # worker spins up, and the worker stays warm afterwards. A
                # server-side failure is therefore retryable; a rejected request
                # (4xx) is not.
                if exc.code < 500 or attempt >= 3:
                    raise EmbeddingError(
                        f"embedding endpoint returned {exc.code}: {detail}"
                    ) from exc
                last_error = EmbeddingError(f"HTTP {exc.code}: {detail}")
                time.sleep(10.0 * (attempt + 1))
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                last_error = exc
                if attempt < 3:
                    time.sleep(5.0 * (attempt + 1))
        else:
            raise EmbeddingError(f"embedding endpoint failed: {last_error}")
        vectors = data.get("data") or []
        out: list[Embedding] = []
        for item in vectors:
            values = item.get("embedding") or []
            out.append(
                Embedding(
                    values=tuple(float(v) for v in values),
                    provider="remote",
                    model=str(data.get("model") or self.model),
                )
            )
        if len(out) != len(texts):
            raise EmbeddingError(
                f"embedding endpoint returned {len(out)} vectors for {len(texts)} inputs"
            )
        return out


class LocalEmbedder:
    """Embeddings from a local ONNX model (no egress).

    The model directory is expected to hold a ``tokenizer.json`` and an
    ``.onnx`` graph, as produced by the ``bge-small-en-v1.5`` ONNX export.
    """

    def __init__(self, model_dir: Path | None = None) -> None:
        self.model_dir = model_dir or self._discover()
        if self.model_dir is None:
            raise EmbeddingError("no local ONNX embedding model found")
        self._session = None
        self._tokenizer = None

    @staticmethod
    def _discover() -> Path | None:
        override = os.environ.get("VIOLIN_EMBED_MODEL_DIR", "").strip()
        if override:
            path = Path(override).expanduser()
            return path if path.is_dir() else None
        root = DEFAULT_LOCAL_MODEL_DIR
        if not root.is_dir():
            return None
        for candidate in sorted(root.glob("**/snapshots/*")):
            if candidate.is_dir() and any(candidate.glob("*.onnx")):
                return candidate
        return None

    def _ensure(self) -> None:
        if self._session is not None:
            return
        try:
            import onnxruntime  # type: ignore
            from tokenizers import Tokenizer  # type: ignore
        except ImportError as exc:  # pragma: no cover - depends on host env
            raise EmbeddingError(
                "local embedding backend needs onnxruntime and tokenizers"
            ) from exc
        graph = next(iter(sorted(self.model_dir.glob("*.onnx"))), None)
        tokenizer_file = self.model_dir / "tokenizer.json"
        if graph is None or not tokenizer_file.is_file():
            raise EmbeddingError("local embedding model directory is incomplete")
        self._session = onnxruntime.InferenceSession(
            str(graph), providers=["CPUExecutionProvider"]
        )
        self._tokenizer = Tokenizer.from_file(str(tokenizer_file))

    def embed(self, texts: Sequence[str]) -> list[Embedding]:
        if not texts:
            return []
        self._ensure()
        assert self._session is not None and self._tokenizer is not None
        out: list[Embedding] = []
        for text in texts:
            encoded = self._tokenizer.encode(text)
            ids = encoded.ids[:_MAX_SEQUENCE_TOKENS]
            mask = encoded.attention_mask[:_MAX_SEQUENCE_TOKENS]
            inputs: dict[str, object] = {}
            for spec in self._session.get_inputs():
                if "input_ids" in spec.name:
                    inputs[spec.name] = [ids]
                elif "attention" in spec.name:
                    inputs[spec.name] = [mask]
                elif "token_type" in spec.name:
                    inputs[spec.name] = [[0] * len(ids)]
                else:
                    inputs[spec.name] = [ids]
            outputs = self._session.run(None, inputs)
            hidden = outputs[0][0]
            # Mean pooling over the attended tokens, then L2 normalisation.
            weights = mask
            total = float(sum(weights)) or 1.0
            vector = [
                sum(float(hidden[position][dim]) * weights[position] for position in range(len(weights)))
                / total
                for dim in range(hidden.shape[1])
            ]
            norm = sum(v * v for v in vector) ** 0.5 or 1.0
            out.append(
                Embedding(
                    values=tuple(v / norm for v in vector),
                    provider="local",
                    model=self.model_dir.name,
                )
            )
        return out


def _local_available() -> bool:
    """Whether the local ONNX backend can actually run on this host."""
    import importlib.util

    if importlib.util.find_spec("onnxruntime") is None:
        return False
    if importlib.util.find_spec("tokenizers") is None:
        return False
    return LocalEmbedder._discover() is not None


def build_embedder(preferred: str = "auto") -> object:
    """Return an embedder for ``preferred`` (``local``, ``remote`` or ``auto``).

    ``auto`` prefers the local ONNX model so that no target-derived text
    leaves the host, and falls back to the remote endpoint when the local
    runtime is unavailable. ``remote`` forces the endpoint, ``local`` forces
    the ONNX model and fails when it is not usable.
    """
    if preferred == "auto":
        order = ("local", "remote") if _local_available() else ("remote",)
    else:
        order = (preferred,)
    errors: list[str] = []
    for kind in order:
        try:
            if kind == "local":
                return LocalEmbedder()
            return RemoteEmbedder()
        except EmbeddingError as exc:
            errors.append(f"{kind}: {exc}")
    raise EmbeddingError("; ".join(errors) or "no embedding backend available")


def text_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
