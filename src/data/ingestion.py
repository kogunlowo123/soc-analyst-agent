"""Document ingestion pipeline for the INDEXED data lane.

Accepts documents from multiple sources, extracts text, chunks
semantically, generates embeddings, and stores vectors with metadata.
Deduplication is via content hashing (SHA-256 of normalised text).
"""

from __future__ import annotations

import hashlib
import io
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

import httpx
import structlog

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Protocols for pluggable backends
# ---------------------------------------------------------------------------


class EmbeddingProvider(Protocol):
    """Generates vector embeddings from text chunks."""

    async def embed(self, texts: list[str]) -> list[list[float]]: ...


class VectorStore(Protocol):
    """Stores and retrieves vector chunks."""

    async def upsert(self, documents: list[dict[str, Any]]) -> int: ...
    async def exists(self, content_hash: str) -> bool: ...


# ---------------------------------------------------------------------------
# Text extraction
# ---------------------------------------------------------------------------


def _extract_text_from_markdown(content: bytes) -> str:
    return content.decode("utf-8", errors="replace")


def _extract_text_from_html(content: bytes) -> str:
    text = content.decode("utf-8", errors="replace")
    text = re.sub(r"<script[^>]*>.*?</script>", "", text, flags=re.DOTALL)
    text = re.sub(r"<style[^>]*>.*?</style>", "", text, flags=re.DOTALL)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _extract_text_from_json(content: bytes) -> str:
    import json as _json

    data = _json.loads(content)
    return _json.dumps(data, indent=2, ensure_ascii=False)


def _extract_text_from_pdf(content: bytes) -> str:
    """Extract text from a PDF.  Uses pdfplumber if available, otherwise
    falls back to a simple binary-string extraction."""
    try:
        import pdfplumber

        with pdfplumber.open(io.BytesIO(content)) as pdf:
            pages = [page.extract_text() or "" for page in pdf.pages]
            return "\n\n".join(pages)
    except ImportError:
        logger.warning("pdfplumber_not_installed_falling_back")
        text = content.decode("latin-1", errors="replace")
        return re.sub(r"[^\x20-\x7E\n]", "", text)


def _extract_text_from_docx(content: bytes) -> str:
    """Extract text from a DOCX file."""
    try:
        import docx as _docx

        doc = _docx.Document(io.BytesIO(content))
        return "\n\n".join(p.text for p in doc.paragraphs if p.text.strip())
    except ImportError:
        logger.warning("python-docx_not_installed")
        return ""


_EXTRACTORS: dict[str, Any] = {
    ".md": _extract_text_from_markdown,
    ".markdown": _extract_text_from_markdown,
    ".txt": _extract_text_from_markdown,
    ".html": _extract_text_from_html,
    ".htm": _extract_text_from_html,
    ".json": _extract_text_from_json,
    ".pdf": _extract_text_from_pdf,
    ".docx": _extract_text_from_docx,
}


def extract_text(file_path: str, content: bytes) -> str:
    """Dispatch to the correct extractor based on file extension."""
    ext = Path(file_path).suffix.lower()
    extractor = _EXTRACTORS.get(ext)
    if extractor is None:
        logger.warning("no_extractor_for_extension", ext=ext)
        return content.decode("utf-8", errors="replace")
    return extractor(content)


# ---------------------------------------------------------------------------
# Semantic chunking
# ---------------------------------------------------------------------------

_DEFAULT_CHUNK_SIZE = 512  # tokens (approx 4 chars/token)
_DEFAULT_OVERLAP = 64


def _approximate_token_count(text: str) -> int:
    return max(1, len(text) // 4)


def chunk_text(
    text: str,
    chunk_size: int = _DEFAULT_CHUNK_SIZE,
    overlap: int = _DEFAULT_OVERLAP,
) -> list[str]:
    """Split text into overlapping chunks at sentence boundaries.

    Chunks target ``chunk_size`` tokens with ``overlap`` tokens of
    context carried from the previous chunk.
    """
    sentences = re.split(r"(?<=[.!?])\s+", text)
    chunks: list[str] = []
    current_chunk: list[str] = []
    current_tokens = 0

    for sentence in sentences:
        sentence_tokens = _approximate_token_count(sentence)
        if current_tokens + sentence_tokens > chunk_size and current_chunk:
            chunks.append(" ".join(current_chunk))

            # Build overlap from the tail
            overlap_chunk: list[str] = []
            overlap_tokens = 0
            for s in reversed(current_chunk):
                t = _approximate_token_count(s)
                if overlap_tokens + t > overlap:
                    break
                overlap_chunk.insert(0, s)
                overlap_tokens += t

            current_chunk = overlap_chunk
            current_tokens = overlap_tokens

        current_chunk.append(sentence)
        current_tokens += sentence_tokens

    if current_chunk:
        chunks.append(" ".join(current_chunk))

    return chunks


# ---------------------------------------------------------------------------
# Content hashing (deduplication)
# ---------------------------------------------------------------------------

def content_hash(text: str) -> str:
    """SHA-256 of whitespace-normalised text."""
    normalised = re.sub(r"\s+", " ", text.strip())
    return hashlib.sha256(normalised.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Ingestion pipeline
# ---------------------------------------------------------------------------

@dataclass
class IngestionResult:
    """Summary of a single ingestion run."""

    total_documents: int = 0
    chunks_created: int = 0
    chunks_deduplicated: int = 0
    errors: list[str] = field(default_factory=list)


class IngestionPipeline:
    """Orchestrates extraction, chunking, embedding, and storage.

    Args:
        embedding_provider: Generates vector embeddings.
        vector_store: Stores the resulting chunks.
        chunk_size: Target chunk size in approximate tokens.
        chunk_overlap: Overlap between adjacent chunks.
    """

    def __init__(
        self,
        embedding_provider: EmbeddingProvider,
        vector_store: VectorStore,
        chunk_size: int = _DEFAULT_CHUNK_SIZE,
        chunk_overlap: int = _DEFAULT_OVERLAP,
    ) -> None:
        self._embedder = embedding_provider
        self._store = vector_store
        self._chunk_size = chunk_size
        self._chunk_overlap = chunk_overlap

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def ingest_file(
        self,
        file_path: str,
        metadata: dict[str, Any] | None = None,
    ) -> IngestionResult:
        """Ingest a single file from disk."""
        meta = metadata or {}
        result = IngestionResult(total_documents=1)

        try:
            raw = Path(file_path).read_bytes()
            text = extract_text(file_path, raw)
            if not text.strip():
                result.errors.append(f"Empty text after extraction: {file_path}")
                return result

            chunks = chunk_text(text, self._chunk_size, self._chunk_overlap)
            await self._embed_and_store(chunks, {**meta, "source": file_path}, result)
        except Exception as exc:
            logger.error("ingest_file_failed", file=file_path, error=str(exc))
            result.errors.append(f"{file_path}: {exc}")

        return result

    async def ingest_url(
        self,
        url: str,
        metadata: dict[str, Any] | None = None,
    ) -> IngestionResult:
        """Download a URL and ingest its content."""
        meta = metadata or {}
        result = IngestionResult(total_documents=1)

        try:
            async with httpx.AsyncClient(timeout=30, follow_redirects=True) as c:
                resp = await c.get(url)
                resp.raise_for_status()
                content_type = resp.headers.get("content-type", "")
                raw = resp.content

            if "html" in content_type:
                text = _extract_text_from_html(raw)
                ext = ".html"
            elif "json" in content_type:
                text = _extract_text_from_json(raw)
                ext = ".json"
            elif "pdf" in content_type:
                text = _extract_text_from_pdf(raw)
                ext = ".pdf"
            else:
                text = raw.decode("utf-8", errors="replace")
                ext = ".txt"

            if not text.strip():
                result.errors.append(f"Empty text after extraction: {url}")
                return result

            chunks = chunk_text(text, self._chunk_size, self._chunk_overlap)
            await self._embed_and_store(chunks, {**meta, "source": url, "format": ext}, result)
        except Exception as exc:
            logger.error("ingest_url_failed", url=url, error=str(exc))
            result.errors.append(f"{url}: {exc}")

        return result

    async def ingest_batch(
        self,
        documents: list[dict[str, Any]],
    ) -> IngestionResult:
        """Ingest a batch of pre-extracted documents.

        Each dict must have ``text`` and may have ``metadata``.
        """
        result = IngestionResult(total_documents=len(documents))

        for doc in documents:
            text = doc.get("text", "")
            meta = doc.get("metadata", {})
            if not text.strip():
                result.errors.append("Skipped empty document")
                continue
            chunks = chunk_text(text, self._chunk_size, self._chunk_overlap)
            await self._embed_and_store(chunks, meta, result)

        return result

    async def sync_source(
        self,
        source_config: dict[str, Any],
    ) -> IngestionResult:
        """Pull documents from a configured source and ingest them.

        ``source_config`` must contain at least ``type`` (confluence,
        sharepoint, mitre_attack, nvd) and any connection parameters.
        """
        source_type = source_config.get("type", "")
        logger.info("sync_source_start", type=source_type)

        if source_type == "confluence":
            from .connectors.confluence import ConfluenceConnector

            connector = ConfluenceConnector.from_config(source_config)
            documents = await connector.fetch_all()
        elif source_type == "sharepoint":
            from .connectors.sharepoint import SharePointConnector

            connector = SharePointConnector.from_config(source_config)
            documents = await connector.fetch_all()
        elif source_type == "mitre_attack":
            from .connectors.mitre_attack import MitreAttackConnector

            connector = MitreAttackConnector()
            documents = await connector.fetch_all()
        elif source_type == "nvd":
            from .connectors.nvd import NVDConnector

            connector = NVDConnector.from_config(source_config)
            documents = await connector.fetch_all()
        else:
            return IngestionResult(errors=[f"Unknown source type: {source_type}"])

        return await self.ingest_batch(documents)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _embed_and_store(
        self,
        chunks: list[str],
        metadata: dict[str, Any],
        result: IngestionResult,
    ) -> None:
        """Deduplicate, embed, and store chunks."""
        new_chunks: list[str] = []
        new_hashes: list[str] = []

        for chunk in chunks:
            h = content_hash(chunk)
            if await self._store.exists(h):
                result.chunks_deduplicated += 1
                continue
            new_chunks.append(chunk)
            new_hashes.append(h)

        if not new_chunks:
            return

        embeddings = await self._embedder.embed(new_chunks)

        docs_to_store: list[dict[str, Any]] = []
        for chunk_text_val, embedding, h in zip(new_chunks, embeddings, new_hashes):
            docs_to_store.append(
                {
                    "content_hash": h,
                    "text": chunk_text_val,
                    "embedding": embedding,
                    "metadata": {
                        **metadata,
                        "ingested_at": datetime.now(timezone.utc).isoformat(),
                    },
                }
            )

        stored = await self._store.upsert(docs_to_store)
        result.chunks_created += stored
        logger.info(
            "chunks_stored",
            new=stored,
            deduped=result.chunks_deduplicated,
            source=metadata.get("source", "unknown"),
        )
