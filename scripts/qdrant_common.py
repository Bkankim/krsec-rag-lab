"""Shared helpers for the Qdrant comparison scripts (issue #6).

numpy and qdrant_client are imported inside functions only, so importing this module works
in the CI environment that has neither.
"""

from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request

DEFAULT_URL = "http://127.0.0.1:16333"
URL_ENV = "KRSEC_QDRANT_URL"


def resolve_url(url: str | None) -> str:
    return (url or os.environ.get(URL_ENV) or DEFAULT_URL).rstrip("/")


def get_json(url: str, path: str) -> dict:
    """GET a Qdrant REST endpoint and return the server's JSON response unchanged."""
    with urllib.request.urlopen(f"{url}{path}", timeout=30) as response:
        return json.load(response)


def server_info(url: str) -> dict:
    return get_json(url, "/")


def collection_info_raw(url: str, name: str) -> dict:
    """Raw ``GET /collections/{name}``, the evidence for indexed_vectors_count."""
    return get_json(url, f"/collections/{name}")


def client_endpoint(url: str) -> dict:
    """Host, port, scheme and prefix of ``url`` the way get_json() reaches it.

    QdrantClient(url=...) substitutes port 6333 when the URL has no port, while urllib uses
    the scheme default (80/443). Passing these explicitly keeps both on one endpoint. An IPv6
    literal keeps its brackets because QdrantClient joins ``host:port`` without adding them.
    """
    parts = urllib.parse.urlsplit(url)
    https = parts.scheme == "https"
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    return {
        "host": host,
        "port": parts.port or (443 if https else 80),
        "https": https,
        "prefix": parts.path.strip("/") or None,
    }


def make_client(url: str):
    from qdrant_client import QdrantClient

    return QdrantClient(**client_endpoint(url), prefer_grpc=False, timeout=120)


def recreate_collection(client, name: str, **kwargs) -> None:
    """Drop and create only the named collection (never touches other collections)."""
    if client.collection_exists(name):
        client.delete_collection(name)
    client.create_collection(collection_name=name, **kwargs)


def wait_until_indexed(url: str, name: str, min_indexed: int = 0, timeout_s: float = 600.0) -> dict:
    """Poll until status is green with at least ``min_indexed`` indexed vectors; return raw info."""
    deadline = time.monotonic() + timeout_s
    while True:
        info = collection_info_raw(url, name)
        result = info["result"]
        indexed = result.get("indexed_vectors_count") or 0
        if (
            result["status"] == "green"
            and result["optimizer_status"] == "ok"
            and indexed >= min_indexed
        ):
            return info
        if time.monotonic() > deadline:
            raise TimeoutError(f"{name} not green after {timeout_s}s: {json.dumps(info)}")
        time.sleep(1.0)
