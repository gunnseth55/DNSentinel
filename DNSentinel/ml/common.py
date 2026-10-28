"""JSON, hashing and explicit dependency errors shared by M1 commands."""
import hashlib
import json
from pathlib import Path


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, allow_nan=False), encoding="utf-8")


def require_torch():
    try:
        import torch
        return torch
    except ImportError as error:
        raise SystemExit(
            "PyTorch is required. From DNSentinel run:\n"
            ".\\.venv\\Scripts\\python.exe -m pip install -r requirements-gru.txt "
            "--index-url https://download.pytorch.org/whl/cpu"
        ) from error
