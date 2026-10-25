import hashlib
import json
from typing import Any, Dict

def compute_arguments_digest(args: Dict[str, Any]) -> str:
    """
    Computes SHA-256 over recursively key-sorted compact JSON arguments.
    Compact JSON uses no whitespace after commas or colons.
    """
    compact_sorted = json.dumps(args, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(compact_sorted.encode("utf-8")).hexdigest().lower()
