"""Small shared helpers used across core/ modules."""
from __future__ import annotations

from typing import Any


def get_ci(row: Any, *names: str, default: Any = None) -> Any:
    """Case-insensitive lookup across dict-like or pandas Series rows.

    Tries each name in order, so a field with more than one accepted
    spelling (e.g. "Status" / "Staus") can be looked up in one call. This
    is what lets the same parsing/classification code accept both the
    offline pipeline's pandas rows (capitalized headers) and the live
    analyzer's lowercased CSV headers without two implementations.
    """
    lower_map = {str(k).lower(): v for k, v in row.items()}
    for name in names:
        key = name.lower()
        if key in lower_map:
            return lower_map[key]
    return default
