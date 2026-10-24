"""Collect every string inside a nested payload, however deeply it is nested."""

from typing import Any


def strings_of(value: Any, *, keys: bool = True, numbers: bool = False) -> list[str]:
    """All strings in ``value``: dict values, list items and (optionally) keys and numbers.

    Walks with a stack instead of recursion, so a payload nested a thousand levels deep cannot
    hide a string from a scan and cannot crash the scanner.
    """
    out: list[str] = []
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            for k, v in reversed(list(item.items())):
                stack.append(v)
                if keys:
                    stack.append(k)
        elif isinstance(item, list | tuple):
            stack.extend(reversed(item))
        elif numbers and isinstance(item, int | float) and not isinstance(item, bool):
            out.append(str(item))
    return out


def exceeds_depth(value: Any, limit: int) -> bool:
    """True if ``value`` is nested more than ``limit`` levels deep (checked without recursion)."""
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, dict | list | tuple):
            if depth >= limit:
                return True
            children = item.values() if isinstance(item, dict) else item
            stack.extend((child, depth + 1) for child in children)
    return False
