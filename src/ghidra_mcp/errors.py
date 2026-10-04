"""
Failure categories shared by every tool (see docs/intent/server/server-design.md § Failure Reporting).

Every tool failure carries exactly one recovery category, telling the caller what to do next:
fix_input (change the request), retry_later (repeat it later), or stop (don't retry).
"""

import re

FIX_INPUT = "fix_input"
RETRY_LATER = "retry_later"
STOP = "stop"

# Ghidra exceptions that mean "the name you supplied was rejected": the caller can fix it.
_NAME_REJECTIONS = {
    "ghidra.util.exception.InvalidInputException",
    "ghidra.util.exception.DuplicateNameException",
}


class ToolFailure(Exception):
    """An anticipated failure whose category is known where it is raised."""

    category = STOP


class FixInput(ToolFailure, ValueError):
    """The caller must change the request. A ValueError, so existing handling stays valid."""

    category = FIX_INPUT


class RetryLater(ToolFailure):
    """The request is valid but the server isn't ready yet; repeat it later."""

    category = RETRY_LATER


class Stop(ToolFailure):
    """Retrying won't help; the failure should be reported or escalated."""

    category = STOP


def _java_class_name(exc: BaseException) -> str | None:
    get_class = getattr(exc, "getClass", None)
    if not callable(get_class):
        return None
    try:
        return str(get_class().getName())
    except Exception:
        return None


def classify(exc: BaseException) -> str | None:
    """Return the recovery category of an anticipated failure, or None if it is unexpected."""
    if isinstance(exc, ToolFailure):
        return exc.category
    if isinstance(exc, (ValueError, re.error, FileNotFoundError)):
        return FIX_INPUT
    if _java_class_name(exc) in _NAME_REJECTIONS:
        return FIX_INPUT
    return None


def describe(exc: BaseException) -> str:
    """Caller-facing text for an anticipated failure (a Java exception's own message)."""
    if _java_class_name(exc) is not None:
        get_message = getattr(exc, "getMessage", None)
        if callable(get_message):
            message = get_message()
            if message:
                return str(message)
    return str(exc)
