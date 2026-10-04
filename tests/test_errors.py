"""Failure categories shared by every segment (server LLD § Failure Reporting)."""

import re
import types

import pytest

from ghidra_mcp.errors import FixInput, RetryLater, Stop, classify, describe


class FakeJavaException(Exception):
    """Mimics a JPype-wrapped Java exception: getClass().getName() and getMessage()."""

    def __init__(self, java_class, message):
        super().__init__(f"{java_class}: {message}")
        self._java_class = java_class
        self._message = message

    def getClass(self):  # noqa: N802 - Java naming
        return types.SimpleNamespace(getName=lambda: self._java_class)

    def getMessage(self):  # noqa: N802 - Java naming
        return self._message


# @spec SRV-032
@pytest.mark.parametrize(
    ("exc", "category"),
    [
        (FixInput("x"), "fix_input"),
        (RetryLater("x"), "retry_later"),
        (Stop("x"), "stop"),
        (ValueError("x"), "fix_input"),
        (re.error("x"), "fix_input"),
        (FileNotFoundError("x"), "fix_input"),
        (RuntimeError("x"), None),
        (KeyError("x"), None),
    ],
)
def test_classify(exc, category):
    assert classify(exc) == category


def test_fix_input_is_a_value_error_so_existing_handling_stays_valid():
    assert isinstance(FixInput("x"), ValueError)


# @spec WB-023
@pytest.mark.parametrize(
    "java_class",
    ["ghidra.util.exception.InvalidInputException", "ghidra.util.exception.DuplicateNameException"],
)
def test_ghidra_name_rejections_are_fix_input_with_ghidras_reason(java_class):
    exc = FakeJavaException(java_class, "Symbol name already exists: foo")
    assert classify(exc) == "fix_input"
    assert describe(exc) == "Symbol name already exists: foo"


def test_other_java_exceptions_are_unexpected():
    exc = FakeJavaException("java.lang.IllegalStateException", "boom")
    assert classify(exc) is None
