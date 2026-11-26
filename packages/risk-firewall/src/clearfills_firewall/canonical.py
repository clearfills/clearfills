"""RFC 8785 (JCS) JSON Canonicalization Scheme implementation.

Provides deterministic, cross-language canonical JSON serialization compliant with
RFC 8785:
- Rejects non-finite floats (NaN, +Infinity, -Infinity).
- Normalizes -0.0 to 0.
- Formats IEEE-754 floats using exact ECMAScript Number::toString(x, 10) shortest
  round-trip decimal representation (e.g. 100.0 -> 100, 1e-6 -> 0.000001, 1e-7 -> 1e-7).
- Escapes strings strictly per RFC 8785 Section 3.2.2.2 (control chars, \\, ", literal UTF-8).
- Sorts object keys by UTF-16 code units (RFC 8785 Section 3.2.3).
"""

from __future__ import annotations

import hashlib
import math
from typing import Any


def _escape_jcs_string(value: str) -> str:
    """Serialize a Python string according to RFC 8785 Section 3.2.2.2."""
    # Reject lone UTF-16 surrogates (invalid UTF-8)
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("RFC 8785 JCS forbids lone UTF-16 surrogates in strings") from exc

    out: list[str] = ['"']
    for ch in value:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif code == 0x08:
            out.append("\\b")
        elif code == 0x09:
            out.append("\\t")
        elif code == 0x0A:
            out.append("\\n")
        elif code == 0x0C:
            out.append("\\f")
        elif code == 0x0D:
            out.append("\\r")
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _format_es6_float(value: float) -> str:
    """Format an IEEE-754 float per ECMAScript Number::toString(x, 10) / RFC 8785."""
    if math.isnan(value) or math.isinf(value):
        raise ValueError(f"RFC 8785 JCS forbids non-finite float value: {value!r}")
    if value == 0.0:
        return "0"

    sign = "-" if value < 0.0 else ""
    x = abs(value)

    # Python 3 repr(float) uses David Gay's shortest round-trip IEEE-754 dtoa algorithm,
    # matching the significant digits of ECMAScript Number::toString(x, 10).
    s = repr(x).lower()
    if "e" in s:
        mantissa, exp_str = s.split("e", 1)
        exp = int(exp_str)
    else:
        mantissa = s
        exp = 0

    if "." in mantissa:
        int_part, frac_part = mantissa.split(".", 1)
    else:
        int_part, frac_part = mantissa, ""

    raw_digits = int_part + frac_part
    stripped_leading = raw_digits.lstrip("0")
    digits = stripped_leading.rstrip("0")
    trailing_zeros = len(stripped_leading) - len(digits)

    k = len(digits)
    n = exp - len(frac_part) + trailing_zeros + k

    if k <= n <= 21:
        formatted = digits + ("0" * (n - k))
    elif 0 < n <= 21:
        formatted = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        formatted = "0." + ("0" * (-n)) + digits
    else:
        exp_val = n - 1
        exp_sign = "+" if exp_val >= 0 else "-"
        exp_digits = str(abs(exp_val))
        if k == 1:
            formatted = f"{digits}e{exp_sign}{exp_digits}"
        else:
            formatted = f"{digits[0]}.{digits[1:]}e{exp_sign}{exp_digits}"

    return sign + formatted


def _utf16_sort_key(key: str) -> bytes:
    """Return UTF-16BE bytes so lexicographic sort matches UTF-16 code unit order."""
    return key.encode("utf-16-be")


def canonical_json(value: Any) -> str:
    """Serialize a JSON-compatible Python value to an RFC 8785 canonical JSON string."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return _format_es6_float(value)
    if isinstance(value, str):
        return _escape_jcs_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    if isinstance(value, dict):
        items: list[tuple[bytes, str, Any]] = []
        for k, v in value.items():
            if not isinstance(k, str):
                raise TypeError(f"RFC 8785 JCS requires string object keys, got {type(k).__name__}")
            # Ensure key is valid UTF-8 before UTF-16 sorting
            try:
                k.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ValueError("RFC 8785 JCS forbids lone UTF-16 surrogates in object keys") from exc
            items.append((_utf16_sort_key(k), k, v))
        items.sort(key=lambda item: item[0])
        return "{" + ",".join(f"{_escape_jcs_string(k)}:{canonical_json(v)}" for _, k, v in items) + "}"
    raise TypeError(f"Value of type {type(value).__name__} is not JSON-serializable under RFC 8785")


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize a JSON-compatible Python value to UTF-8 encoded RFC 8785 JCS bytes."""
    return canonical_json(value).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    """Compute the SHA-256 hex digest of the RFC 8785 JCS canonical encoding of `value`."""
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()
