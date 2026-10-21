"""Tests for ROM detection and explicitly accepted ROM variants."""

import hashlib

from ebtools.rom import detect


def test_detect_accepts_configured_md5_variant() -> None:
    rom = b"known test ROM bytes"
    digest = hashlib.md5(rom).hexdigest()

    result = detect(rom, "NOT THE HEADER", [digest])

    assert result.matched
    assert not result.header


def test_detect_rejects_unlisted_md5_variant() -> None:
    rom = b"known test ROM bytes"

    result = detect(rom, "NOT THE HEADER", ["00000000000000000000000000000000"])

    assert not result.matched
