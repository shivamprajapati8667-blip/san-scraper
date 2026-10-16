"""Lossless binary serializer and reassembler for Lotus 1-2-3 (.WKS) recovery results."""

from __future__ import annotations
import struct
from typing import Any
from src.models import FileRecoveryResult, RecoveredRecord, DamageBlock, DamageType


class SerializationError(Exception):
    """Raised when recovery result fails structural validation or cannot be serialized losslessly."""
    pass


def serialize_wks(result: FileRecoveryResult) -> bytes:
    """
    Layer 1: Lossless region reassembler.
    Reconstructs exact byte-for-byte stream from recovered records, BOF, and damage/gap blocks.

    Invariants validated before emission:
      - All regions start at offset 0 and end at file_size.
      - Regions are strictly contiguous (no overlapping intervals, no unrepresented gaps).
      - Reconstructed length matches original file size.
    """
    file_size = result.file_size
    if file_size < 0:
        raise SerializationError(f"Negative file size in result: {file_size}")

    if file_size == 0:
        return b""

    # Collect intervals: (start, end, raw_bytes, tag)
    intervals: list[tuple[int, int, bytes, str]] = []

    # 1. BOF record (if present)
    bof_rec: RecoveredRecord | None = result.metadata.get("bof_record")
    if bof_rec is not None:
        start, end = bof_rec.byte_range
        bof_fields = bof_rec.fields
        opcode = bof_fields.get("opcode", 0x0000)
        payload_len = bof_fields.get("payload_len")
        raw_payload_hex = bof_fields.get("raw_payload", "")
        payload_bytes = bytes.fromhex(raw_payload_hex)
        if payload_len is None:
            payload_len = len(payload_bytes)

        header_bytes = struct.pack("<HH", opcode, payload_len)
        full_bof_bytes = header_bytes + payload_bytes
        if len(full_bof_bytes) != (end - start):
            raise SerializationError(
                f"BOF byte length mismatch: range={end - start}, payload={len(full_bof_bytes)}"
            )
        intervals.append((start, end, full_bof_bytes, "BOF"))

    # 2. Recovered records
    for rec in result.recovered_records:
        start, end = rec.byte_range
        rec_fields = rec.fields
        opcode = rec_fields.get("opcode")
        payload_len = rec_fields.get("payload_len")
        raw_payload_hex = rec_fields.get("raw_payload", "")
        payload_bytes = bytes.fromhex(raw_payload_hex)

        if opcode is None:
            raise SerializationError(f"Record {rec.record_id} missing opcode")
        if payload_len is None:
            payload_len = len(payload_bytes)

        header_bytes = struct.pack("<HH", opcode, payload_len)
        full_rec_bytes = header_bytes + payload_bytes
        if len(full_rec_bytes) != (end - start):
            raise SerializationError(
                f"Record {rec.record_id} byte range mismatch: expected {end - start}, got {len(full_rec_bytes)}"
            )
        intervals.append((start, end, full_rec_bytes, f"REC_{rec.record_id}"))

    # 3. Damage blocks
    for idx, dmg in enumerate(result.damages):
        start = dmg.offset
        end = dmg.offset + dmg.length

        # Skip diagnostic overlay damage inside BOF (e.g. invalid revision)
        if bof_rec is not None and bof_rec.byte_range[0] <= start and end <= bof_rec.byte_range[1]:
            continue

        if dmg.raw_hex is None:
            raise SerializationError(f"Damage block {idx} ({dmg.damage_type.value}) missing raw_hex")

        dmg_bytes = bytes.fromhex(dmg.raw_hex)
        if len(dmg_bytes) != dmg.length:
            raise SerializationError(
                f"Damage block {idx} length mismatch: declared {dmg.length}, hex len {len(dmg_bytes)}"
            )
        intervals.append((start, end, dmg_bytes, f"DMG_{dmg.damage_type.value}_{idx}"))

    # Sort strictly by start offset
    intervals.sort(key=lambda item: item[0])

    # Invariant validation
    curr = 0
    buffer = bytearray()
    for start, end, chunk, tag in intervals:
        if start < curr:
            raise SerializationError(f"Overlapping interval at offset {start} for {tag} (previous ended at {curr})")
        if start > curr:
            raise SerializationError(f"Unrepresented gap between offset {curr} and {start} before {tag}")
        if len(chunk) != (end - start):
            raise SerializationError(f"Chunk byte length {len(chunk)} does not match range [{start}, {end}] for {tag}")

        buffer.extend(chunk)
        curr = end

    if curr != file_size:
        raise SerializationError(f"Final output size {curr} does not match expected file size {file_size}")

    return bytes(buffer)


# ---------------------------------------------------------------------------
# Layer 2: Semantic re-encoding verification
# ---------------------------------------------------------------------------

def encode_record_payload(rec: RecoveredRecord) -> bytes | None:
    """
    Re-encode a recovered record's payload from its decoded semantic fields.
    Returns bytes if the record type is supported and fields are complete, or None if skipped/unknown.
    """
    rec_type = rec.fields.get("record_type")
    fields = rec.fields

    if rec_type == "EOF":
        return b""

    if rec_type == "BLANK":
        fmt = fields.get("format_byte", 0)
        col = fields.get("col", 0)
        row = fields.get("row", 0)
        return struct.pack("<BHH", fmt, col, row)

    if rec_type == "INTEGER":
        fmt = fields.get("format_byte", 0)
        col = fields.get("col", 0)
        row = fields.get("row", 0)
        val = fields.get("value", 0)
        return struct.pack("<BHHh", fmt, col, row, val)

    if rec_type == "NUMBER":
        fmt = fields.get("format_byte", 0)
        col = fields.get("col", 0)
        row = fields.get("row", 0)
        val = fields.get("value", 0.0)
        if val is None:
            return None
        return struct.pack("<BHHd", fmt, col, row, float(val))

    if rec_type == "LABEL":
        fmt = fields.get("format_byte", 0)
        col = fields.get("col", 0)
        row = fields.get("row", 0)
        align_str = fields.get("align_prefix", "'")
        align_byte = ord(align_str) if align_str else ord("'")
        text_str = fields.get("text", "")
        text_bytes = text_str.encode("latin-1") + b"\x00"
        return struct.pack("<BHHB", fmt, col, row, align_byte) + text_bytes

    if rec_type == "COLUMN_WIDTH":
        col = fields.get("col", 0)
        width = fields.get("width", 0)
        return struct.pack("<HB", col, width)

    if rec_type == "NAMED_RANGE":
        name = fields.get("range_name", "")
        # Name is 16 bytes null padded
        name_bytes = name.encode("latin-1")
        name_bytes = name_bytes.ljust(16, b"\x00")[:16]
        c1 = fields.get("start_col", 0)
        r1 = fields.get("start_row", 0)
        c2 = fields.get("end_col", 0)
        r2 = fields.get("end_row", 0)
        return struct.pack("<16sHHHH", name_bytes, c1, r1, c2, r2)

    if rec_type == "FORMULA":
        fmt = fields.get("format_byte", 0)
        col = fields.get("col", 0)
        row = fields.get("row", 0)
        val = fields.get("cached_value")
        if val is None:
            val = 0.0
        formula_raw_hex = fields.get("formula_raw_hex", "")
        bytecode = bytes.fromhex(formula_raw_hex)
        header = struct.pack("<BHHdH", fmt, col, row, float(val), len(bytecode))
        return header + bytecode

    return None


def verify_semantic_reencoding(result: FileRecoveryResult) -> dict[str, Any]:
    """
    Verification-only semantic re-encoding check (Layer 2).
    Compares payload re-encoded from fields against stored raw_payload.
    Does NOT modify the result.
    """
    total_checked = 0
    matches = 0
    mismatches: list[dict[str, Any]] = []
    stats_by_opcode: dict[int, dict[str, int]] = {}

    records_to_check = list(result.recovered_records)
    bof = result.metadata.get("bof_record")
    if bof is not None:
        records_to_check.insert(0, bof)

    for rec in records_to_check:
        opcode = rec.fields.get("opcode")
        if opcode not in stats_by_opcode:
            stats_by_opcode[opcode] = {"checked": 0, "matched": 0, "mismatched": 0}

        reencoded = encode_record_payload(rec)
        if reencoded is None:
            continue

        raw_payload = bytes.fromhex(rec.fields.get("raw_payload", ""))
        stats_by_opcode[opcode]["checked"] += 1
        total_checked += 1

        if reencoded == raw_payload:
            stats_by_opcode[opcode]["matched"] += 1
            matches += 1
        else:
            stats_by_opcode[opcode]["mismatched"] += 1
            mismatches.append({
                "record_id": rec.record_id,
                "opcode": f"0x{opcode:04X}" if opcode is not None else None,
                "offset": rec.byte_range[0],
                "expected_hex": raw_payload.hex(),
                "reencoded_hex": reencoded.hex(),
            })

    return {
        "total_checked": total_checked,
        "matches": matches,
        "mismatches": mismatches,
        "by_opcode": stats_by_opcode,
    }


def serialize_wks_from_dict(data: dict[str, Any]) -> bytes:
    """
    Reconstruct raw WKS bytes losslessly from a saved per-file analysis JSON dictionary.
    Rejects malformed or hostile JSON dictionaries with SerializationError.
    """
    if not isinstance(data, dict):
        raise SerializationError("Expected a JSON dictionary representing FileRecoveryResult")

    file_size = data.get("file_size")
    if file_size is None or not isinstance(file_size, int) or file_size < 0:
        raise SerializationError(f"Invalid file_size in JSON: {file_size}")

    if file_size == 0:
        return b""

    intervals: list[tuple[int, int, bytes, str]] = []

    # 1. BOF record
    metadata = data.get("metadata", {})
    if not isinstance(metadata, dict):
        raise SerializationError("Invalid metadata dictionary in JSON")

    bof_dict = metadata.get("bof_record")
    if bof_dict is not None:
        if not isinstance(bof_dict, dict):
            raise SerializationError("Invalid bof_record in metadata")
        byte_range = bof_dict.get("byte_range")
        if not byte_range or len(byte_range) != 2:
            raise SerializationError("Invalid byte_range in bof_record")
        start, end = byte_range
        bof_data = bof_dict.get("data", {})
        opcode = bof_data.get("opcode", 0x0000)
        payload_len = bof_data.get("payload_len")
        raw_payload_hex = bof_data.get("raw_payload", "")
        payload_bytes = bytes.fromhex(raw_payload_hex)
        if payload_len is None:
            payload_len = len(payload_bytes)

        header_bytes = struct.pack("<HH", opcode, payload_len)
        full_bof_bytes = header_bytes + payload_bytes
        if len(full_bof_bytes) != (end - start):
            raise SerializationError(f"BOF byte length mismatch in JSON: range={end - start}, payload={len(full_bof_bytes)}")
        intervals.append((start, end, full_bof_bytes, "BOF"))

    # 2. Records
    records_list = data.get("records", [])
    if not isinstance(records_list, list):
        raise SerializationError("Invalid records list in JSON")

    for rec in records_list:
        if not isinstance(rec, dict):
            raise SerializationError("Invalid record entry in JSON")
        byte_range = rec.get("byte_range")
        if not byte_range or len(byte_range) != 2:
            raise SerializationError("Invalid byte_range in record")
        start, end = byte_range
        rec_data = rec.get("data", {})
        opcode = rec_data.get("opcode")
        payload_len = rec_data.get("payload_len")
        raw_payload_hex = rec_data.get("raw_payload", "")
        payload_bytes = bytes.fromhex(raw_payload_hex)
        if opcode is None:
            raise SerializationError("Record missing opcode in JSON")
        if payload_len is None:
            payload_len = len(payload_bytes)

        header_bytes = struct.pack("<HH", opcode, payload_len)
        full_rec_bytes = header_bytes + payload_bytes
        if len(full_rec_bytes) != (end - start):
            raise SerializationError(f"Record range mismatch in JSON: expected {end - start}, got {len(full_rec_bytes)}")
        intervals.append((start, end, full_rec_bytes, f"REC_{rec.get('id')}"))

    # 3. Damages
    damages_list = data.get("damages", [])
    if not isinstance(damages_list, list):
        raise SerializationError("Invalid damages list in JSON")

    for idx, dmg in enumerate(damages_list):
        if not isinstance(dmg, dict):
            raise SerializationError("Invalid damage entry in JSON")
        offset = dmg.get("offset")
        length = dmg.get("length")
        raw_hex = dmg.get("raw_hex")
        if offset is None or length is None:
            raise SerializationError("Damage entry missing offset or length")
        start = offset
        end = offset + length

        # Skip BOF internal overlay
        if bof_dict is not None:
            b_range = bof_dict.get("byte_range")
            if b_range and b_range[0] <= start and end <= b_range[1]:
                continue

        if raw_hex is None:
            raise SerializationError(f"Damage block {idx} missing raw_hex in JSON")
        dmg_bytes = bytes.fromhex(raw_hex)
        if len(dmg_bytes) != length:
            raise SerializationError(f"Damage block {idx} length mismatch: declared {length}, got {len(dmg_bytes)}")
        intervals.append((start, end, dmg_bytes, f"DMG_{idx}"))

    # Sort strictly by start offset
    intervals.sort(key=lambda item: item[0])

    curr = 0
    buffer = bytearray()
    for start, end, chunk, tag in intervals:
        if start < curr:
            raise SerializationError(f"Overlapping interval at offset {start} for {tag}")
        if start > curr:
            raise SerializationError(f"Unrepresented gap between offset {curr} and {start} before {tag}")
        if len(chunk) != (end - start):
            raise SerializationError(f"Chunk byte length {len(chunk)} does not match range [{start}, {end}] for {tag}")
        buffer.extend(chunk)
        curr = end

    if curr != file_size:
        raise SerializationError(f"Final output size {curr} does not match expected file size {file_size}")

    return bytes(buffer)


def serialize_wks_from_json(json_str: str) -> bytes:
    """Parse JSON string and reconstruct raw WKS bytes losslessly."""
    import json
    try:
        data = json.loads(json_str)
    except Exception as e:
        raise SerializationError(f"Malformed JSON: {e}") from e
    return serialize_wks_from_dict(data)

