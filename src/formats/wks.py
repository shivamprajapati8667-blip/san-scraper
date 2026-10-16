"""Parser for Lotus 1-2-3 Release 1A .WKS spreadsheet format."""

from __future__ import annotations
import struct
from src.formats.base import BaseParser
from src.formats.wks_formula import disassemble_formula
from src.reader import BoundedBinaryReader, BoundsError, TruncationError
from src.models import (
    FileRecoveryResult,
    RecoveredRecord,
    RecordStatus,
    DamageBlock,
    DamageType,
)

class WksParser(BaseParser):
    """
    Defensive parser for Lotus 1-2-3 Release 1A (.WKS) sequential record stream.

    Sequential Record Layout:
      +0x00..+0x02: Opcode (uint16, little-endian)
      +0x02..+0x04: Length N (uint16, little-endian)
      +0x04..+0x04+N: Payload (N bytes)

    Opcodes:
      0x0000: BOF (Beginning of file, length 2, Release 1A version = 0x0404)
      0x0001: EOF (End of file, length 0)
      0x000C: INTEGER cell (format byte, uint16 col, uint16 row, int16 value)
      0x000D: NUMBER cell (format byte, uint16 col, uint16 row, double 64-bit value)
      0x000E: LABEL cell (format byte, uint16 col, uint16 row, align byte, string)
      0x000F: FORMULA cell (inert, formula tree not executed)
    """

    # Authoritative Lotus 1-2-3 Release 1A / WK1 Record Opcodes:
    # Reference: Lotus 1-2-3 File Format Specification; Gnumeric lotus.c; LibreOffice sc/source/filter/lotus
    OPCODE_BOF = 0x0000        # Beginning of file (length 2, Release 1A version = 0x0404)
    OPCODE_EOF = 0x0001        # End of file (length 0)
    OPCODE_COLUMN_WIDTH = 0x0008  # Column width (3 bytes: col uint16, width uint8)
    OPCODE_NAMED_RANGE = 0x000B   # Named range (24 bytes: name 16s, col1 uint16, row1 uint16, col2 uint16, row2 uint16)
    OPCODE_BLANK = 0x000C      # Blank cell (4 bytes payload: format byte, col uint16, row uint16)
    OPCODE_INTEGER = 0x000D    # Integer cell (7 bytes payload: format byte, col uint16, row uint16, int16 val)
    OPCODE_NUMBER = 0x000E     # Floating-point number (13 bytes payload: format byte, col uint16, row uint16, double 64-bit val)
    OPCODE_LABEL = 0x000F      # Label/text string (min 6 bytes: format byte, col uint16, row uint16, align byte, string)
    OPCODE_FORMULA = 0x0010    # Formula cell (inert data: format byte, col uint16, row uint16, 8-byte float result, formula tree)

    # Legacy / Alternate mapping compatibility aliases:
    ALT_OPCODE_INTEGER = 0x000C
    ALT_OPCODE_NUMBER = 0x000D
    ALT_OPCODE_LABEL = 0x000E
    ALT_OPCODE_FORMULA = 0x000F

    WKS_RELEASE_1A_VERSION = 0x0404
    HEADER_SIZE = 4
    MAX_RECORD_LENGTH = 65536
    MAX_RECORDS = 50000

    def __init__(self) -> None:
        # Layer B: Modular decoder registry mapping opcode -> decoder method
        self._registry: dict[int, Any] = {
            self.OPCODE_BOF: self._decode_bof,
            self.OPCODE_COLUMN_WIDTH: self._decode_column_width,
            self.OPCODE_NAMED_RANGE: self._decode_named_range,
            self.OPCODE_BLANK: self._decode_blank,
            self.OPCODE_INTEGER: self._decode_integer,
            self.OPCODE_NUMBER: self._decode_number,
            self.OPCODE_LABEL: self._decode_label,
            self.OPCODE_FORMULA: self._decode_formula,
        }

    def register_decoder(self, opcode: int, decoder_fn: Any) -> None:
        """Allows registering or overriding opcode decoders modularly."""
        self._registry[opcode] = decoder_fn

    # --- Modular Opcode Decoders ---

    def _decode_bof(self, payload_bytes: bytes, errors: list[str]) -> dict[str, Any] | None:
        """Decodes Lotus 1-2-3 BOF (Beginning of File) record."""
        if len(payload_bytes) >= 2:
            ver = struct.unpack("<H", payload_bytes[:2])[0]
            return {
                "record_type": "BOF",
                "version_code": f"0x{ver:04X}",
                "version": ver,
                "is_release_1a": (ver == self.WKS_RELEASE_1A_VERSION),
            }
        errors.append("BOF record payload smaller than 2 bytes")
        return {
            "record_type": "BOF",
            "version_code": None,
            "version": None,
            "is_release_1a": False,
        }

    def _decode_column_width(self, payload_bytes: bytes, errors: list[str]) -> dict[str, Any] | None:
        """Opcode 0x0008: COLUMN_WIDTH (3 bytes payload: col uint16 LE, width uint8)."""
        if len(payload_bytes) == 3:
            col, width = struct.unpack("<HB", payload_bytes)
            return {
                "record_type": "COLUMN_WIDTH",
                "col": col,
                "width": width,
            }
        errors.append(f"Invalid COLUMN_WIDTH payload length: expected 3 bytes, got {len(payload_bytes)}")
        return None

    def _decode_named_range(self, payload_bytes: bytes, errors: list[str]) -> dict[str, Any] | None:
        """Opcode 0x000B: NAMED_RANGE (24 bytes payload: name 16 bytes, col1 uint16, row1 uint16, col2 uint16, row2 uint16)."""
        if len(payload_bytes) == 24:
            raw_name, col1, row1, col2, row2 = struct.unpack("<16sHHHH", payload_bytes)
            # 16-byte name field is ASCII/Latin-1, null-terminated or space/null-padded
            name_bytes = raw_name.split(b"\x00", 1)[0]
            name_str = name_bytes.decode("latin-1", errors="replace").strip()
            return {
                "record_type": "NAMED_RANGE",
                "range_name": name_str,
                "start_col": col1,
                "start_row": row1,
                "end_col": col2,
                "end_row": row2,
            }
        errors.append(f"Invalid NAMED_RANGE payload length: expected 24 bytes, got {len(payload_bytes)}")
        return None

    def _decode_blank(self, payload_bytes: bytes, errors: list[str]) -> dict[str, Any] | None:
        """Opcode 0x000C: BLANK cell (5 bytes payload: format byte, col uint16, row uint16)."""
        if len(payload_bytes) == 5:
            fmt_byte, col, row = struct.unpack("<BHH", payload_bytes[:5])
            return {
                "record_type": "BLANK",
                "col": col,
                "row": row,
                "format_byte": fmt_byte,
            }
        # Fallback to alternate INTEGER mapping if 7 bytes
        if len(payload_bytes) == 7:
            return self._decode_integer(payload_bytes, errors)
        return None

    def _decode_integer(self, payload_bytes: bytes, errors: list[str]) -> dict[str, Any] | None:
        """Opcode 0x000D (or alternate 0x000C): INTEGER cell (7 bytes payload)."""
        if len(payload_bytes) >= 7:
            fmt_byte, col, row, val = struct.unpack("<BHHh", payload_bytes[:7])
            return {
                "record_type": "INTEGER",
                "col": col,
                "row": row,
                "value": val,
                "format_byte": fmt_byte,
            }
        # Fallback to alternate NUMBER mapping if 13 bytes
        if len(payload_bytes) >= 13:
            return self._decode_number(payload_bytes, errors)
        return None

    def _decode_number(self, payload_bytes: bytes, errors: list[str]) -> dict[str, Any] | None:
        """Opcode 0x000E (or alternate 0x000D): NUMBER cell (13 bytes double or 15 bytes float80)."""
        if len(payload_bytes) >= 13:
            fmt_byte, col, row = struct.unpack("<BHH", payload_bytes[:5])
            val = None
            if len(payload_bytes) >= 15:
                try:
                    mantissa, exp_sign = struct.unpack("<QH", payload_bytes[5:15])
                    sign = -1.0 if (exp_sign & 0x8000) else 1.0
                    exp = (exp_sign & 0x7FFF) - 16383
                    if exp == 16384:
                        val = float('nan') if mantissa != 0 else (sign * float('inf'))
                    elif exp == -16383:
                        val = 0.0
                    else:
                        val = sign * (mantissa / (2**63)) * (2.0 ** exp)
                except Exception:
                    val = struct.unpack("<d", payload_bytes[5:13])[0]
            else:
                val = struct.unpack("<d", payload_bytes[5:13])[0]

            return {
                "record_type": "NUMBER",
                "col": col,
                "row": row,
                "value": val,
                "format_byte": fmt_byte,
            }
        # Fallback to alternate LABEL mapping if >= 6 bytes
        if len(payload_bytes) >= 6:
            return self._decode_label(payload_bytes, errors)
        return None

    def _decode_label(self, payload_bytes: bytes, errors: list[str]) -> dict[str, Any] | None:
        """Opcode 0x000F (or alternate 0x000E): LABEL cell (min 6 bytes)."""
        if len(payload_bytes) >= 6:
            fmt_byte, col, row, align_byte = struct.unpack("<BHHB", payload_bytes[:6])
            text_raw = payload_bytes[6:].split(b"\x00", 1)[0]
            text_str = text_raw.decode("latin-1", errors="replace")
            return {
                "record_type": "LABEL",
                "col": col,
                "row": row,
                "align_prefix": chr(align_byte) if 32 <= align_byte <= 126 else "",
                "text": text_str,
                "format_byte": fmt_byte,
            }
        # Fallback to alternate FORMULA mapping if >= 5 bytes
        if len(payload_bytes) >= 5:
            return self._decode_formula(payload_bytes, errors)
        return None

    def _decode_formula(self, payload_bytes: bytes, errors: list[str]) -> dict[str, Any] | None:
        """Opcode 0x0010 (or alternate 0x000F): FORMULA cell (min 5 bytes)."""
        if len(payload_bytes) >= 5:
            fmt_byte, col, row = struct.unpack("<BHH", payload_bytes[:5])
            cached_val = None
            if len(payload_bytes) >= 13:
                try:
                    cached_val = struct.unpack("<d", payload_bytes[5:13])[0]
                except struct.error:
                    cached_val = None

            formula_raw_hex = ""
            formula_len = 0
            decode_status = "raw_preserved"

            formula_tokens = []
            formula_text = None
            formula_unparsed_hex = None

            formula_decode_status = None
            if len(payload_bytes) >= 15:
                formula_len = struct.unpack("<H", payload_bytes[13:15])[0]
                bytecode = payload_bytes[15:15 + formula_len]
                formula_raw_hex = bytecode.hex()
                if len(bytecode) == formula_len:
                    decode_status = "bytecode_preserved"
                    try:
                        disasm = disassemble_formula(bytecode, base_col=col, base_row=row)
                        formula_tokens = disasm.get("formula_tokens", [])
                        formula_text = disasm.get("formula_text")
                        formula_decode_status = disasm.get("formula_decode_status", "disassembled")
                        formula_unparsed_hex = disasm.get("formula_unparsed_hex")
                    except Exception as exc:
                        errors.append(f"Formula disassembly failed: {exc}")
                        formula_decode_status = "formula_disassembly_error"
                else:
                    errors.append(f"Truncated formula bytecode: declared {formula_len} bytes, got {len(bytecode)}")
                    decode_status = "truncated_bytecode"
                    formula_decode_status = "truncated_bytecode"
            else:
                errors.append(f"Short formula payload without bytecode length header ({len(payload_bytes)} < 15)")
                decode_status = "short_formula_payload"
                formula_decode_status = "short_formula_payload"

            res: dict[str, Any] = {
                "record_type": "FORMULA",
                "col": col,
                "row": row,
                "format_byte": fmt_byte,
                "cached_value": cached_val,
                "formula_len": formula_len,
                "formula_raw_hex": formula_raw_hex,
                "formula_tokens": formula_tokens,
                "formula_text": formula_text,
                "formula_decode_status": formula_decode_status,
                "decode_status": decode_status,
            }
            if formula_unparsed_hex:
                res["formula_unparsed_hex"] = formula_unparsed_hex
            return res
        return None

    def _fallback_unknown(self, opcode: int, payload_bytes: bytes, errors: list[str]) -> dict[str, Any]:
        """Layer B fallback: gracefully preserve raw unknown opcode without throwing."""
        return {
            "record_type": f"UNKNOWN_OPCODE_0x{opcode:04X}",
            "decode_status": "raw_preserved",
        }

    def parse(self, filename: str, reader: BoundedBinaryReader) -> FileRecoveryResult:
        file_size = reader.size
        damages: list[DamageBlock] = []
        recovered_records: list[RecoveredRecord] = []
        is_valid_header = False
        saw_bof = False
        saw_eof = False
        version_code = None
        bof_record: RecoveredRecord | None = None

        if file_size < 4:
            # File is smaller than even a 4-byte record header
            raw_bytes = reader.read_bytes(file_size) if file_size > 0 else b""
            damages.append(
                DamageBlock(
                    offset=0,
                    length=file_size,
                    damage_type=DamageType.TRUNCATION,
                    description=f"File smaller than record header ({file_size} < 4)",
                    raw_hex=raw_bytes.hex(),
                    reason="truncated_header",
                )
            )
            return FileRecoveryResult(
                filename=filename,
                format_name="WKS",
                file_size=file_size,
                is_valid_header=False,
                total_records=0,
                recovered_records=[],
                damages=damages,
                metadata={"status": "truncated_header"},
            )

        # Examine BOF record at offset 0
        bof_start = reader.position
        first_opcode = reader.read_u16_le()
        first_len = reader.read_u16_le()

        if first_opcode == self.OPCODE_BOF:
            saw_bof = True
            if reader.remaining < first_len:
                # Truncated BOF payload: fewer than first_len bytes remain
                incomplete_len = reader.remaining
                incomplete_bytes = reader.read_bytes(incomplete_len)
                total_damage_bytes = reader.read_exact(4 + incomplete_len, bof_start)
                damages.append(
                    DamageBlock(
                        offset=bof_start,
                        length=4 + incomplete_len,
                        damage_type=DamageType.TRUNCATION,
                        description=f"BOF record payload truncated (declared {first_len}, got {incomplete_len})",
                        raw_hex=total_damage_bytes.hex(),
                        reason="bof_payload_truncated",
                    )
                )
                return FileRecoveryResult(
                    filename=filename,
                    format_name="WKS",
                    file_size=file_size,
                    is_valid_header=False,
                    total_records=0,
                    recovered_records=[],
                    damages=damages,
                    metadata={"status": "truncated_bof_payload", "saw_bof": True, "saw_eof": False},
                )

            # Full BOF payload available
            bof_payload_bytes = reader.read_bytes(first_len)
            bof_end = reader.position
            errors: list[str] = []

            if first_len >= 2:
                version_code = struct.unpack("<H", bof_payload_bytes[:2])[0]
                if version_code == self.WKS_RELEASE_1A_VERSION:
                    is_valid_header = True
                else:
                    errors.append(f"Unsupported Lotus revision: 0x{version_code:04X}")
                    damages.append(
                        DamageBlock(
                            offset=4,
                            length=2,
                            damage_type=DamageType.INVALID_HEADER,
                            description=f"Unsupported or non-Release 1A Lotus revision: 0x{version_code:04X}",
                            raw_hex=bof_payload_bytes[:2].hex(),
                            reason="unsupported_lotus_revision",
                        )
                    )
                    is_valid_header = True  # Proceed best-effort
            else:
                errors.append(f"BOF payload length {first_len} < 2")

            bof_fields: dict[str, Any] = {
                "opcode": first_opcode,
                "payload_len": first_len,
                "raw_payload": bof_payload_bytes.hex(),
                "raw_hex": bof_payload_bytes.hex(),
                "record_type": "BOF",
                "version_code": f"0x{version_code:04X}" if version_code is not None else None,
                "version": version_code,
                "is_release_1a": (version_code == self.WKS_RELEASE_1A_VERSION),
            }

            bof_record = RecoveredRecord(
                record_id=0,
                status=RecordStatus.COMPLETE if not errors else RecordStatus.PARTIAL,
                byte_range=(bof_start, bof_end),
                fields=bof_fields,
                errors=errors,
            )
        else:
            # File does not begin with BOF opcode 0x0000
            reader.seek(bof_start)

        # Parse sequential records
        rec_idx = 0
        while not reader.is_eof() and rec_idx < self.MAX_RECORDS:
            rec_start = reader.position

            if reader.remaining < 4:
                trunc_len = reader.remaining
                trunc_bytes = reader.read_bytes(trunc_len)
                damages.append(
                    DamageBlock(
                        offset=rec_start,
                        length=trunc_len,
                        damage_type=DamageType.TRUNCATION,
                        description=f"Truncated record header at offset {rec_start} ({trunc_len} bytes left)",
                        raw_hex=trunc_bytes.hex(),
                        reason="truncated_record_header",
                    )
                )
                break

            opcode = reader.read_u16_le()
            payload_len = reader.read_u16_le()

            if payload_len > self.MAX_RECORD_LENGTH:
                damages.append(
                    DamageBlock(
                        offset=rec_start,
                        length=4,
                        damage_type=DamageType.CORRUPT_RECORD,
                        description=f"Record {rec_idx} payload length {payload_len} exceeds limit",
                        raw_hex=reader.read_exact(4, rec_start).hex(),
                        reason="payload_length_exceeds_max",
                    )
                )
                break

            if reader.remaining < payload_len:
                # Payload extends beyond EOF
                rem_len = reader.remaining
                reader.skip(rem_len)
                total_damaged_slice = reader.read_exact(4 + rem_len, rec_start)
                damages.append(
                    DamageBlock(
                        offset=rec_start,
                        length=4 + rem_len,
                        damage_type=DamageType.TRUNCATION,
                        description=f"Record {rec_idx} payload truncated (expected {payload_len}, got {rem_len})",
                        raw_hex=total_damaged_slice.hex(),
                        reason="payload_truncated_before_eof",
                    )
                )
                break

            payload_bytes = reader.read_bytes(payload_len)
            rec_end = reader.position

            if opcode == self.OPCODE_EOF:
                saw_eof = True
                recovered_records.append(
                    RecoveredRecord(
                        record_id=rec_idx,
                        status=RecordStatus.COMPLETE,
                        byte_range=(rec_start, rec_end),
                        fields={
                            "record_type": "EOF",
                            "opcode": opcode,
                            "payload_len": payload_len,
                            "raw_payload": payload_bytes.hex(),
                            "raw_hex": payload_bytes.hex(),
                        },
                    )
                )
                break

            # Layer A: Full raw payload retention for lossless recovery
            raw_payload_hex = payload_bytes.hex()
            fields: dict = {
                "opcode": opcode,
                "payload_len": payload_len,
                "raw_payload": raw_payload_hex,
                "raw_hex": raw_payload_hex,
            }
            errors: list[str] = []

            # Layer B: Modular decoder registry dispatch
            decoder = self._registry.get(opcode)
            if decoder is not None:
                try:
                    decoded_fields = decoder(payload_bytes, errors)
                    if decoded_fields is not None:
                        fields.update(decoded_fields)
                    else:
                        fields.update(self._fallback_unknown(opcode, payload_bytes, errors))
                except Exception as e:
                    errors.append(f"Decoder error on opcode 0x{opcode:04X}: {str(e)}")
                    fields.update({
                        "record_type": f"UNKNOWN_OPCODE_0x{opcode:04X}",
                        "decode_status": "decoder_exception",
                    })
            else:
                fields.update(self._fallback_unknown(opcode, payload_bytes, errors))

            recovered_records.append(
                RecoveredRecord(
                    record_id=rec_idx,
                    status=RecordStatus.COMPLETE,
                    byte_range=(rec_start, rec_end),
                    fields=fields,
                    errors=errors,
                )
            )
            rec_idx += 1

        # Check for trailing bytes after parsing terminates (e.g. after EOF or loop exit)
        if not reader.is_eof():
            trailing_offset = reader.position
            trailing_len = reader.remaining
            trailing_bytes = reader.read_bytes(trailing_len)
            damages.append(
                DamageBlock(
                    offset=trailing_offset,
                    length=trailing_len,
                    damage_type=DamageType.TRAILING_BYTES,
                    description=f"Trailing unparsed bytes after record sequence ({trailing_len} bytes)",
                    raw_hex=trailing_bytes.hex(),
                    reason="trailing_bytes_after_eof" if saw_eof else "unparsed_stream_tail",
                )
            )

        if not saw_eof:
            # Note missing EOF in metadata/diagnostics without fabricating a fake 0-byte damage block
            # If there was unparsed tail, it is already recorded above in damages.
            pass

        return FileRecoveryResult(
            filename=filename,
            format_name="WKS",
            file_size=file_size,
            is_valid_header=is_valid_header,
            total_records=len(recovered_records),
            recovered_records=recovered_records,
            damages=damages,
            metadata={
                "saw_bof": saw_bof,
                "saw_eof": saw_eof,
                "version_code": f"0x{version_code:04X}" if version_code is not None else None,
                "bof_record": bof_record,
            },
        )
