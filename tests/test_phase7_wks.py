"""Phase 7: Damage Block & Gap Recovery invariants, fixtures, and verification."""

import unittest
import struct
import random
import glob
import os
from pathlib import Path

from src.formats.wks import WksParser
from src.reader import BoundedBinaryReader
from src.models import FileRecoveryResult, DamageType, RecordStatus


def assert_byte_accounting(test_case: unittest.TestCase, file_bytes: bytes, result: FileRecoveryResult) -> dict[str, int]:
    """
    Reusable invariant validator for Phase 7 byte-accounting:
      1. Every byte of file_bytes is accounted for exactly once.
      2. No overlapping intervals.
      3. No unrepresented gaps.
      4. Total file size == sum(recovered_records) + sum(damages) + bof_bytes.
      5. Concatenation in offset order yields byte-exact replica of original input.
    """
    file_size = len(file_bytes)
    test_case.assertEqual(result.file_size, file_size)

    # Collect all contiguous byte intervals: (start, end, raw_bytes, tag)
    intervals = []

    # 1. BOF record (if present)
    bof_rec = result.metadata.get("bof_record")
    bof_bytes_count = 0
    if bof_rec is not None:
        start, end = bof_rec.byte_range
        bof_bytes_count = end - start
        intervals.append((start, end, file_bytes[start:end], "BOF"))

    # 2. Recovered records
    records_bytes_count = 0
    for rec in result.recovered_records:
        start, end = rec.byte_range
        rec_len = end - start
        records_bytes_count += rec_len
        intervals.append((start, end, file_bytes[start:end], f"REC_{rec.record_id}"))

    # 3. Damage blocks (gaps, truncations, corrupted records, trailing bytes)
    damage_bytes_count = 0
    trailing_bytes_count = 0
    for dmg in result.damages:
        start = dmg.offset
        end = dmg.offset + dmg.length
        dmg_len = dmg.length

        # If this damage block is a diagnostic overlay inside the BOF record (e.g. unsupported revision),
        # its bytes are already accounted for by the BOF record interval.
        if bof_rec is not None and bof_rec.byte_range[0] <= start and end <= bof_rec.byte_range[1]:
            continue

        if dmg.damage_type == DamageType.TRAILING_BYTES:
            trailing_bytes_count += dmg_len
        else:
            damage_bytes_count += dmg_len
        # If raw_hex is specified, verify it matches the underlying file bytes
        if dmg.raw_hex is not None:
            test_case.assertEqual(bytes.fromhex(dmg.raw_hex), file_bytes[start:end])
        intervals.append((start, end, file_bytes[start:end], f"DMG_{dmg.damage_type.value}"))

    # Sort intervals strictly by start offset
    intervals.sort(key=lambda item: item[0])

    # Validate continuity, non-overlap, and zero-gap invariants
    curr_offset = 0
    reconstructed_bytes = bytearray()
    for start, end, chunk, tag in intervals:
        test_case.assertEqual(start, curr_offset, f"Gap or misalignment before {tag}: expected {curr_offset}, got {start}")
        test_case.assertGreaterEqual(end, start, f"Inverted range in {tag}: [{start}, {end}]")
        test_case.assertEqual(chunk, file_bytes[start:end], f"Mismatched byte content in {tag}")
        reconstructed_bytes.extend(chunk)
        curr_offset = end

    test_case.assertEqual(curr_offset, file_size, f"Unaccounted trailing gap: covered {curr_offset} of {file_size} bytes")
    test_case.assertEqual(bytes(reconstructed_bytes), file_bytes, "Reconstructed stream != original file bytes")

    # Invariant sums:
    # Total input bytes = bof_bytes_count + records_bytes_count + damage_bytes_count + trailing_bytes_count
    total_accounted = bof_bytes_count + records_bytes_count + damage_bytes_count + trailing_bytes_count
    test_case.assertEqual(total_accounted, file_size)

    return {
        "file_size": file_size,
        "bof_bytes": bof_bytes_count,
        "record_bytes": records_bytes_count,
        "damage_bytes": damage_bytes_count,
        "trailing_bytes": trailing_bytes_count,
        "total_accounted": total_accounted,
        "intervals_count": len(intervals),
    }


class TestPhase7DamageAndGapRecovery(unittest.TestCase):
    def setUp(self):
        self.parser = WksParser()

    # --- 15 Required Synthetic Corruption Fixtures ---

    def test_fixture_01_truncated_header_1_byte(self):
        """Fixture 1: 1-byte truncated file -> DamageBlock with exact byte."""
        data = b"\x00"
        res = self.parser.parse("f01.wks", BoundedBinaryReader(data))
        stats = assert_byte_accounting(self, data, res)
        self.assertEqual(len(res.damages), 1)
        self.assertEqual(res.damages[0].damage_type, DamageType.TRUNCATION)
        self.assertEqual(res.damages[0].raw_hex, "00")

    def test_fixture_02_truncated_header_2_bytes(self):
        """Fixture 2: 2-byte truncated file -> DamageBlock with exact 2 bytes."""
        data = b"\x00\x00"
        res = self.parser.parse("f02.wks", BoundedBinaryReader(data))
        stats = assert_byte_accounting(self, data, res)
        self.assertEqual(len(res.damages), 1)
        self.assertEqual(res.damages[0].damage_type, DamageType.TRUNCATION)
        self.assertEqual(res.damages[0].raw_hex, "0000")

    def test_fixture_03_truncated_header_3_bytes(self):
        """Fixture 3: 3-byte truncated file -> DamageBlock with exact 3 bytes."""
        data = b"\x00\x00\x02"
        res = self.parser.parse("f03.wks", BoundedBinaryReader(data))
        stats = assert_byte_accounting(self, data, res)
        self.assertEqual(len(res.damages), 1)
        self.assertEqual(res.damages[0].damage_type, DamageType.TRUNCATION)
        self.assertEqual(res.damages[0].raw_hex, "000002")

    def test_fixture_04_incomplete_bof_payload_1_byte_remaining(self):
        """Fixture 4: Incomplete BOF header declaring 2 bytes payload but only 1 byte present."""
        data = b"\x00\x00\x02\x00\x04"
        res = self.parser.parse("f04.wks", BoundedBinaryReader(data))
        stats = assert_byte_accounting(self, data, res)
        self.assertEqual(len(res.damages), 1)
        self.assertEqual(res.damages[0].raw_hex, "0000020004")

    def test_fixture_05_malformed_bof_unsupported_revision(self):
        """Fixture 5: Malformed BOF version (e.g. 0x0500 instead of 0x0404) followed by EOF."""
        data = b"\x00\x00\x02\x00\x00\x05\x01\x00\x00\x00"
        res = self.parser.parse("f05.wks", BoundedBinaryReader(data))
        stats = assert_byte_accounting(self, data, res)
        self.assertTrue(any(d.damage_type == DamageType.INVALID_HEADER for d in res.damages))

    def test_fixture_06_payload_extends_beyond_eof(self):
        """Fixture 6: Record header claims 10 bytes payload, but only 4 bytes exist before EOF."""
        bof = b"\x00\x00\x02\x00\x04\x04"
        int_rec_header = b"\x0d\x00\x0a\x00" # opcode 0x000D, payload len 10
        truncated_payload = b"\x00\x01\x00\x02" # only 4 bytes
        data = bof + int_rec_header + truncated_payload
        res = self.parser.parse("f06.wks", BoundedBinaryReader(data))
        stats = assert_byte_accounting(self, data, res)
        self.assertTrue(any(d.damage_type == DamageType.TRUNCATION for d in res.damages))

    def test_fixture_07_valid_record_plus_gap_bytes(self):
        """Fixture 7: Valid record followed by trailing unparsed bytes."""
        bof = b"\x00\x00\x02\x00\x04\x04"
        int_rec = b"\x0d\x00\x07\x00\x00\x01\x00\x01\x00\x64\x00" # 11 bytes
        garbage = b"\xDE\xAD\xBE\xEF"
        data = bof + int_rec + garbage
        res = self.parser.parse("f07.wks", BoundedBinaryReader(data))
        stats = assert_byte_accounting(self, data, res)
        self.assertEqual(len(res.recovered_records), 1)
        self.assertTrue(any(d.damage_type == DamageType.TRUNCATION for d in res.damages))

    def test_fixture_08_valid_eof_plus_trailing_bytes(self):
        """Fixture 8: Complete valid file followed by trailing bytes after EOF."""
        bof = b"\x00\x00\x02\x00\x04\x04"
        eof = b"\x01\x00\x00\x00"
        extra = b"\xAA\xBB\xCC\xDD\xEE\xFF"
        data = bof + eof + extra
        res = self.parser.parse("f08.wks", BoundedBinaryReader(data))
        stats = assert_byte_accounting(self, data, res)
        self.assertEqual(len(res.recovered_records), 1) # EOF
        trailing = [d for d in res.damages if d.damage_type == DamageType.TRAILING_BYTES]
        self.assertEqual(len(trailing), 1)
        self.assertEqual(trailing[0].raw_hex, extra.hex())

    def test_fixture_09_multiple_damage_regions_and_excessive_payload(self):
        """Fixture 9: Header claiming payload > 65536 max record length."""
        bof = b"\x00\x00\x02\x00\x04\x04"
        corrupt_rec = struct.pack("<HH", 0x000C, 65535) + b"\x12\x34\x56\x78"
        data = bof + corrupt_rec
        res = self.parser.parse("f09.wks", BoundedBinaryReader(data))
        stats = assert_byte_accounting(self, data, res)
        self.assertTrue(any(d.damage_type == DamageType.TRUNCATION for d in res.damages))

    def test_fixture_10_damage_at_file_start_non_bof(self):
        """Fixture 10: Non-BOF opcode at file start."""
        garbage = b"\x99\x99\x04\x00\x01\x02\x03\x04"
        res = self.parser.parse("f10.wks", BoundedBinaryReader(garbage))
        stats = assert_byte_accounting(self, garbage, res)
        self.assertEqual(len(res.damages), 1)
        self.assertEqual(res.damages[0].damage_type, DamageType.INVALID_HEADER)

    def test_fixture_11_damage_at_file_end_truncated_record_header(self):
        """Fixture 11: Valid BOF and records followed by 2 bytes of a truncated next header."""
        bof = b"\x00\x00\x02\x00\x04\x04"
        eof = b"\x01\x00\x00\x00"
        trunc_hdr = b"\x0D\x00" # 2 bytes
        data = bof + eof + trunc_hdr
        res = self.parser.parse("f11.wks", BoundedBinaryReader(data))
        stats = assert_byte_accounting(self, data, res)
        self.assertTrue(any(d.damage_type == DamageType.TRAILING_BYTES for d in res.damages))

    def test_fixture_12_empty_file_0_bytes(self):
        """Fixture 12: Completely empty 0-byte file."""
        data = b""
        res = self.parser.parse("f12.wks", BoundedBinaryReader(data))
        stats = assert_byte_accounting(self, data, res)
        self.assertEqual(stats["file_size"], 0)
        self.assertEqual(stats["total_accounted"], 0)

    def test_fixture_13_very_short_file_4_bytes(self):
        """Fixture 13: 4-byte file (header only with 0 length but invalid opcode)."""
        data = b"\x12\x34\x00\x00"
        res = self.parser.parse("f13.wks", BoundedBinaryReader(data))
        stats = assert_byte_accounting(self, data, res)
        self.assertEqual(len(res.damages), 1)

    def test_fixture_14_demo_05_valid_formula_inert_preserved(self):
        """Fixture 14: demo/input/05_valid.wks with inert formula #4 preserved byte-exact."""
        path = "demo/input/05_valid.wks"
        with open(path, "rb") as f:
            data = f.read()
        res = self.parser.parse("05_valid.wks", BoundedBinaryReader(data))
        stats = assert_byte_accounting(self, data, res)
        self.assertEqual(stats["file_size"], 85)
        # Verify Record #4 status remains short_formula_payload
        rec4 = res.recovered_records[4]
        self.assertEqual(rec4.fields["record_type"], "FORMULA")
        self.assertEqual(rec4.fields["formula_decode_status"], "short_formula_payload")
        self.assertEqual(rec4.fields["cached_value"], 140.6)

    def test_fixture_15_named_range_and_column_width_complete_sequence(self):
        """Fixture 15: Clean sequence of BOF, COLWIDTH, NAMED_RANGE, INTEGER, EOF."""
        bof = b"\x00\x00\x02\x00\x04\x04"
        colwidth = b"\x08\x00\x03\x00\x02\x00\x0f" # col 2, width 15
        nrange = b"\x0b\x00\x18\x00" + b"TEST_RANGE\x00\x00\x00\x00\x00\x00" + struct.pack("<HHHH", 0, 0, 1, 1)
        int_rec = b"\x0d\x00\x07\x00\x00\x00\x00\x00\x00\x2a\x00"
        eof = b"\x01\x00\x00\x00"
        data = bof + colwidth + nrange + int_rec + eof
        res = self.parser.parse("f15.wks", BoundedBinaryReader(data))
        stats = assert_byte_accounting(self, data, res)
        self.assertEqual(len(res.recovered_records), 4)
        self.assertEqual(len(res.damages), 0)

    # --- Fuzz / Robustness Testing ---

    def test_seeded_wks_fuzz_byte_accounting_invariance(self):
        """Deterministic seeded fuzzing ensuring parser never crashes and preserves invariant."""
        prng = random.Random(1337)
        for i in range(100):
            size = prng.randint(0, 1024)
            data = bytearray(prng.randbytes(size))
            if prng.choice([True, False]) and size >= 6:
                # Prepend valid BOF
                data[:6] = b"\x00\x00\x02\x00\x04\x04"
            fuzz_bytes = bytes(data)
            res = self.parser.parse(f"fuzz_{i}.wks", BoundedBinaryReader(fuzz_bytes))
            assert_byte_accounting(self, fuzz_bytes, res)

    # --- Real Corpus Verification (17 Files) ---

    def test_real_corpus_17_files_byte_accounting(self):
        """Verify strict byte-accounting across all 17 WKS corpus fixtures."""
        files = sorted(set(glob.glob("**/*.wks", recursive=True) + glob.glob("**/*.WKS", recursive=True)))
        self.assertEqual(len(files), 17)

        for path in files:
            with open(path, "rb") as f:
                data = f.read()
            res = self.parser.parse(os.path.basename(path), BoundedBinaryReader(data))
            stats = assert_byte_accounting(self, data, res)
            self.assertEqual(stats["total_accounted"], stats["file_size"])


if __name__ == "__main__":
    unittest.main()
