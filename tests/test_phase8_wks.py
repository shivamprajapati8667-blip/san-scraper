"""Phase 8: Round-Trip Binary Re-serialization Tests (WKS)."""

import unittest
import struct
import random
import glob
import os
import hashlib
import json
from pathlib import Path

from src.formats.wks import WksParser
from src.reader import BoundedBinaryReader
from src.formats.wks_writer import (
    serialize_wks,
    serialize_wks_from_dict,
    serialize_wks_from_json,
    verify_semantic_reencoding,
    SerializationError,
)
from src.models import FileRecoveryResult, RecoveredRecord, DamageBlock, DamageType, RecordStatus


def assert_roundtrip(test_case: unittest.TestCase, original_bytes: bytes, filename: str = "test.wks") -> bytes:
    """Helper to parse, serialize, and assert byte-for-byte and SHA-256 equivalence."""
    parser = WksParser()
    res = parser.parse(filename, BoundedBinaryReader(original_bytes))
    rebuilt_bytes = serialize_wks(res)

    test_case.assertEqual(len(rebuilt_bytes), len(original_bytes))
    test_case.assertEqual(rebuilt_bytes, original_bytes)
    test_case.assertEqual(
        hashlib.sha256(rebuilt_bytes).hexdigest(),
        hashlib.sha256(original_bytes).hexdigest(),
    )
    return rebuilt_bytes


class TestPhase8RoundTripSerialization(unittest.TestCase):
    def setUp(self):
        self.parser = WksParser()

    # 1. Real Corpus Verification (17 Files)
    def test_corpus_17_files_roundtrip_byte_exact(self):
        """All 17 real WKS corpus files round-trip byte-identical."""
        files = sorted(set(glob.glob("**/*.wks", recursive=True) + glob.glob("**/*.WKS", recursive=True)))
        self.assertEqual(len(files), 17)

        for p in files:
            with open(p, "rb") as f:
                data = f.read()
            fname = os.path.basename(p)
            with self.subTest(file=fname):
                rebuilt = assert_roundtrip(self, data, fname)
                self.assertEqual(rebuilt, data)

    # 2. Synthetic Corruption Fixtures (from Phase 7)
    def test_phase7_synthetic_fixtures_roundtrip(self):
        """The 15 Phase 7 synthetic corruption fixtures round-trip byte-identical."""
        fixtures = [
            # 1: 1-byte header
            b"\x00",
            # 2: 2-byte header
            b"\x00\x00",
            # 3: 3-byte header
            b"\x00\x00\x02",
            # 4: Incomplete BOF payload
            b"\x00\x00\x02\x00\x04",
            # 5: Unsupported revision
            b"\x00\x00\x02\x00\x00\x05\x01\x00\x00\x00",
            # 6: Truncated record payload
            b"\x00\x00\x02\x00\x04\x04" + b"\x0d\x00\x0a\x00" + b"\x00\x01\x00\x02",
            # 7: Valid record + garbage before EOF
            b"\x00\x00\x02\x00\x04\x04" + b"\x0d\x00\x07\x00\x00\x01\x00\x01\x00\x64\x00" + b"\xDE\xAD\xBE\xEF",
            # 8: EOF + trailing bytes
            b"\x00\x00\x02\x00\x04\x04" + b"\x01\x00\x00\x00" + b"\xAA\xBB\xCC\xDD\xEE\xFF",
            # 9: Excessive payload declared
            b"\x00\x00\x02\x00\x04\x04" + struct.pack("<HH", 0x000C, 65535) + b"\x12\x34\x56\x78",
            # 10: Non-BOF file start
            b"\x99\x99\x04\x00\x01\x02\x03\x04",
            # 11: Truncated next header at file end
            b"\x00\x00\x02\x00\x04\x04" + b"\x01\x00\x00\x00" + b"\x0D\x00",
            # 12: Empty file
            b"",
            # 13: 4-byte invalid start
            b"\x12\x34\x00\x00",
            # 14: Clean sequence
            b"\x00\x00\x02\x00\x04\x04\x08\x00\x03\x00\x02\x00\x0f\x01\x00\x00\x00",
        ]
        for idx, data in enumerate(fixtures, 1):
            with self.subTest(fixture_idx=idx):
                assert_roundtrip(self, data, f"fixture_{idx}.wks")

    # 3. Empty file and short files
    def test_empty_and_short_files(self):
        """0, 1, 2, 3-byte files round-trip byte-exact."""
        for b in [b"", b"\x01", b"\x01\x02", b"\x01\x02\x03"]:
            assert_roundtrip(self, b)

    # 4. Trailing bytes with zeros and non-zeros
    def test_trailing_zeros_and_non_zeros(self):
        """Trailing zeros and arbitrary non-zeros after EOF preserved byte-for-byte."""
        base = b"\x00\x00\x02\x00\x04\x04\x01\x00\x00\x00"
        with_zeros = base + b"\x00\x00\x00\x00"
        with_data = base + b"\x1a\x2b\x3c\x4d\x00\xff"
        assert_roundtrip(self, with_zeros)
        assert_roundtrip(self, with_data)

    # 5. 05_valid.wks record #4 short formula round-trip
    def test_05_valid_record_4_short_formula_roundtrip(self):
        """05_valid.wks Record #4 stays short_formula_payload and round-trips exactly."""
        with open("demo/input/05_valid.wks", "rb") as f:
            data = f.read()
        res = self.parser.parse("05_valid.wks", BoundedBinaryReader(data))
        rec4 = res.recovered_records[4]
        self.assertEqual(rec4.fields["formula_decode_status"], "short_formula_payload")
        rebuilt = serialize_wks(res)
        self.assertEqual(rebuilt, data)

    # 6. JSON round-trip
    def test_json_roundtrip_all_corpus(self):
        """Result -> to_dict -> JSON string -> serialize_wks_from_json == original."""
        files = sorted(set(glob.glob("**/*.wks", recursive=True) + glob.glob("**/*.WKS", recursive=True)))
        for p in files:
            with open(p, "rb") as f:
                data = f.read()
            res = self.parser.parse(os.path.basename(p), BoundedBinaryReader(data))
            json_str = json.dumps(res.to_dict())
            rebuilt = serialize_wks_from_json(json_str)
            self.assertEqual(rebuilt, data)

    # 7. Layer 2 Semantic Re-encoding Check
    def test_layer2_semantic_reencoding_matches(self):
        """Layer 2 re-encoding matches raw bytes across all standard supported records."""
        files = sorted(set(glob.glob("**/*.wks", recursive=True) + glob.glob("**/*.WKS", recursive=True)))
        total_checked = 0
        total_matches = 0
        total_mismatches = 0
        for p in files:
            with open(p, "rb") as f:
                data = f.read()
            res = self.parser.parse(os.path.basename(p), BoundedBinaryReader(data))
            ver = verify_semantic_reencoding(res)
            total_checked += ver["total_checked"]
            total_matches += ver["matches"]
            total_mismatches += len(ver["mismatches"])

        # Exactly 1 known intentional mismatch in corpus: 05_valid.wks Record #4 (13-byte synthetic short formula)
        self.assertEqual(total_mismatches, 1)
        self.assertEqual(total_matches, 11276)
        self.assertEqual(total_checked, 11277)

    # 8. Negative Tests: SerializationError
    def test_negative_overlapping_intervals_raises(self):
        """Overlapping record/damage intervals raise SerializationError."""
        res = FileRecoveryResult(
            filename="overlap.wks",
            format_name="WKS",
            file_size=10,
            is_valid_header=True,
            total_records=2,
            recovered_records=[
                RecoveredRecord(
                    record_id=0,
                    status=RecordStatus.COMPLETE,
                    byte_range=(0, 6),
                    fields={"opcode": 0, "payload_len": 2, "raw_payload": "0404"},
                ),
                RecoveredRecord(
                    record_id=1,
                    status=RecordStatus.COMPLETE,
                    byte_range=(5, 10),  # overlaps with 0..6
                    fields={"opcode": 1, "payload_len": 1, "raw_payload": "00"},
                ),
            ],
        )
        with self.assertRaises(SerializationError):
            serialize_wks(res)

    def test_negative_unrepresented_gap_raises(self):
        """Unrepresented gap between regions raises SerializationError."""
        res = FileRecoveryResult(
            filename="gap.wks",
            format_name="WKS",
            file_size=12,
            is_valid_header=True,
            total_records=2,
            recovered_records=[
                RecoveredRecord(
                    record_id=0,
                    status=RecordStatus.COMPLETE,
                    byte_range=(0, 4),
                    fields={"opcode": 0, "payload_len": 0, "raw_payload": ""},
                ),
                # Gap at offset 4..8
                RecoveredRecord(
                    record_id=1,
                    status=RecordStatus.COMPLETE,
                    byte_range=(8, 12),
                    fields={"opcode": 1, "payload_len": 0, "raw_payload": ""},
                ),
            ],
        )
        with self.assertRaises(SerializationError):
            serialize_wks(res)

    def test_negative_mismatched_payload_length_raises(self):
        """Record raw_payload not matching byte_range raises SerializationError."""
        res = FileRecoveryResult(
            filename="mismatch.wks",
            format_name="WKS",
            file_size=10,
            is_valid_header=True,
            total_records=1,
            recovered_records=[
                RecoveredRecord(
                    record_id=0,
                    status=RecordStatus.COMPLETE,
                    byte_range=(0, 10),
                    fields={"opcode": 0, "payload_len": 2, "raw_payload": "0404"}, # 4 hdr + 2 payload = 6 != 10
                ),
            ],
        )
        with self.assertRaises(SerializationError):
            serialize_wks(res)

    def test_negative_malformed_json_raises(self):
        """Malformed JSON raises SerializationError."""
        with self.assertRaises(SerializationError):
            serialize_wks_from_json("NOT_JSON")

    # 9. Determinism Test
    def test_determinism_serialize_twice(self):
        """Serializing the same result twice produces byte-identical output."""
        with open("demo/input/public_sample.wks", "rb") as f:
            data = f.read()
        res = self.parser.parse("public_sample.wks", BoundedBinaryReader(data))
        out1 = serialize_wks(res)
        out2 = serialize_wks(res)
        self.assertEqual(out1, out2)

    # 10. Massive Seeded Fuzzing (2,000 iterations)
    def test_massive_seeded_fuzz_roundtrip(self):
        """
        2,000 seeded random inputs (varied seeds, with/without BOF, injected byte flips, insertions, truncations).
        Parser must never crash, and serialize(parse(x)) == x.
        """
        # Base templates for mutation
        bof = b"\x00\x00\x02\x00\x04\x04"
        sample_cells = (
            b"\x0d\x00\x07\x00\x00\x01\x00\x01\x00\x2a\x00"
            b"\x0f\x00\x0b\x00\x00\x02\x00\x02\x00\x27WKS1\x00"
            b"\x01\x00\x00\x00"
        )
        template = bof + sample_cells

        for seed in [42, 1337, 2026, 9999]:
            prng = random.Random(seed)
            for _ in range(500):
                mode = prng.randint(0, 5)
                if mode == 0:
                    # Pure random byte stream
                    length = prng.randint(0, 512)
                    data = prng.randbytes(length)
                elif mode == 1:
                    # Random bytes with valid BOF prefix
                    length = prng.randint(0, 512)
                    data = bof + prng.randbytes(length)
                elif mode == 2:
                    # Truncation of valid template at arbitrary offset
                    trunc_off = prng.randint(0, len(template))
                    data = template[:trunc_off]
                elif mode == 3:
                    # Byte flip inside template
                    buf = bytearray(template)
                    flip_pos = prng.randint(0, len(buf) - 1)
                    buf[flip_pos] ^= prng.randint(1, 255)
                    data = bytes(buf)
                elif mode == 4:
                    # Random byte insertion into template
                    buf = bytearray(template)
                    insert_pos = prng.randint(0, len(buf))
                    insert_bytes = prng.randbytes(prng.randint(1, 16))
                    buf[insert_pos:insert_pos] = insert_bytes
                    data = bytes(buf)
                else:
                    # Random deletion from template
                    buf = bytearray(template)
                    del_start = prng.randint(0, len(buf) - 1)
                    del_len = prng.randint(1, min(10, len(buf) - del_start))
                    del buf[del_start:del_start + del_len]
                    data = bytes(buf)

                res = self.parser.parse("fuzz.wks", BoundedBinaryReader(data))
                rebuilt = serialize_wks(res)
                self.assertEqual(len(rebuilt), len(data))
                self.assertEqual(rebuilt, data)


if __name__ == "__main__":
    unittest.main()
