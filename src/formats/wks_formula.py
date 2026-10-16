"""Lotus 1-2-3 (.WKS) formula RPN tokenizer and human-readable disassembler.

This module provides semantic interpretation (Layer B) for Lotus 1-2-3 Release 1A
formula bytecode.

Architectural invariants:
- Lossless preservation: raw bytecode is NEVER modified, discarded, or overwritten.
- Robust isolation: failures in tokenization or expression rendering return explicit
  status codes and never raise unhandled exceptions.
- Derived data: tokens and human-readable formula text are purely auxiliary.
"""

from __future__ import annotations

import struct
from typing import Any


def _col_to_letter(col: int) -> str:
    """Convert a 0-indexed column integer to spreadsheet letters (0 -> A, 25 -> Z, 26 -> AA)."""
    s = ""
    col += 1
    while col > 0:
        col, rem = divmod(col - 1, 26)
        s = chr(65 + rem) + s
    return s


def _format_cell(col: int, row: int, is_rel_col: bool, is_rel_row: bool) -> str:
    """Format cell coordinates into standard notation (e.g. A1, $A$1, A$1, $A1)."""
    col_str = _col_to_letter(col) if is_rel_col else f"${_col_to_letter(col)}"
    row_str = str(row + 1) if is_rel_row else f"${row + 1}"
    return f"{col_str}{row_str}"


def _decode_col_coord(raw_val: int, base_col: int) -> tuple[bool, int]:
    """Decode a 16-bit column coordinate word.

    Bit 15 (0x8000) indicates relative addressing.
    In relative mode, the lower byte is an 8-bit signed offset (-128..127).
    In absolute mode, the lower byte is an unsigned 8-bit column index (0..255).
    """
    is_rel = bool(raw_val & 0x8000)
    if is_rel:
        low_byte = raw_val & 0xFF
        offset = low_byte - 256 if low_byte >= 128 else low_byte
        return True, base_col + offset
    return False, raw_val & 0xFF


def _decode_row_coord(raw_val: int, base_row: int) -> tuple[bool, int]:
    """Decode a 16-bit row coordinate word.

    Bit 15 (0x8000) indicates relative addressing.
    In relative mode, bits 0..13 represent a 14-bit signed offset.
    In absolute mode, bits 0..13 represent a 14-bit 0-indexed row index.
    """
    is_rel = bool(raw_val & 0x8000)
    if is_rel:
        offset = raw_val & 0x3FFF
        if offset & 0x2000:
            offset -= 0x4000
        return True, base_row + offset
    return False, raw_val & 0x3FFF


# Opcode definitions and arities
OPERATOR_SYMBOLS: dict[int, tuple[str, int]] = {
    0x08: ("-", 1),       # Unary minus
    0x09: ("+", 2),       # Addition
    0x0A: ("-", 2),       # Subtraction
    0x0B: ("*", 2),       # Multiplication
    0x0C: ("/", 2),       # Division
    0x0D: ("^", 2),       # Exponentiation
    0x0E: ("=", 2),       # Equal
    0x0F: ("<>", 2),      # Not equal
    0x10: ("<=", 2),      # Less than or equal
    0x11: (">=", 2),      # Greater than or equal
    0x12: ("<", 2),       # Less than
    0x13: (">", 2),       # Greater than
    0x14: ("#AND#", 2),   # Logical AND
    0x15: ("#OR#", 2),    # Logical OR
    0x16: ("#NOT#", 1),   # Logical NOT
    0x17: ("+", 1),       # Unary plus
}

FIXED_FUNCTIONS: dict[int, tuple[str, int]] = {
    0x1F: ("@NA", 0),
    0x20: ("@ERR", 0),
    0x21: ("@ABS", 1),
    0x22: ("@INT", 1),
    0x23: ("@SQRT", 1),
    0x24: ("@LOG", 1),
    0x25: ("@LN", 1),
    0x26: ("@PI", 0),
    0x27: ("@SIN", 1),
    0x28: ("@COS", 1),
    0x29: ("@TAN", 1),
    0x2A: ("@ATAN2", 2),
    0x2B: ("@ATAN", 1),
    0x2C: ("@ASIN", 1),
    0x2D: ("@ACOS", 1),
    0x2E: ("@EXP", 1),
    0x2F: ("@MOD", 2),
    0x30: ("@CHOOSE", 1),
    0x31: ("@ISNA", 1),
    0x32: ("@ISERR", 1),
    0x33: ("@FALSE", 0),
    0x34: ("@TRUE", 0),
    0x35: ("@RAND", 0),
    0x36: ("@DATE", 3),
    0x37: ("@TODAY", 0),
    0x38: ("@PMT", 3),
    0x39: ("@PV", 3),
    0x3A: ("@FV", 3),
    0x3B: ("@IF", 3),
    0x3C: ("@DAY", 1),
    0x3D: ("@MONTH", 1),
    0x3E: ("@YEAR", 1),
    0x3F: ("@ROUND", 2),
    0x40: ("@TIME", 3),
    0x41: ("@HOUR", 1),
    0x42: ("@MINUTE", 1),
    0x43: ("@SECOND", 1),
    0x44: ("@ISNUMBER", 1),
    0x45: ("@ISSTRING", 1),
    0x46: ("@LENGTH", 1),
    0x47: ("@VALUE", 1),
    0x55: ("@VLOOKUP", 3),
    0x5B: ("@DSUM", 3),
}

MULTI_FUNCTIONS: dict[int, str] = {
    0x50: "@SUM",
    0x51: "@AVG",
    0x52: "@COUNT",
    0x53: "@MIN",
    0x54: "@MAX",
    0x56: "@STD",
    0x57: "@NPV",
    0x58: "@VAR",
}


def tokenize_formula(bytecode: bytes, base_col: int = 0, base_row: int = 0) -> tuple[list[dict[str, Any]], bytes]:
    """Tokenize Lotus 1-2-3 formula bytecode into structured RPN tokens.

    Returns:
        tuple[list[dict], bytes]: (tokens, unparsed_trailing_bytes)
    """
    tokens: list[dict[str, Any]] = []
    idx = 0
    total_len = len(bytecode)

    while idx < total_len:
        op = bytecode[idx]

        # 0x00: Constant (8-byte IEEE double)
        if op == 0x00:
            if idx + 9 <= total_len:
                raw_chunk = bytecode[idx:idx + 9]
                val = struct.unpack("<d", raw_chunk[1:9])[0]
                tokens.append({
                    "opcode": op,
                    "kind": "CONSTANT",
                    "value": val,
                    "text": f"{val:g}",
                    "raw_hex": raw_chunk.hex(),
                })
                idx += 9
            else:
                break

        # 0x01: Variable / Cell reference (4 bytes: uint16 col, uint16 row)
        elif op == 0x01:
            if idx + 5 <= total_len:
                raw_chunk = bytecode[idx:idx + 5]
                c_raw, r_raw = struct.unpack("<HH", raw_chunk[1:5])
                is_rel_c, res_c = _decode_col_coord(c_raw, base_col)
                is_rel_r, res_r = _decode_row_coord(r_raw, base_row)
                cell_str = _format_cell(res_c, res_r, is_rel_c, is_rel_r)
                tokens.append({
                    "opcode": op,
                    "kind": "CELL_REF",
                    "col": res_c,
                    "row": res_r,
                    "is_rel_col": is_rel_c,
                    "is_rel_row": is_rel_r,
                    "text": cell_str,
                    "raw_hex": raw_chunk.hex(),
                })
                idx += 5
            else:
                break

        # 0x02: Range reference (8 bytes: col1, row1, col2, row2)
        elif op == 0x02:
            if idx + 9 <= total_len:
                raw_chunk = bytecode[idx:idx + 9]
                c1, r1, c2, r2 = struct.unpack("<HHHH", raw_chunk[1:9])
                is_rel_c1, rc1 = _decode_col_coord(c1, base_col)
                is_rel_r1, rr1 = _decode_row_coord(r1, base_row)
                is_rel_c2, rc2 = _decode_col_coord(c2, base_col)
                is_rel_r2, rr2 = _decode_row_coord(r2, base_row)
                c1_str = _format_cell(rc1, rr1, is_rel_c1, is_rel_r1)
                c2_str = _format_cell(rc2, rr2, is_rel_c2, is_rel_r2)
                tokens.append({
                    "opcode": op,
                    "kind": "RANGE_REF",
                    "start_col": rc1,
                    "start_row": rr1,
                    "end_col": rc2,
                    "end_row": rr2,
                    "is_rel_start_col": is_rel_c1,
                    "is_rel_start_row": is_rel_r1,
                    "is_rel_end_col": is_rel_c2,
                    "is_rel_end_row": is_rel_r2,
                    "text": f"{c1_str}..{c2_str}",
                    "raw_hex": raw_chunk.hex(),
                })
                idx += 9
            else:
                break

        # 0x03: Return / End of formula
        elif op == 0x03:
            tokens.append({
                "opcode": op,
                "kind": "RETURN",
                "text": "",
                "raw_hex": bytecode[idx:idx + 1].hex(),
            })
            idx += 1

        # 0x04: Explicit parentheses wrapper
        elif op == 0x04:
            tokens.append({
                "opcode": op,
                "kind": "PAREN",
                "text": "()",
                "raw_hex": bytecode[idx:idx + 1].hex(),
            })
            idx += 1

        # 0x05: Integer constant (2 bytes int16)
        elif op == 0x05:
            if idx + 3 <= total_len:
                raw_chunk = bytecode[idx:idx + 3]
                val = struct.unpack("<h", raw_chunk[1:3])[0]
                tokens.append({
                    "opcode": op,
                    "kind": "INTEGER",
                    "value": val,
                    "text": str(val),
                    "raw_hex": raw_chunk.hex(),
                })
                idx += 3
            else:
                break

        # 0x08..0x17: Operators
        elif op in OPERATOR_SYMBOLS:
            symbol, arity = OPERATOR_SYMBOLS[op]
            tokens.append({
                "opcode": op,
                "kind": "OPERATOR",
                "symbol": symbol,
                "arity": arity,
                "text": symbol,
                "raw_hex": bytecode[idx:idx + 1].hex(),
            })
            idx += 1

        # 0x1F..0x4F, 0x55, 0x5B: Fixed-arity functions
        elif op in FIXED_FUNCTIONS:
            func_name, arity = FIXED_FUNCTIONS[op]
            tokens.append({
                "opcode": op,
                "kind": "FUNCTION",
                "name": func_name,
                "arity": arity,
                "text": func_name,
                "raw_hex": bytecode[idx:idx + 1].hex(),
            })
            idx += 1

        # 0x50..0x58 (except 0x55): Multi-argument functions with 1-byte argument count
        elif op in MULTI_FUNCTIONS:
            if idx + 2 <= total_len:
                raw_chunk = bytecode[idx:idx + 2]
                argc = raw_chunk[1]
                func_name = MULTI_FUNCTIONS[op]
                tokens.append({
                    "opcode": op,
                    "kind": "FUNCTION",
                    "name": func_name,
                    "arity": argc,
                    "text": func_name,
                    "raw_hex": raw_chunk.hex(),
                })
                idx += 2
            else:
                break

        # Unknown / unsupported token
        else:
            break

    unparsed = bytecode[idx:]
    return tokens, unparsed


def render_rpn_to_infix(tokens: list[dict[str, Any]]) -> str | None:
    """Render a sequence of Lotus 1-2-3 RPN tokens into a human-readable formula string.

    Returns:
        str | None: Infix formula string (e.g. '@SUM(A1..A10)') or None if evaluation fails.
    """
    stack: list[str] = []

    for token in tokens:
        kind = token.get("kind")

        if kind in ("CONSTANT", "INTEGER", "CELL_REF", "RANGE_REF"):
            stack.append(token.get("text", ""))

        elif kind == "PAREN":
            if stack:
                top = stack.pop()
                stack.append(f"({top})")
            else:
                return None

        elif kind == "OPERATOR":
            arity = token.get("arity", 2)
            symbol = token.get("symbol", "")
            if arity == 1:
                if stack:
                    arg = stack.pop()
                    stack.append(f"{symbol}{arg}")
                else:
                    return None
            elif arity == 2:
                if len(stack) >= 2:
                    right = stack.pop()
                    left = stack.pop()
                    stack.append(f"{left}{symbol}{right}")
                else:
                    return None
            else:
                return None

        elif kind == "FUNCTION":
            name = token.get("name", "")
            arity = token.get("arity", 0)
            if arity == 0:
                stack.append(f"{name}()")
            elif len(stack) >= arity:
                args = [stack.pop() for _ in range(arity)]
                args.reverse()
                stack.append(f"{name}({', '.join(args)})")
            else:
                return None

        elif kind == "RETURN":
            # 0x03 marks the end of formula evaluation
            continue

        else:
            # Unknown token encountered
            return None

    if len(stack) == 1:
        return stack[0]
    return None


def disassemble_formula(bytecode: bytes, base_col: int = 0, base_row: int = 0) -> dict[str, Any]:
    """Top-level formula disassembler.

    Produces structured tokens, human-readable formula text, and status reporting
    without ever throwing or discarding unparsed bytes.
    """
    tokens, unparsed = tokenize_formula(bytecode, base_col=base_col, base_row=base_row)
    formula_text = render_rpn_to_infix(tokens)

    if not unparsed:
        if formula_text is not None:
            decode_status = "disassembled"
        else:
            decode_status = "tokens_parsed_render_failed"
    elif tokens:
        decode_status = "partially_disassembled"
    else:
        decode_status = "unrecognized_bytecode"

    result: dict[str, Any] = {
        "formula_tokens": tokens,
        "formula_text": formula_text,
        "formula_decode_status": decode_status,
    }
    if unparsed:
        result["formula_unparsed_hex"] = unparsed.hex()

    return result
