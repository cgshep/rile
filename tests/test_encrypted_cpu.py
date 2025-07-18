import struct
import pytest

from rile.crypto import (
    encrypt_instruction,
    decrypt_instruction,
    encrypt_program,
    decrypt_program
)
from rile.encrypted_cpu import EncryptedCPU
from rile.cpu import CPU
from rile.memory import Memory

# A single, architecturally‑defined NOP for RV32I: addi x0, x0, 0 = 0x00000013
NOP_WORD = 0x00000013


def _w(word: int) -> bytes:
    """Convenience: pack a 32‑bit little‑endian word."""
    return struct.pack("<I", word)


# ---------------------------------------------------------------------------
# 1.  Crypto unit tests
# ---------------------------------------------------------------------------

def test_encrypt_decrypt_roundtrip():
    ct = encrypt_instruction(NOP_WORD)
    assert decrypt_instruction(ct) == NOP_WORD, "encrypt→decrypt must return original word"
    # ciphertext length must be constant for a 4‑byte instruction (ASCON‑128 = 20 B)
    assert len(ct) == len(encrypt_instruction(0)), "ciphertext size should be deterministic"


def test_program_roundtrip():
    program = _w(NOP_WORD) * 4  # four NOPs
    ct = encrypt_program(program)
    assert decrypt_program(ct) == program


def test_invalid_tag_raises():
    ct = bytearray(encrypt_instruction(NOP_WORD))
    ct[0] ^= 0x01  # flip a bit → MAC should fail
    with pytest.raises(ValueError):
        decrypt_instruction(bytes(ct))


# ---------------------------------------------------------------------------
# 2.  Architectural test: EncryptedCPU vs plain CPU
# ---------------------------------------------------------------------------

def test_encrypted_cpu_matches_plain_cpu_state():
    """After executing one instruction the architectural registers must match."""
    # --- assemble a 1‑instruction program (NOP) ----------------------------
    prog_plain = _w(NOP_WORD)
    prog_enc   = encrypt_program(prog_plain)

    # --- plain CPU ---------------------------------------------------------
    mem_plain = Memory()
    mem_plain.write(prog_plain)
    cpu_plain = CPU(verbose=0)
    cpu_plain.next_cycle(mem_plain)
    state_plain = cpu_plain.dump_state()

    # --- encrypted CPU -----------------------------------------------------
    mem_enc = Memory()
    mem_enc.write(prog_enc)
    cpu_enc = EncryptedCPU(verbose=0)
    cpu_enc.next_cycle(mem_enc)
    state_enc = cpu_enc.dump_state()

    # All 32 architectural registers must match; we ignore the program counter
    for reg in range(32):
        assert state_plain["regs"][reg] == state_enc["regs"][reg], (
            f"Mismatch in x{reg}: plain={state_plain['regs'][reg]} "
            f"enc={state_enc['regs'][reg]}"
        )

    # Sanity: each CPU advanced exactly one cycle
    assert state_plain["cycle"] == 1
    assert state_enc["cycle"]   == 1
