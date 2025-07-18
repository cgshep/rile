# tests/test_encrypted_programs.py
import struct
import pytest

from rile.crypto import (
    encrypt_instruction,
    decrypt_instruction,
    encrypt_program,
    decrypt_program,
    CT_SIZE,                 # 20 B per encrypted instruction :contentReference[oaicite:0]{index=0}
)
from rile.cpu import CPU
from rile.encrypted_cpu import EncryptedCPU        # :contentReference[oaicite:1]{index=1}
from rile.memory import Memory

# --- helpers ---------------------------------------------------------------

def _w(word: int) -> bytes:
    """Pack one 32-bit word little-endian."""
    return struct.pack("<I", word)

def _run(cpu_cls, binary: bytes, max_cycles=100):
    """Run `binary` on the supplied CPU class and return its final state."""
    mem = Memory()
    mem.write(binary)
    cpu = cpu_cls(verbose=0)
    cpu.run(mem, max_cycles=max_cycles)
    return cpu.dump_state()

# ---------------------------------------------------------------------------
# 1.  Crypto-level tests
# ---------------------------------------------------------------------------

def test_encrypt_decrypt_blob_roundtrip():
    # 3 distinct instructions (ADD, SUB, NOP) × 2 = 6 words
    prog = b"".join([
        _w(0x002080b3),   # add x1,x1,x2
        _w(0x402080b3),   # sub x1,x1,x2
        _w(0x00000013),   # nop
    ]) * 2
    ct = encrypt_program(prog)
    assert decrypt_program(ct) == prog

def test_program_ciphertext_length_matches_ct_size():
    prog = _w(0x00000013) * 5            # 5 NOPs
    ct = encrypt_program(prog)
    # one ciphertext block per instruction
    assert len(ct) == 5 * CT_SIZE

def test_tampered_program_tag_raises():
    prog = _w(0x00000013) * 2
    ct = bytearray(encrypt_program(prog))
    ct[-1] ^= 0x42                         # flip a bit in the final tag
    with pytest.raises(ValueError):
        decrypt_program(bytes(ct))

# ---------------------------------------------------------------------------
# 2.  Architectural tests (plain vs encrypted CPU)
# ---------------------------------------------------------------------------

ARITH_PROG = [
    0x00300093,       # li x1,3
    0x00400113,       # li x2,4
    0x002081b3,       # add x3,x1,x2   → 7
    0x40210233,       # sub x4,x2,x1   → 1
    0x0000006f,       # jal x0,0  (halt)
]

def test_encrypted_cpu_matches_plain_cpu_for_arith_program():
    plain_bin = b"".join(_w(w) for w in ARITH_PROG)
    enc_bin   = encrypt_program(plain_bin)

    plain_state = _run(CPU,           plain_bin)
    enc_state   = _run(EncryptedCPU,   enc_bin)

    for reg in range(32):
        assert plain_state["regs"][reg] == enc_state["regs"][reg]

def test_loop_sum_encrypted():
    """
    Same algorithm as tests/test_programs.py::test_loop_sum,
    but executed through the encrypted fetch path.  Expected:
    x3 = Σ_{i=1}^{10} i = 55
    """
    loop_prog = [
        0x00000093,       # li x1,0
        0x00100113,       # li x2,1
        0x00b00213,       # li x4,11
        0x002080b3,       # add x1,x1,x2
        0x00110113,       # addi x2,x2,1
        0xfe414ce3,       # blt x2,x4,-8
        0x000081b3,       # add x3,x1,x0
        0x0000006f,
    ]
    enc_bin = encrypt_program(b"".join(_w(w) for w in loop_prog))
    state   = _run(EncryptedCPU, enc_bin, max_cycles=150)

    assert state["regs"][3] == 55        # result
    assert state["regs"][2] == 11        # loop index after exit
    assert state["regs"][1] == 55
