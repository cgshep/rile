import struct
import ascon

from typing import Final


KEY:   Final[bytes] = b"0123456789ABCDEF"     # 16-byte (128-bit) demo key
NONCE: Final[bytes] = b"0011223344556677"     # 16-byte (128-bit) nonce
PT_SIZE: Final[int] = 4                       # 32-bit instruction
TAG_SIZE: Final[int] = 16                     # ASCON-128 MAC length
CT_SIZE: Final[int] = PT_SIZE + TAG_SIZE      # 20 bytes / encrypted instr


def encrypt_instruction(word: int) -> bytes:
    """Encrypt a 32-bit little-endian instruction."""
    pt = struct.pack("<I", word)
    return ascon.encrypt(KEY, NONCE, b"", pt)


def decrypt_instruction(ct: bytes) -> int:
    """
    Decrypt a single 32-bit instruction and verify its MAC.

    Raises
    ------
    ValueError
        If the authentication tag is invalid.
    """
    pt = ascon.decrypt(KEY, NONCE, b"", ct)

    # ASCON returns None when the tag verification fails, so convert that
    # into the semantic error the tests (and callers) expect.
    if pt is None:
        raise ValueError("Ciphertext authentication failed")

    # Successful decryption → unpack little-endian 32-bit word
    return struct.unpack("<I", pt)[0]


def encrypt_blob(code: bytes) -> bytes:
    """Encrypt an entire program (length ≡ 0 (mod 4))."""
    if len(code) % PT_SIZE:
        raise ValueError("Program length must be a multiple of 4 bytes")
    out = bytearray()
    for i in range(0, len(code), PT_SIZE):
        out += encrypt_instruction(struct.unpack("<I", code[i:i+4])[0])
    return bytes(out)


def decrypt_blob(ct: bytes) -> bytes:
    if len(ct) % CT_SIZE:
        raise ValueError("Ciphertext length ≠ k⋅20 bytes")
    out = bytearray()
    for i in range(0, len(ct), CT_SIZE):
        out += struct.pack("<I", decrypt_instruction(ct[i:i+CT_SIZE]))
    return bytes(out)


# Aliases kept for backwards compatibility and test imports
encrypt_program = encrypt_blob
decrypt_program = decrypt_blob
