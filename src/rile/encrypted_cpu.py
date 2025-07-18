# src/rile/encrypted_cpu.py
from .cpu    import CPU, INST_ALIGN, PC_REG_INDEX
from .crypto import decrypt_instruction, CT_SIZE

class EncryptedCPU(CPU):
    CT_BYTES = CT_SIZE          # 20-byte ciphertext per instruction

    def _fetch(self, memory):
        pc   = self.regfile[PC_REG_INDEX]            # 0,4,8,…
        idx  = pc // INST_ALIGN                      # instruction index
        addr = idx * self.CT_BYTES                   # idx·20  → RAM offset
        ct   = memory.read(addr, self.CT_BYTES)      # 20-byte slice

        if ct == b"\x00" * self.CT_BYTES:
            # We do not want to decrypt null
            return 0

        return decrypt_instruction(ct)           # happy path
