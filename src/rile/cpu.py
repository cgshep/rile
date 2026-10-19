import struct

from .decoder import (
    RVInst, RType, IType, SType, BType, UType, JType,
    decode_instruction, DecodeError, nop_inst,
    Instruction, REG_DICT,
)
from .utils import register_names, abi_register_name_dict, logger

# Instructions are always 4-byte aligned for RV32I
INST_ALIGN = 4
PC_REG_INDEX = 32

MASK32 = 0xFFFFFFFF


class AlignmentError(Exception):
    pass


def _to_signed32(v: int) -> int:
    """Reinterpret a 32-bit unsigned value as a signed integer."""
    v &= MASK32
    return v if v < 0x80000000 else v - 0x100000000


class CPU:
    def __init__(self, start_pc=0, verbose=0):
        self.regfile = self.reset_regs()
        self.regfile[PC_REG_INDEX] = start_pc
        self.cycle = 0
        self.verbose = verbose

    def __str__(self) -> str:
        dump_str = f"Cycle: {self.cycle}\n"
        dump_str += "Register states:\n"
        for i, r in enumerate(self.regfile.keys()):
            dump_str += "{:>3}: {:<12}".format(REG_DICT[i], hex(self.regfile[r]))
            if (i + 1) % 5 == 0:
                dump_str += "\n"
        return dump_str

    def reset_regs(self) -> dict:
        return { i: 0 for i, _ in enumerate(register_names()) }

    def _write_reg(self, rd: int, val: int):
        """Write val to register rd, enforcing x0==0 and 32-bit wrap."""
        if rd != 0:
            self.regfile[rd] = val & MASK32

    def _fetch(self, memory):
        raw_inst = memory.read(self.regfile[PC_REG_INDEX],
                               INST_ALIGN)
        logger.debug(f"Fetched instruction: 0x{raw_inst.hex()}")
        # Convert to little endian
        raw_inst_bin = struct.unpack("<I", raw_inst)[0]
        return raw_inst_bin

    def _decode(self, raw_inst: int) -> RVInst:
        # No instruction
        if raw_inst == 0:
            logger.warning("No instruction!")

        try:
            decoded_inst = decode_instruction(raw_inst)
            logger.debug(f"Decoded: {decoded_inst}")
            return decoded_inst
        except DecodeError as e:
            logger.error(e)
            logger.error("Using NOP instead")
            return nop_inst()

    def _execute(self, inst: RVInst, memory) -> bool:
        """
        Execute one instruction.

        Returns True if the instruction explicitly modified the PC
        (jump or taken branch), False otherwise.  The caller is
        responsible for the sequential PC increment when False is
        returned.
        """
        if self.verbose:
            print(inst)
        mne = inst.mnemonic
        r = self.regfile  # For brevity

        if isinstance(inst, UType):
            if mne == Instruction.LUI:
                self._write_reg(inst.rd, inst.imm)
            elif mne == Instruction.AUIPC:
                self._write_reg(inst.rd, r[PC_REG_INDEX] + inst.imm)

        elif isinstance(inst, JType):
            if mne == Instruction.JAL:
                self._write_reg(inst.rd, r[PC_REG_INDEX] + INST_ALIGN)
                r[PC_REG_INDEX] += inst.imm
                return True

        elif isinstance(inst, BType):
            a = r[inst.rs1]
            b = r[inst.rs2]
            taken = False
            if mne == Instruction.BEQ:
                taken = (a == b)
            elif mne == Instruction.BNE:
                taken = (a != b)
            elif mne == Instruction.BLT:
                taken = (_to_signed32(a) < _to_signed32(b))
            elif mne == Instruction.BLTU:
                taken = (a < b)
            elif mne == Instruction.BGE:
                taken = (_to_signed32(a) >= _to_signed32(b))
            elif mne == Instruction.BGEU:
                taken = (a >= b)
            if taken:
                logger.debug(f"Branch {mne.name} taken: PC += {inst.imm}")
                r[PC_REG_INDEX] += inst.imm
                return True

        elif isinstance(inst, SType):
            addr = r[inst.rs1] + inst.imm
            if mne == Instruction.SB:
                memory.write(struct.pack("B", r[inst.rs2] & 0xFF), addr)
            elif mne == Instruction.SH:
                memory.write(struct.pack("<H", r[inst.rs2] & 0xFFFF), addr)
            elif mne == Instruction.SW:
                memory.write(struct.pack("<I", r[inst.rs2] & MASK32), addr)

        elif isinstance(inst, IType):
            # JALR: set LSB of target to 0 per spec
            if mne == Instruction.JALR:
                self._write_reg(inst.rd, r[PC_REG_INDEX] + INST_ALIGN)
                r[PC_REG_INDEX] = (r[inst.rs1] + inst.imm) & ~1
                return True
            # Load instructions
            elif mne == Instruction.LB:
                addr = r[inst.rs1] + inst.imm
                val = memory.read(addr, 1)[0]
                self._write_reg(inst.rd, val if val < 0x80 else val - 0x100)
            elif mne == Instruction.LBU:
                addr = r[inst.rs1] + inst.imm
                self._write_reg(inst.rd, memory.read(addr, 1)[0])
            elif mne == Instruction.LH:
                addr = r[inst.rs1] + inst.imm
                val = struct.unpack("<H", memory.read(addr, 2))[0]
                self._write_reg(inst.rd, val if val < 0x8000 else val - 0x10000)
            elif mne == Instruction.LHU:
                addr = r[inst.rs1] + inst.imm
                self._write_reg(inst.rd, struct.unpack("<H", memory.read(addr, 2))[0])
            elif mne == Instruction.LW:
                addr = r[inst.rs1] + inst.imm
                self._write_reg(inst.rd, struct.unpack("<I", memory.read(addr, 4))[0])
            # Arithmetic immediate instructions
            elif mne == Instruction.ADDI:
                self._write_reg(inst.rd, r[inst.rs1] + inst.imm)
            elif mne == Instruction.SLTI:
                self._write_reg(inst.rd, 1 if _to_signed32(r[inst.rs1]) < inst.imm else 0)
            elif mne == Instruction.SLTIU:
                self._write_reg(inst.rd, 1 if r[inst.rs1] < (inst.imm & MASK32) else 0)
            elif mne == Instruction.XORI:
                self._write_reg(inst.rd, r[inst.rs1] ^ inst.imm)
            elif mne == Instruction.ORI:
                self._write_reg(inst.rd, r[inst.rs1] | inst.imm)
            elif mne == Instruction.ANDI:
                self._write_reg(inst.rd, r[inst.rs1] & inst.imm)
            elif mne == Instruction.SLLI:
                self._write_reg(inst.rd, r[inst.rs1] << (inst.imm & 0x1F))
            elif mne == Instruction.SRLI:
                self._write_reg(inst.rd, r[inst.rs1] >> (inst.imm & 0x1F))
            elif mne == Instruction.SRAI:
                self._write_reg(inst.rd, _to_signed32(r[inst.rs1]) >> (inst.imm & 0x1F))

        elif isinstance(inst, RType):
            if mne == Instruction.ADD:
                self._write_reg(inst.rd, r[inst.rs1] + r[inst.rs2])
            elif mne == Instruction.SUB:
                self._write_reg(inst.rd, r[inst.rs1] - r[inst.rs2])
            elif mne == Instruction.SLL:
                self._write_reg(inst.rd, r[inst.rs1] << (r[inst.rs2] & 0x1F))
            elif mne == Instruction.SLT:
                self._write_reg(inst.rd, 1 if _to_signed32(r[inst.rs1]) < _to_signed32(r[inst.rs2]) else 0)
            elif mne == Instruction.SLTU:
                self._write_reg(inst.rd, 1 if r[inst.rs1] < r[inst.rs2] else 0)
            elif mne == Instruction.XOR:
                self._write_reg(inst.rd, r[inst.rs1] ^ r[inst.rs2])
            elif mne == Instruction.SRL:
                self._write_reg(inst.rd, r[inst.rs1] >> (r[inst.rs2] & 0x1F))
            elif mne == Instruction.SRA:
                self._write_reg(inst.rd, _to_signed32(r[inst.rs1]) >> (r[inst.rs2] & 0x1F))
            elif mne == Instruction.OR:
                self._write_reg(inst.rd, r[inst.rs1] | r[inst.rs2])
            elif mne == Instruction.AND:
                self._write_reg(inst.rd, r[inst.rs1] & r[inst.rs2])

        return False

    def next_cycle(self, memory) -> bool:
        """
        Execute one cycle.

        Returns True if a halt is detected: a control-flow instruction
        (JAL/JALR/taken branch) explicitly jumped back to the same PC,
        creating an infinite self-loop.
        """
        prev_pc = self.regfile[PC_REG_INDEX]
        raw_inst = self._fetch(memory)
        decoded_inst = self._decode(raw_inst)
        pc_modified = self._execute(decoded_inst, memory)

        # Confirm that the PC is aligned at a multiple of 4
        if self.regfile[PC_REG_INDEX] & 0b11:
            raise AlignmentError(f"Program counter is misaligned! - "
                                 f"PC: {self.regfile[PC_REG_INDEX]}")

        if pc_modified:
            # Control-flow instruction: halt if it jumped to itself
            halted = (self.regfile[PC_REG_INDEX] == prev_pc)
        else:
            # Sequential instruction: advance to next instruction
            self.regfile[PC_REG_INDEX] += INST_ALIGN
            halted = False

        self.cycle += 1
        return halted

    def dump_state(self):
        """
        Return current state as a dict for testing.
        """
        return {
            "cycle": self.cycle,
            "pc": self.regfile[PC_REG_INDEX],
            "regs": dict(self.regfile),  # copy
        }

    def run(self, memory, max_cycles=1000):
        """
        Run until max_cycles or halt condition detected.
        """
        for _ in range(max_cycles):
            if self.next_cycle(memory):
                break
