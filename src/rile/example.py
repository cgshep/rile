#!/usr/bin/env python3

import struct

from memory import Memory
from cpu import CPU
from utils import logger

from elftools.elf.elffile import ELFFile

REPL_PROMPT = "> Next cycle (n), enter N cycle, view current cycle (c), " \
    "registers (r), memory (m), or quit (q): "
PROGRAM_PROMPT = "> Select test program - (1, default) rv32ui-p-xor, " \
    "(2) rv32ui-p-add, " \
    "(3) rv32ui-p-srai: "
SEG_N = 1
TEST_PROGRAM_PATH =  "./tests/riscv-tests-prebuilt-binaries/isa/rv32ui/"

if __name__ == "__main__":
    voyager_cpu = CPU(verbose=1)
    voyager_ram = Memory()

    usr_in = input(PROGRAM_PROMPT)
    f = TEST_PROGRAM_PATH
    
    if "2" in usr_in:
        f += "rv32ui-p-add"
    elif "3" in usr_in:
        f += "rv32ui-p-srai"
    else:
        f += "rv32ui-p-xor"

    print(f"Loading {f}...")

    with open(f, "rb") as ff:
        e = ELFFile(ff)
        for i, s in enumerate(e.iter_segments()):
            print(f"Segment {i} type: {s['p_type']}")

        print(f"Loading segment {SEG_N}...")
        seg = e.get_segment(SEG_N)
        voyager_ram.write(seg.data())

    while True:
        usr_in = input(REPL_PROMPT)
        if "c" in usr_in:
            print(f"Cycle: {voyager_cpu.cycle}")
        elif "r" in usr_in:
            print(voyager_cpu)
        elif "m" in usr_in:
            print(voyager_ram)
        elif "q" in usr_in:
            break
        elif "n" in usr_in:
            voyager_cpu.next_cycle(voyager_ram)
        elif usr_in.isdigit():
            for i in range(int(usr_in)):
                if i % 5 == 0:
                    print(f"Cycle: +{i}")
                voyager_cpu.next_cycle(voyager_ram)
        else:
            print("Try again")
    print("Bye!")
