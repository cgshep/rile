# RILE: RISC-V Instruction-level Encryption Emulator

RILE is a Python-based emulation of a RV32I CPU with instruction-level encryption derived from the Voyager CPU project.

## Features

+ (Ongoing) Integration of an encryption unit before the fetch stage.
+ Supports the RV32I ISA using a non-pipelined CPU with a single-cycle instruction fetch, decode, and execution stage.
+ A simple virtual RAM into which test programs (ELF binaries) are loaded.
  -  The [official RISC-V ISA tests](https://github.com/riscv-software-src/riscv-tests/) can be used for this purpose (see below).
+ A basic REPL for viewing register and RAM contents, and executing the next N cycles.
+ MIT license.

## Build and Run

1. Clone the repository.
2. (Optional) Clone the pre-built RV32UI tests using:
```
git submodule init
git submodule update
```
The binaries will be placed under `tests/riscv-tests-prebuilt-binaries/`. Alternatively, you can build the [test suites from the official repo](https://github.com/riscv-software-src/riscv-tests/).

3. See the example in `src/rile/example.py`. You may run this directly using `python src/voyagercpu/example.py`.

4. Enjoy!

5. (Optional) Run the Voyager unit tests using `pytest`

## Todo

+ Add more tests, particularly at the execution stage.
+ Implement some ISA extensions, e.g. the M and C specifications.
+ Add pipelining and privileged mode.
+ Improve pretty printing.
+ Etc.

Please contribute!
