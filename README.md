# FuSS: Coverage-Directed Hardware Fuzzing with Selective Symbolic Execution

This repository contains the full implementation of **FuSS (Firmware-based Symbolic-guided SoC Fuzzing)—a hybrid hardware fuzzing framework** designed for validating **RISC-V-based SoCs**, particularly targeting the PicoRV32 core. FuSS uses **coverage-guided fuzzing** and **selective symbolic execution** to uncover deeply buried hardware states unreachable by conventional fuzzers or property checkers.

---

## 🧠 Overview

- ✅ Bit-level toggle coverage feedback from RTL simulation using iverilog and VCD traces

- 🔁 Firmware mutation engine that iteratively mutates instruction sequences (firmware.hex)

- 📈 Coverage tracking backend using .vcd waveform analysis

- 🧠 Selective symbolic execution fallback powered by angr to overcome coverage plateaus

- ⚙️ Works with open-source tools (iverilog, vvp, angr, riscv32-unknown-elf-gcc)

---

## ▶️ How to Run

Refer to this [documentation](https://archfx.me/posts/2023/02/firmware1/) for inital set-up 

### 1. Build the Initial Firmware

```bash
cd firmware
riscv32-unknown-elf-gcc -o firmware.elf -nostartfiles -T sections.lds start.S firmware.c
riscv32-unknown-elf-objcopy -O verilog firmware.elf firmware.hex
```

### 2. Start Fuzzing

```bash
python3 fuzzing_engine.py
```

Each iteration:

- Appends N random RISC-V 32-bit instructions
- Simulates using `iverilog` + `vvp`
- Analyzes `testbench.vcd` for toggle coverage
- If coverage improves: commits changes
- If not: reverts and logs dropped instructions
- If no improvement after `num_holds` rounds, symbolic exploration is triggered via `angr`.

---

## 📈 Output Artifacts

After running the fuzzer, you will have:

- `testbench.vcd`: Hardware-level waveform trace
- `dropped_instrs.txt`: Ineffective instructions filtered by coverage
- `firmware.hex`: Updated instruction stream

---

## ♻️ High-level Architecture Diagram

```
           ┌────────────────────┐
           │ Original Firmware  │
           └────────┬───────────┘
                    │
         +──────────▼───────────+
         │ Append Random Instrs │
         +──────────┬───────────+
                    │
                    ▼
           ┌────────────────────┐
           │ Verilog Simulation │
           └────────┬───────────┘
                    │
         +──────────▼───────────+
         │ Toggle Coverage Eval │
         +──────────┬───────────+
        No ⬅────────┘    └──────▶ Yes
                    │
        Revert + Drop Instrs
                    │
      ┌─────────────▼─────────────┐
      │ (Fallback) Symbolic Exec  │
      │     with angr (WIP)       │
      └───────────────────────────┘
```

---

## 📜 License

This project is licensed under the MIT License. See `LICENSE` for details.

---

## 📬 Contact

For questions, open an issue or contact [supra.nlpn@gmail.com].
