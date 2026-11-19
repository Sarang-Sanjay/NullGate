# Contributing to NullGate

Thank you for contributing to NullGate! NullGate is an adversarial systems security platform where architectural invariants, compiler hardening, and hardware guarantees are strictly enforced.

---

## 1. Development Environment Prerequisites

To build and test NullGate locally, your development system must have:
* **Operating System:** Linux with kernel version >= 6.8 (with `CONFIG_BPF_LSM=y` active).
* **CPU:** x86_64 CPU with Intel PKU (`ospke`) and Intel CET (`ibt`, `user_shstk` / `arch_cet`).
* **Toolchain:** `clang-18` (or newer), `llvm-18-dev`, `bpftool`, `libbpf-dev`, `cmake >= 3.28`, `libelf-dev`.

Run `scripts/check_env.sh` to verify your environment before building.

---

## 2. Inviolable Security & Architectural Invariants

Every patch, pull request, or contribution must strictly adhere to the following rules:

1. **Pillar 4 Gadget Invariant (Zero WRPKRU in C Code):**
   - **Never emit raw `wrpkru` instructions (`0F 01 EF`) in C code or application binaries.**
   - WRPKRU instructions are quarantined exclusively to authorized supervisor assembly entry points in `src/libnullgate/callgate.S` and `src/libnullgate/signal_trampoline.S`.
   - All translation units are audited via `nullgate-scrubber --strict` and the LLVM compiler pass `libNullGatePass.so`.
2. **Mandatory Intel CET & NX Stack Compliance:**
   - All C/C++ targets must compile with `-fcf-protection=full -mshstk`.
   - Assembly files (`.S`) must use `NG_ENDBR64` landing pads and emit the `.note.gnu.property` section with `GNU_PROPERTY_X86_FEATURE_1_AND` enabling IBT and SHSTK.
   - Non-executable stack (`GNU_STACK RW`) is required on all ELF objects and shared libraries.
3. **No Unprivileged Elevation:**
   - The test suite and userspace runtime must execute cleanly as an unprivileged user (zero `sudo` required during `ctest`).

---

## 3. Building & Testing

Always verify your changes against the master certification gate:

```bash
# 1. Build the repository cleanly
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

# 2. Run the automated CTest regression suite
ctest --test-dir build --output-on-failure

# 3. Execute the full end-to-end certification gate
bash scripts/verify_nullgate.sh
```

---

## 4. Code Formatting & Style

* **Language Standard:** C11 for core libraries; C++17 for the LLVM compiler pass.
* **Indentation:** 4 spaces (no tab characters).
* **Format:** Run `clang-format -i <file>` using the project `.clang-format` configuration.
* **Compiler Cleanliness:** Code must compile with zero warnings under `-Wall -Wextra -Werror`.

---

## 5. Pull Request Workflow

1. Fork the repository and create a feature branch (`git checkout -b feature/my-feature`).
2. Implement your changes along with unit or security penetration tests in `tests/`.
3. Verify that `bash scripts/verify_nullgate.sh` passes 100%.
4. Commit your changes with clear, descriptive commit messages.
5. Push to your branch and submit a Pull Request.
