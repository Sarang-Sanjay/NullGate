# NullGate Developer Starter Examples

This directory contains standalone, self-contained example applications illustrating how to integrate, sandbox, and communicate with NullGate compartments.

---

## Example 1: Basic Compartmentalization (`01_basic_compartment/`)
Demonstrates core hardware compartmentalization:
* Initializes the NullGate runtime (`ng_init()`).
* Allocates an isolated stack and registers hardware Domain 2 (`ng_domain_create()`).
* Dispatches untrusted calculations into Domain 2 using the hardware call-gate (`ng_enter()`).

```bash
cd 01_basic_compartment
make run
```

---

## Example 2: Zero-Copy Hardware IPC (`02_zero_copy_ipc/`)
Demonstrates high-performance intra-process messaging:
* Creates a 64-slot single-producer single-consumer (SPSC) hardware ring channel between Domain 0 and Domain 2 (`ng_ipc_channel_create()`).
* Streams 100,000 messages with **zero kernel copies** and **< 40ns latency**.
* Safely destroys the channel and recycles hardware PKU keys (`ng_ipc_channel_destroy()`).

```bash
cd 02_zero_copy_ipc
make run
```

---

## Example 3: Transparent Library Shim (`03_library_shim/`)
Demonstrates how to sandbox third-party libraries (parsers, codecs) with **zero modifications to caller application code**:
* Builds an unmodified library (`libparser.so`) and client application (`app`).
* Builds a lightweight shim library (`libparser_shim.so`) using `NG_INTERPOSE_FUNC_2`.
* Running `LD_PRELOAD=./libparser_shim.so ./app` automatically intercepts calls and executes the parser inside Domain 3.

```bash
cd 03_library_shim
make run
```
