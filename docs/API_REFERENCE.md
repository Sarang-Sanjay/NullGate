# NullGate C API Reference Manual

This document details the public C application programming interfaces (APIs) provided by `libnullgate.so`, `libnullgate_shim.so`, and associated headers.

---

## 1. Core Runtime & Domain Management (`nullgate.h`)

### `int ng_init(void);`
Initializes the NullGate userspace runtime. Detects CPU hardware support (PKU, CET), verifies `CR4.PKE`, sets up signal trampolines on dedicated altstacks, and maps the calling thread's dedicated supervisor state page under Key 1.
* **Returns:** `NG_SUCCESS` (0) on success, or negative error code on failure.

### `int ng_domain_create(uint32_t domain_id, void *stack_base, size_t stack_size);`
Registers and configures an isolated domain ($1 \le D \le 15$). Assigns a dedicated hardware PKU key and tags the provided stack region with `pkey_mprotect()`.
* **Parameters:**
  * `domain_id`: Target domain index (1..15).
  * `stack_base`: Base address of memory allocated for the compartment stack.
  * `stack_size`: Size of the stack buffer in bytes (must be page-aligned).
* **Returns:** `NG_SUCCESS` (0) on success, or negative error code.

### `int ng_domain_destroy(uint32_t domain_id);`
Safely tears down an allocated domain, resets stack memory protection to Key 0, recycles hardware PKU keys, and clears domain descriptor.
* **Parameters:**
  * `domain_id`: Target domain index to destroy (1..15).
* **Returns:** `NG_SUCCESS` (0) on success, `NG_ERR_LOCKED` if actively leased, or `NG_ERR_INVALID`.

### `uint64_t ng_enter(uint32_t domain_id, ng_compartment_fn fn, void *arg);`
Executes an untrusted function inside the designated compartment via the hardware call-gate. Switches the active stack, revokes Key 0 and Key 1 privileges via `WRPKRU`, executes `fn(arg)`, restores supervisor privileges, and returns the result.
* **Parameters:**
  * `domain_id`: Target compartment index.
  * `fn`: Function pointer matching `uint64_t (*)(void *arg)`.
  * `arg`: Opaque pointer passed to the compartment function.
* **Returns:** The 64-bit integer return value of `fn(arg)`.

### `uint32_t ng_get_active_domain(void);`
Returns the currently executing domain ID of the calling thread.
* **Returns:** `0` for supervisor/host runtime, or `1..15` for isolated compartments.

### `struct ng_trusted_state *ng_get_thread_state(void);`
Returns a pointer to the calling thread's dedicated 4KB supervisor state structure.
* **Returns:** Pointer to `struct ng_trusted_state` mapped under Key 1.

---

## 2. Hardware Zero-Copy IPC Channels (`nullgate_ipc.h`)

### `struct ng_ipc_channel *ng_ipc_channel_create(uint32_t dom_a, uint32_t dom_b, uint32_t num_slots);`
Allocates a cacheline-aligned (64-byte) single-producer single-consumer (SPSC) lock-free shared memory channel between two domains. Allocates a hardware PKU key, tags shared memory with `pkey_mprotect()`, and grants read/write access to both domains.
* **Parameters:**
  * `dom_a`: Producer domain index.
  * `dom_b`: Consumer domain index.
  * `num_slots`: Slot count (must be a power of 2, e.g. 64, 128, 1024).
* **Returns:** Pointer to `struct ng_ipc_channel` on success, or `NULL` on error.

### `int ng_ipc_send(struct ng_ipc_channel *chan, const void *data, size_t len);`
Publishes a message into the channel ring buffer without kernel intervention.
* **Parameters:**
  * `chan`: Active IPC channel pointer.
  * `data`: Message payload buffer.
  * `len`: Message length in bytes ($\le$ `NG_IPC_MAX_DATA_PER_SLOT`, up to 32,744 bytes).
* **Returns:** `0` on success, or negative error code (`NG_IPC_ERR_FULL`).

### `int ng_ipc_recv(struct ng_ipc_channel *chan, void *buf, size_t max_len);`
Consumes the next message from the channel ring buffer.
* **Parameters:**
  * `chan`: Active IPC channel pointer.
  * `buf`: Output destination buffer.
  * `max_len`: Capacity of output buffer.
* **Returns:** Non-negative count of bytes copied on success, or negative error code (`NG_IPC_ERR_EMPTY`).

### `void ng_ipc_channel_destroy(struct ng_ipc_channel *chan);`
Unmaps shared ring memory and recycles the hardware PKU key for future channel allocations.

---

## 3. Hardware-Isolated Stack Pool (`nullgate_stack_pool.h`)

### `struct ng_stack_slot *ng_stack_pool_acquire(uint32_t domain_id, int pkey, size_t stack_size);`
Acquires an isolated stack slot with `PROT_NONE` guard pages from the thread-local stack pool. Recycled stacks are actively scrubbed with `memset` before assignment to prevent cross-domain data disclosure.
* **Parameters:**
  * `domain_id`: Target domain.
  * `pkey`: Hardware PKU key to tag the usable stack area.
  * `stack_size`: Usable stack capacity (default: 64KB).
* **Returns:** Pointer to `struct ng_stack_slot`, or `NULL` on failure.

### `void ng_stack_pool_release(struct ng_stack_slot *slot);`
Returns an acquired stack slot to the thread-local pool for reuse.

### `void ng_stack_pool_thread_cleanup(void);`
Unmaps and frees all stack slots allocated by the calling thread.

---

## 4. Transparent Library Preload Shim (`nullgate_shim.h`)

### `NG_INTERPOSE_FUNC_N(ret_type, func_name, domain_id, ...)`
Defines an interposition wrapper intercepting function calls to third-party libraries and routing them through `ng_enter()`. Available for argument counts $N \in \{0, 1, 2, 3, 4, 5, 6, 7, 8\}$.

### `NG_INTERPOSE_VOID_FUNC_N(func_name, domain_id, ...)`
Variant of interposition macro for functions with `void` return types.

### `void ng_shim_reset_depth(void);`
Safely resets thread-local interposition recursion depth (`t_shim_depth = 0`) following longjmp unwinds or return to `NG_DOMAIN_TRUSTED`.
