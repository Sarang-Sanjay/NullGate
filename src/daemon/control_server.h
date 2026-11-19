/*
 * NullGate — Security Daemon Control Server Header
 * Declares interfaces for the epoll-multiplexed UNIX domain control socket server.
 */

#ifndef NULLGATE_CONTROL_SERVER_H
#define NULLGATE_CONTROL_SERVER_H

#include <signal.h>
#include <stdbool.h>
#include <bpf/libbpf.h>

#include "nullgate_control.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ng_control_server;

/**
 * ng_control_server_create - Create and bind the daemon control socket.
 * @override_path: Optional socket path override (or NULL to use /run/nullgate/control.sock)
 *
 * Verifies/creates parent directory, unlinks stale socket, binds with 0600 mode,
 * and initializes epoll multiplexer.
 *
 * Returns pointer to server context on success, or NULL on error.
 */
struct ng_control_server *ng_control_server_create(const char *override_path);

/**
 * ng_control_server_run_loop - Run unified non-blocking epoll loop.
 * @srv: Control server context
 * @rb: libbpf audit ring_buffer context
 * @stop_flag: Pointer to volatile signal termination flag
 *
 * Multiplexes control socket clients and kernel BPF ring buffer in a single thread.
 * Returns 0 on clean exit, or negative errno on error.
 */
int ng_control_server_run_loop(struct ng_control_server *srv, struct ring_buffer *rb, volatile sig_atomic_t *stop_flag);

/**
 * ng_control_server_destroy - Close all client connections and unlink socket.
 * @srv: Control server context
 */
void ng_control_server_destroy(struct ng_control_server *srv);

#ifdef __cplusplus
}
#endif

#endif /* NULLGATE_CONTROL_SERVER_H */
