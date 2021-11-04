/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef FLB_IO_H
#define FLB_IO_H

#include <monkey/mk_core.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_coro.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_upstream.h>

/* Coroutine status 'flb_coro.status' */
#define FLB_IO_CONNECT     0  /* thread issue a connection request */
#define FLB_IO_WRITE       1  /* thread wants to write() data      */

/* Network operation modes */
#define FLB_IO_TCP         1  /* use plain TCP                          */
#define FLB_IO_TLS         2  /* use TLS/SSL layer                      */
#define FLB_IO_OPT_TLS     4  /* use TCP and optional TLS               */
#define FLB_IO_ASYNC       8  /* use async mode (depends on event loop) */
#define FLB_IO_TCP_KA     16  /* use async mode (depends on event loop) */

/* Other features */
#define FLB_IO_IPV6       32  /* network I/O uses IPv6                  */

/* IO Wait */
#define FLB_IO_WAIT_ERROR      0
#define FLB_IO_WAIT_TIMEOUT    1
#define FLB_IO_WAIT_COMPLETE   2
typedef int flb_io_wait_ret;

int flb_io_net_connect(struct flb_upstream_conn *u_conn,
                       struct flb_coro *th);

/*
 * Wait for connection via async:mk_event_loop or sync:poll(2)
 * Uses monkey event loop if async,
 * Otherwise sync blocking wait.
 * 
 * currently timeout only supported for sync waits
 * 
 * If timeout_ms is -1, then there is no timeout.
 * 
 * u_conn->coro and u_conn->fd must be set.
 * Return FLB_IO_WAIT_ERROR on failure
 * Return FLB_IO_WAIT_TIMEOUT on timeout
 * Return FLB_IO_WAIT_COMPLETE on complete
 * 
 * It is the responsability of the caller to set u_conn->coro is async
 * 
 * @param co may be set to null if sync
 * 
 * @param mask is an event types mask composed of MK_EVENT_<READ, WRITE, ...>
 *  or the equivalent POLL<IN, OUT, ...>
 */
flb_io_wait_ret flb_io_wait(struct flb_upstream_conn *u_conn, uint32_t mask,
                           struct flb_coro *co);

int flb_io_net_write(struct flb_upstream_conn *u, const void *data,
                     size_t len, size_t *out_len);
ssize_t flb_io_net_read(struct flb_upstream_conn *u, void *buf, size_t len);

#endif
