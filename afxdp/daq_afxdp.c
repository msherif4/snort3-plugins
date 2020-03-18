/*
** Copyright (C) 2019 Cisco and/or its affiliates. All rights reserved.
** Author: Mohamed S. Mahmoud <mmahmoud@cisco.com>

** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <syslog.h>
#include <daq_dlt.h>
#include <daq.h>
#include <daq_common.h>
#include <daq_module_api.h>
#include <net/if.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <poll.h>
#include <pthread.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/xsk.h>

#define DAQ_XDP_VERSION       1

#define DBG(xc, _fmt, args...)          \
    if (unlikely(xc->debug)) {     \
        fprintf(stdout, "\n"_fmt, ##args);   \
    }

#define XDP_DAQ_GETTID(xc)  (xc->xdp_interface_id)

#ifndef unlikely
#define unlikely(expr) __builtin_expect(!!(expr), 0)
#endif

#ifndef likely
#define likely(expr) __builtin_expect(!!(expr), 1)
#endif

#define static_always_inline static inline __attribute__ ((__always_inline__))

#define SET_ERROR(modinst, ...) daq_base_api.set_errbuf(modinst, __VA_ARGS__)
#define APP_NAME "xdp_ngdaq"
#define NUM_FRAMES (4 * 1024)
#define BATCH_SIZE 64
#define MAX_XDP_BUFS 255
#define XDP_DAQ_DEFAULT_POOL_SIZE 64
#define INVALID_UMEM_FRAME UINT64_MAX
#define MAX_NUM_INTERFACES 2
#define IN_SOCK_IDX  0
#define OUT_SOCK_IDX 1

/* XDP section */

#define XDP_FLAGS_UPDATE_IF_NOEXIST	(1U << 0)
#define XDP_FLAGS_SKB_MODE		(1U << 1)
#define XDP_FLAGS_DRV_MODE		(1U << 2)
#define XDP_FLAGS_HW_MODE		(1U << 3)
#define XDP_FLAGS_MODES			(XDP_FLAGS_SKB_MODE | \
                                 XDP_FLAGS_DRV_MODE | \
                                 XDP_FLAGS_HW_MODE)
#define XDP_FLAGS_MASK			(XDP_FLAGS_UPDATE_IF_NOEXIST | \
                                 XDP_FLAGS_MODES)

typedef uint32_t u32;
typedef uint64_t u64;

typedef struct _xdp_pkt_desc
{
    DAQ_Msg_t msg;
    DAQ_PktHdr_t pkthdr;
    uint8_t *data;
    unsigned int length;
    u64 addr;
    struct _xdp_pkt_desc *next;
} xdpPktDesc;

typedef struct _xdp_msg_pool
{
    xdpPktDesc *pool;
    xdpPktDesc *freelist;
    DAQ_MsgPoolInfo_t info;
} xdpifMsgPool;

typedef struct _xsk_umem_info {
    struct xsk_ring_prod fq; /* Fill Queue */
    struct xsk_ring_cons cq; /* Complete Queue */
    struct xsk_umem *umem;   /* User space memory */
    void *buffer;
} xsk_umem_info;

typedef struct _xsk_socket_info {
    struct xsk_ring_cons rx; /* Receive Queue */
    struct xsk_ring_prod tx; /* Transmit Queue */
    xsk_umem_info *umem; /* user-space memory */
    struct xsk_socket *xsk[MAX_NUM_INTERFACES];
    unsigned long rx_npkts;
    unsigned long tx_npkts;
    u32 outstanding_tx;
    uint64_t umem_frame_addr[NUM_FRAMES];
    uint32_t umem_frame_free;
} xsk_socket_info;

typedef struct xdp_context_
{
    char *device;
    int snaplen;
    int timeout;
    volatile DAQ_State state;
    volatile int interrupted;
    DAQ_Stats_t stats;
    DAQ_ModuleInstance_h modinst;
    xdpifMsgPool pool;
    unsigned dump;
    unsigned debug;
    unsigned zerocopy;
    uint64_t poll_calls;
    uint64_t non_poll_calls;
    u32 xdp_interface_id;
    xsk_socket_info *xsk;
    xsk_umem_info *umem;
    char opt_if[MAX_NUM_INTERFACES][IFNAMSIZ];
    int opt_ifindex[MAX_NUM_INTERFACES];
    int opt_queue;
    u32 prog_id;
} Xdp_Context_t;

static u32 thread_idx = 0;

static DAQ_VariableDesc_t xdp_variable_descriptions[] = {
    { "debug", "Enable traces to stdout", DAQ_VAR_DESC_FORBIDS_ARGUMENT },
    { "dump", "Enable packets dump to stdout", DAQ_VAR_DESC_FORBIDS_ARGUMENT },
    { "zc", "Zero copy enabled", DAQ_VAR_DESC_FORBIDS_ARGUMENT },
    { "queue", "Queue associated to the Interface", DAQ_VAR_DESC_FORBIDS_ARGUMENT },
};

static const char * xdpdaq_status_to_str[MAX_DAQ_RSTAT] = {
    "DAQ_RSTAT_OK",
    "DAQ_RSTAT_WOULD_BLOCK",
    "DAQ_RSTAT_TIMEOUT",
    "DAQ_RSTAT_EOF",
    "DAQ_RSTAT_INTERRUPTED",
    "DAQ_RSTAT_NOBUF",
    "DAQ_RSTAT_ERROR",
    "DAQ_RSTAT_INVALID",
};

static const DAQ_Verdict verdict_translation_table[MAX_DAQ_VERDICT] = {
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_PASS */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLOCK */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_REPLACE */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_WHITELIST */
    DAQ_VERDICT_BLOCK,      /* DAQ_VERDICT_BLACKLIST */
    DAQ_VERDICT_PASS,       /* DAQ_VERDICT_IGNORE */
    DAQ_VERDICT_BLOCK       /* DAQ_VERDICT_RETRY */
};

static DAQ_BaseAPI_t daq_base_api;

/******************************************************************************
 Name:  destroy_packet_pool

 Descr: Free daq packet pools

 IN:    Xdp_Context_t     *xc   - xdp thread context

 OUT:   None
*****************************************************************************/
static void destroy_packet_pool (Xdp_Context_t *xc)
{
    xdpifMsgPool *pool = &xc->pool;
    if (pool->pool) {
        free(pool->pool);
        pool->pool = NULL;
    }
    pool->freelist = NULL;
    pool->info.available = 0;
    pool->info.mem_size = 0;
}

/******************************************************************************
 Name:  create_packet_pool

 Descr: allocate daq packet pools

 IN:   Xdp_Context_t     *xc   - xdp thread context
       uint                size  - size of the daq pool and if its
                                   0 a default of 64 will be used.
 OUT:  int                 DAQ error code
*****************************************************************************/
static int create_packet_pool (Xdp_Context_t *xc, unsigned size)
{
    u32 i = 0;
    xdpifMsgPool *pool = &xc->pool;

    DBG(xc, "Enter: Thread %d size %d", XDP_DAQ_GETTID(xc), size);

    if (unlikely(size == 0)) {
        size = XDP_DAQ_DEFAULT_POOL_SIZE;
    }

    pool->pool = calloc(size, sizeof(xdpPktDesc));
    if (unlikely(!pool->pool)) {
        DBG(xc, "%s: Could not allocate %zu bytes for a packet descriptor pool!",
            __func__, sizeof(xdpPktDesc) * size);
        return DAQ_ERROR_NOMEM;
    }
    pool->info.mem_size = sizeof(xdpPktDesc) * size;
    while (i < size) {
        /*
        * Descriptor buffer will be assigned to xdp ring buffers when
        * daq receives packets.
        */
        xdpPktDesc *desc = &pool->pool[i++];
        pool->info.mem_size += xc->snaplen;

        /* Initialize non-zero invariant packet header fields. */
        DAQ_PktHdr_t *pkthdr = &desc->pkthdr;
        pkthdr->ingress_group = DAQ_PKTHDR_UNKNOWN;
        pkthdr->egress_group = DAQ_PKTHDR_UNKNOWN;

        /* Initialize non-zero invariant message header fields. */
        DAQ_Msg_t *msg = &desc->msg;
        msg->type = DAQ_MSG_TYPE_PACKET;
        msg->hdr_len = sizeof(desc->pkthdr);
        msg->hdr = &desc->pkthdr;
        msg->data = desc->data;
        msg->owner = xc->modinst;
        msg->priv = desc;

        /* Place it on the free list */
        desc->next = pool->freelist;
        pool->freelist = desc;

        pool->info.size++;
    }
    pool->info.available = pool->info.size;
    return DAQ_SUCCESS;
}

/******************************************************************************
 Name:  hex_dump

 Descr: utility to dump packet received by daq in log file for debugging

 IN:      Xdp_Context_t *xc      - pointer to xdp dap context
          void *pkt              - pointer to received packet
          size_t len             - packet length
          u64   addr             - buffer address in user-space

 OUT:   none
*****************************************************************************/
static void hex_dump(Xdp_Context_t *xc, void *pkt, size_t length, u64 addr)
{
    const unsigned char *address = (unsigned char *)pkt;
    const unsigned char *line = address;
    size_t line_size = 32;
    unsigned char c;
    char buf[32];
    int i = 0;

    if (!xc->dump) {
        return;
    }

    sprintf(buf, "addr=%lu", addr);
    fprintf(stdout, "length = %zu\n", length);
    fprintf(stdout, "%s | ", buf);
    while (length-- > 0) {
        fprintf(stdout, "%02X ", *address++);
        if (!(++i % line_size) || (length == 0 && i % line_size)) {
            if (length == 0) {
                while (i++ % line_size)
                    fprintf(stdout, "__ ");
            }
            fprintf(stdout, " | ");	/* right close */
            while (line < address) {
                c = *line++;
                fprintf(stdout, "%c", (c < 33 || c == 255) ? 0x2E : c);
            }
            fprintf(stdout, "\n");
            if (length > 0)
                fprintf(stdout, "%s | ", buf);
        }
    }
    fprintf(stdout, "\n");
}

/******************************************************************************
 Name:  xdp_daq_close

 Descr: xdp cleanup function whihc delete alloacted socket and xdp connection
        for specific xdp interface

 IN:     Xdp_Context_t *xc - xdp per thread context
 OUT:   int               return code 0 for success -1 for failure
*****************************************************************************/
static int xdp_daq_close (Xdp_Context_t *xc)
{
    int err = 0;
    DBG(xc, "Thread %d", XDP_DAQ_GETTID(xc));

    if (unlikely(!xc)) {
        return -1;
    }

    xc->state = DAQ_STATE_STOPPED;
    return err;
}

/******************************************************************************
 Name:  xdp_daq_shutdown

 Descr: xdp shutdown will delete xdp socket and all allocated memory and packet pools
        associated with this instance.

 IN:     Xdp_Context_t *xc - xdp per thread context
 OUT:   int               return code 0 for success -1 for failure
*****************************************************************************/
static void xdp_daq_shutdown (void *handle)
{
    Xdp_Context_t *xc = (Xdp_Context_t *) handle;

    DBG(xc, "Thread %d",  XDP_DAQ_GETTID(xc));
    xdp_daq_close(xc);
    if (xc->xsk) {
        xsk_socket__delete(xc->xsk->xsk[IN_SOCK_IDX]);
        xsk_socket__delete(xc->xsk->xsk[OUT_SOCK_IDX]);
    }
    if (xc->umem) {
        xsk_umem__delete(xc->umem->umem);
    }

    if (xc->device) {
        free(xc->device);
    }
    destroy_packet_pool(xc);
    free(xc);
}

/******************************************************************************
 Name:  mxdp_daq_get_vars

 Descr: Read snort process command line args
       used to enable debugging and packet tracing in xdp daq

 IN:      Xdp_Context_t *xc - xdp per thread context
          const DAQ_ModuleConfig_h modcfg - daq module configration handler
          DAQ_ModuleInstance_h modinst -   daq instance specific information

 OUT:   int               return code 0 for success -1 for failure
*****************************************************************************/
static int xdp_daq_get_vars (Xdp_Context_t *context,
                               const DAQ_ModuleConfig_h modcfg,
                               DAQ_ModuleInstance_h modinst)
{
    const char *varKey, *varValue;
    char *p;
    char *dev;
    size_t len;
    int num_intfs = 0;
    daq_base_api.config_first_variable(modcfg, &varKey, &varValue);

    while (varKey) {
        if (!strcmp(varKey, "dump")) {
            context->dump = (unsigned)strtoul(varValue, &p, 10);
            if (!*varValue || *p) {
                SET_ERROR(modinst, "invalid dump (%s)", varValue);
                goto err;
            }
        } else if (!strcmp(varKey, "debug")) {
            context->debug = (unsigned)strtoul(varValue, &p, 10);
            if (!*varValue || *p) {
                SET_ERROR(modinst, "invalid debug (%s)", varValue);
                goto err;
            }
        } else if (!strcmp(varKey, "zc")) {
            context->zerocopy = (unsigned)strtoul(varValue, &p, 10);
            if (!*varValue || *p) {
                SET_ERROR(modinst, "invalid zerocopy (%s)", varValue);
                goto err;
            }
        } else if (!strcmp(varKey, "queue")) {
            context->opt_queue = (unsigned)strtoul(varValue, &p, 10);
            if (!*varValue || *p) {
                SET_ERROR(modinst, "invalid queue (%s)", varValue);
                goto err;
            }
        }

        daq_base_api.config_next_variable(modcfg, &varKey, &varValue);
    }

    dev = context->device;
    while (*dev != '\0') {
        len = strcspn(dev, ":");
        if (len >= IFNAMSIZ) {
           SET_ERROR(modinst, "Interface name too long! (%zu)", len);
        }
	if (num_intfs > 2) {
           SET_ERROR(modinst, "Exceeded number of supported interfaces");
           goto err;
        }
        if (len != 0) {
           snprintf(context->opt_if[num_intfs++], len + 1, "%s", dev);
        } else {
           len = 1;
        }
        dev += len;
   }
    return 0;
err:
    return -1;
}

/******************************************************************************
 Name:  xdp_daq_module_load

 Descr: xdp daq load  xdp plugin

 IN:      const DAQ_BaseAPI_t *base_api - daq api handler

 OUT:   int               return daq error code
*****************************************************************************/
static int xdp_daq_module_load (const DAQ_BaseAPI_t *base_api)
{
    if (base_api->api_version != DAQ_BASE_API_VERSION ||
        base_api->api_size != sizeof(DAQ_BaseAPI_t)) {
        return DAQ_ERROR;
    }
    daq_base_api = *base_api;
    return DAQ_SUCCESS;
}

/******************************************************************************
 Name:  xdp_daq_module_unload

 Descr: xdp daq unload  xdp plugin

 IN:      None

 OUT:   int               return daq error code
*****************************************************************************/
static int xdp_daq_module_unload ()
{
    memset(&daq_base_api, 0, sizeof(daq_base_api));
    return DAQ_SUCCESS;
}

/******************************************************************************
 Name:  xdp_daq_get_variable_descs

 Descr: xdp daq read command line args

 IN:      const DAQ_VariableDesc_t **var_desc_table - pointer to xdp variables

 OUT:   int               return code 0 for success -1 for failure
*****************************************************************************/
static int xdp_daq_get_variable_descs (const DAQ_VariableDesc_t **var_desc_table)
{
    *var_desc_table = xdp_variable_descriptions;

    return sizeof(xdp_variable_descriptions) / sizeof(DAQ_VariableDesc_t);
}

/******************************************************************************
 Name:  xsk_umem_info

 Descr: xdp daq allocate UMEM info

 IN:      Xdp_Context_t *xc - xdp per thread context
          void * buffer - pointer to user space buffer
          uint64_t      - buffer size

 OUT:      xsk_umem_info *    return pointer to umem info struct or NULL
*****************************************************************************/
static xsk_umem_info * xdp_configure_umem (Xdp_Context_t  *xc,
                                           void           *buffer,
                                            uint64_t       size)
{
    xsk_umem_info *umem;
    struct xsk_umem_config cfg = {
        .fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
    };
    int ret;

    umem = calloc(1, sizeof(*umem));
    if (!umem) {
        DBG(xc, "Thread %d failed to allocate UMEM info",
            XDP_DAQ_GETTID(xc));
        return (NULL);
    }

    ret = xsk_umem__create(&umem->umem, buffer, size,
                           &umem->fq, &umem->cq, &cfg);
    if (unlikely(ret)) {
        DBG(xc, "Thread %d failed to create xdp umem err:%d",
            XDP_DAQ_GETTID(xc), ret);
        return (NULL);
    }

    umem->buffer = buffer;
    return umem;
}

static uint64_t xsk_alloc_umem_frame(xsk_socket_info *xsk)
{
	uint64_t frame;
	if (xsk->umem_frame_free == 0) {
		return INVALID_UMEM_FRAME;
    }
	frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
	xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
	return frame;
}

static void xsk_free_umem_frame(xsk_socket_info *xsk, uint64_t frame)
{
	assert(xsk->umem_frame_free < NUM_FRAMES);

	xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

static uint64_t xsk_umem_free_frames(xsk_socket_info *xsk)
{
	return xsk->umem_frame_free;
}

/******************************************************************************
 Name:  xdp_configure_socket

 Descr: xdp daq allocate socket info

 IN:      Xdp_Context_t *xc - xdp per thread context

 OUT:      xsk_socket_info *    return pointer to socket info struct or NULL
*****************************************************************************/
static xsk_socket_info * xdp_configure_socket (Xdp_Context_t  *xc)
{
    struct xsk_socket_config cfg;
    xsk_socket_info *xsk;
    int ret, i;
    u32 idx;

    xsk = calloc(1, sizeof(*xsk));
    if (unlikely(!xsk)) {
        DBG(xc, "Thread %d failed to allocate xdp socket info",
            XDP_DAQ_GETTID(xc));
        return (NULL);
    }

    xsk->umem = xc->umem;
    cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    cfg.libbpf_flags = 0;
    // Make sure the NIC support zero copy else will get bind ENOTSUPPORT
    if (xc->zerocopy) {
        cfg.bind_flags = XDP_ZEROCOPY;
        cfg.xdp_flags = XDP_FLAGS_MODES;
    } else {
        cfg.bind_flags = XDP_COPY;
        cfg.xdp_flags = XDP_FLAGS_SKB_MODE;
    }

    /*
     * create XSK input socket with 2K Rx and Tx queue rings.
     */
    ret = xsk_socket__create(&xsk->xsk[IN_SOCK_IDX], xc->opt_if[IN_SOCK_IDX],
                             xc->opt_queue, xsk->umem->umem,
                             &xsk->rx, &xsk->tx, &cfg);
    if (unlikely(ret)) {
        DBG(xc, "Thread %d failed to create xsk input socket err:%d",
            XDP_DAQ_GETTID(xc), ret);
        return (NULL);
    }

    ret = bpf_get_link_xdp_id(xc->opt_ifindex[IN_SOCK_IDX], &xc->prog_id,
                              cfg.xdp_flags);
    if (unlikely(ret)) {
        DBG(xc, "Thread %d bpf_get_link_xdp_id failed err:%d",
            XDP_DAQ_GETTID(xc), ret);
        return (NULL);
    }

    /*
     * Check if input interface and output interfaces are different "bridged mode"
     * then create additional socket that share the same UMEM pool.
     */
    if (strncmp(xc->opt_if[IN_SOCK_IDX], xc->opt_if[OUT_SOCK_IDX], IFNAMSIZ)) {
        /*
         * Create XSK output socket with 2K Rx and Tx queue rings.
	 * Note: this capability started in libbpf v0.0.5 and enhanced in v0.0.6
         */
        cfg.bind_flags = XDP_SHARED_UMEM;
        cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
        ret = xsk_socket__create(&xsk->xsk[OUT_SOCK_IDX],
                                 xc->opt_if[OUT_SOCK_IDX],
                                 xc->opt_queue, xsk->umem->umem,
                                 &xsk->rx, &xsk->tx, &cfg);
        if (unlikely(ret)) {
            DBG(xc, "Thread %d failed to create xsk output socket err:%d",
                XDP_DAQ_GETTID(xc), ret);
            return (NULL);
       }
    } else {
        xsk->xsk[OUT_SOCK_IDX] = xsk->xsk[IN_SOCK_IDX];
    }

	/* Initialize umem frame allocation */

	for (i = 0; i < NUM_FRAMES; i++) {
		xsk->umem_frame_addr[i] = i * XSK_UMEM__DEFAULT_FRAME_SIZE;
    }
	xsk->umem_frame_free = NUM_FRAMES;

    /*
     * reserve Producer Fill Queue ring with 2k entries.
     */
    ret = xsk_ring_prod__reserve(&xsk->umem->fq,
                                 XSK_RING_PROD__DEFAULT_NUM_DESCS,
                                 &idx);
    if (unlikely(ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)) {
        DBG(xc, "Thread %d xdp_ring_prod__reserve failed err:%d",
            XDP_DAQ_GETTID(xc), ret);
        return (NULL);
    }

    for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++) {
        *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx++) =
            xsk_alloc_umem_frame(xsk);
    }
    /*
     * inform Kernel that producer fill Queue is ready to receive packets.
     */
    xsk_ring_prod__submit(&xsk->umem->fq,
                          XSK_RING_PROD__DEFAULT_NUM_DESCS);

    return xsk;
}

/******************************************************************************
 Name:  xdp_daq_instantiate

 Descr: xdp daq initiailize instance

 IN:      const DAQ_ModuleConfig_h modcfg - daq module configration handler
          DAQ_ModuleInstance_h modinst -   daq instance specific information
          void               **ctxt_ptr - pointer to xdp per thread context

 OUT:   int               return code 0 for success -1 for failure
*****************************************************************************/
static int xdp_daq_instantiate (const DAQ_ModuleConfig_h  modcfg,
                                DAQ_ModuleInstance_h      modinst,
                                void                      **ctxt_ptr)
{
    Xdp_Context_t *xc;
    int rv = DAQ_ERROR, error;
    uint32_t pool_size = 0;
    void *bufs = NULL;

    xc = (Xdp_Context_t*)calloc(1, sizeof(*xc));
    if (unlikely(!xc)) {
        SET_ERROR(modinst, "Couldn't allocate memory for the context!");
        return DAQ_ERROR_NOMEM;
    }
    xc->modinst = modinst;
    xc->device = strdup(daq_base_api.config_get_input(modcfg));
    if (unlikely(!xc->device)) {
        SET_ERROR(modinst, "Couldn't allocate memory for the device string!");
        rv = DAQ_ERROR_NOMEM;
        goto err;
    }
    xc->snaplen = daq_base_api.config_get_snaplen(modcfg);
    xc->timeout = ((int)daq_base_api.config_get_timeout(modcfg) > 0) ?
                   (int)daq_base_api.config_get_timeout(modcfg)  : -1;
    if (unlikely(xdp_daq_get_vars(xc, modcfg, modinst))) {
        rv = DAQ_ERROR;
        goto err;
    }

    error = posix_memalign(&bufs, getpagesize(), /* PAGE_SIZE aligned */
                           NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE);
    if (unlikely(error)) {
        rv = DAQ_ERROR_NOMEM;
        goto err;
    }

    xc->xdp_interface_id = __atomic_fetch_add(&thread_idx, 1, __ATOMIC_SEQ_CST);
    xc->umem = xdp_configure_umem(xc, bufs, NUM_FRAMES * XSK_UMEM__DEFAULT_FRAME_SIZE);
    if (unlikely(!xc->umem)) {
        DBG(xc, "Thread %d failed to configure xdp umem",
            XDP_DAQ_GETTID(xc));
        rv = DAQ_ERROR;
        goto err;
    }

    xc->xsk = xdp_configure_socket(xc);
     if (unlikely(!xc->xsk)) {
        DBG(xc, "Thread %d failed to configure xdp socket",
            XDP_DAQ_GETTID(xc));
        rv = DAQ_ERROR;
        goto err;
    }

    /* Finally, create the message buffer pool. */
    pool_size = daq_base_api.config_get_msg_pool_size(modcfg);
    if (unlikely((rv = create_packet_pool(xc, pool_size)) != DAQ_SUCCESS)) {
        DBG(xc, "Thread %d failed to create packet pool",
            XDP_DAQ_GETTID(xc));
        goto err;
    }

    xc->state = DAQ_STATE_INITIALIZED;
    *ctxt_ptr = xc;
    return DAQ_SUCCESS;

err:
    if (bufs) {
        free(bufs);
    }
    xdp_daq_shutdown(xc);
    return rv;
}

/******************************************************************************
 Name:  xdp_daq_destroy

 Descr: xdp daq destroy call back

 IN:      Xdp_Context_t *xc - xdp per thread context

 OUT:   none
*****************************************************************************/
static void xdp_daq_destroy (void *handle)
{
    Xdp_Context_t *xc = (Xdp_Context_t *) handle;
    DBG(xc, "Enter: Thread %d", XDP_DAQ_GETTID(xc));
    xdp_daq_shutdown(handle);
}

/******************************************************************************
 Name:  xdp_daq_set_filter

 Descr: xdp daq set filter call back

 IN:      Xdp_Context_t *xc - xdp per thread context
          char            * filter - pointer to filer to use

 OUT:   int daq error code
*****************************************************************************/
static int xdp_daq_set_filter (void *handle, const char *filter)
{
    /* TODO */
    return DAQ_ERROR_NOTSUP;
}

/******************************************************************************
 Name:  xdp_daq_start

 Descr: xdp daq start daq functionality

 IN:      void *handle - xdp per thread context

 OUT:   int daq error code
*****************************************************************************/
static int xdp_daq_start (void *handle)
{
    Xdp_Context_t *xc = (Xdp_Context_t *) handle;
    DBG(xc, "Enter: Thread %d",  XDP_DAQ_GETTID(xc));
    xc->state = DAQ_STATE_STARTED;
    return DAQ_SUCCESS;
}

/******************************************************************************
 Name:  xdp_daq_inject

 Descr: xdp daq inject daq functionality

 IN:      void *handle - xdp per thread context
          DAQ_MsgType type
          const void *hdr
          const uint8_t *data
         uint32_t data_len
 OUT:   int daq error code
*****************************************************************************/
static int xdp_daq_inject (void *handle, DAQ_MsgType type, const void *hdr,
                             const uint8_t *data, uint32_t data_len)
{
    /* TODO */
    Xdp_Context_t *xc = (Xdp_Context_t *) handle;
    DBG(xc, "Enter: Thread %d",  XDP_DAQ_GETTID(xc));
    return DAQ_SUCCESS;
}

/******************************************************************************
 Name:  xdp_daq_inject_relative

 Descr: xdp daq inject relative daq functionality

 IN:      void *handle - xdp per thread context
          const DAQ_Msg_t *msg
          const uint8_t *data
         uint32_t data_len
         int reverse
 OUT:   int daq error code
*****************************************************************************/
static int xdp_daq_inject_relative (void *handle, const DAQ_Msg_t *msg, const
                                      uint8_t *data, uint32_t data_len, int reverse)
{
    /* TODO */
    Xdp_Context_t *xc = (Xdp_Context_t *) handle;
    DBG(xc, "Enter: Thread %d",  XDP_DAQ_GETTID(xc));
    return DAQ_SUCCESS;
}

/******************************************************************************
 Name:  xdp_daq_interrupt

 Descr: xdp daq interrupt daq functionality

 IN:      void *handle - xdp per thread context

 OUT:   int daq error code
*****************************************************************************/
static int xdp_daq_interrupt (void *handle)
{
    Xdp_Context_t *xc = (Xdp_Context_t *) handle;
    DBG(xc, "Enter: Thread %d",  XDP_DAQ_GETTID(xc));
    xc->interrupted = true;
    return DAQ_SUCCESS;
}

/******************************************************************************
 Name:  xdp_daq_stop

 Descr: xdp daq stop daq functionality

 IN:      void *handle - xdp per thread context

 OUT:   int daq error code
*****************************************************************************/
static int xdp_daq_stop (void *handle)
{
    Xdp_Context_t *xc = (Xdp_Context_t *) handle;
    DBG(xc, "Enter: Thread %d",  XDP_DAQ_GETTID(xc));
    xdp_daq_close(xc);
    return DAQ_SUCCESS;
}

/******************************************************************************
 Name:  xdp_daq_ioctl

 Descr: xdp daq ioctl daq functionality

 IN:      void *handle - xdp per thread context
          DAQ_IoctlCmd cmd
          void *arg
        size_t arglen
 OUT:   int daq error code
*****************************************************************************/
static int xdp_daq_ioctl (void *handle, DAQ_IoctlCmd cmd,
                            void *arg, size_t arglen)
{
   /* TODO */
    Xdp_Context_t *xc = (Xdp_Context_t *) handle;

    DBG(xc, "Enter: Thread %d",  XDP_DAQ_GETTID(xc));
    return DAQ_SUCCESS;
}

/******************************************************************************
 Name:  xdp_daq_get_stats

 Descr: xdp read daq get stats

 IN:      void *handle        - xdp per thread context
          DAQ_Stats_t * stats

 OUT:   int daq error code
*****************************************************************************/
static int xdp_daq_get_stats (void *handle, DAQ_Stats_t * stats)
{
    Xdp_Context_t *xc = (Xdp_Context_t *) handle;
    DBG(xc, "Enter: Thread %d",  XDP_DAQ_GETTID(xc));

    memcpy(stats, &xc->stats, sizeof(DAQ_Stats_t));
    return DAQ_SUCCESS;
}

/******************************************************************************
 Name:  xdp_daq_get_reset_stats

 Descr: xdp read daq reset stats

 IN:      void *handle        - xdp per thread context

 OUT:   int daq error code
*****************************************************************************/
static void xdp_daq_reset_stats (void *handle)
{
    Xdp_Context_t *xc = (Xdp_Context_t *) handle;
    DBG(xc, "Enter: Thread %d",  XDP_DAQ_GETTID(xc));
    memset(&xc->stats, 0, sizeof(DAQ_Stats_t));;
}

/******************************************************************************
 Name:  xdp_daq_get_snaplen

 Descr: xdp read daq reset stats

 IN:      void *handle        - xdp per thread context

 OUT:   int  buffer size
*****************************************************************************/
static int xdp_daq_get_snaplen (void *handle)
{
    Xdp_Context_t *xc = (Xdp_Context_t *) handle;
    DBG(xc, "Enter: Thread %d",  XDP_DAQ_GETTID(xc));
    return xc->snaplen;
}

/******************************************************************************
 Name:  xdp_daq_get_capabilities

 Descr: xdp get all supported capabilities

 IN:      void *handle        - xdp per thread context

 OUT:   int capabilities
*****************************************************************************/
static uint32_t xdp_daq_get_capabilities (void *handle)
{
    uint32_t capabilities = DAQ_CAPA_BLOCK          |
                            DAQ_CAPA_REPLACE        |
                            DAQ_CAPA_INJECT         |
                            DAQ_CAPA_UNPRIV_START   |
                            DAQ_CAPA_INTERRUPT      |
                            DAQ_CAPA_DEVICE_INDEX;
    Xdp_Context_t *xc = (Xdp_Context_t *) handle;

#ifdef LIBPCAP_AVAILABLE
    capabilities |= DAQ_CAPA_BPF;
#endif
    DBG(xc, "Enter: Thread %d capabilities = 0x%08x",
        XDP_DAQ_GETTID(xc), capabilities);
    return capabilities;
}

/******************************************************************************
 Name:  xdp_daq_get_datalink_type

 Descr: xdp get datalink type

 IN:      void *handle        - xdp per thread context

 OUT:   int datalink type
*****************************************************************************/
static int xdp_daq_get_datalink_type (void *handle)
{
    Xdp_Context_t *xc = (Xdp_Context_t *) handle;
    DBG(xc, "Enter: Thread %d",  XDP_DAQ_GETTID(xc));
    return DLT_EN10MB;
}

/******************************************************************************
 Name:  xdp_daq_rx_packets

Descr: xdp receive packets from the kernel to user space

 IN:      Xdp_Context_t *xc        - xdp per thread context

 OUT:   int number of packets received
*****************************************************************************/
static int xdp_daq_rx_packets (Xdp_Context_t *xc, u32 *idx_rx, u32 *idx_fq)
{
    unsigned int rcvd, frames;
    xsk_socket_info *xsk = xc->xsk;
    int ret, i;

    *idx_rx = *idx_fq = 0;

    /*
     * Check consumer ring see if there is any packets received.
     */
    rcvd = xsk_ring_cons__peek(&xsk->rx, BATCH_SIZE, idx_rx);
    if (!rcvd) {
        return 0;
    }
    /*
     * Read as many frames as possible to batch rx packets
     */
    frames = xsk_prod_nb_free(&xsk->umem->fq,
	                      xsk_umem_free_frames(xsk));

    if (frames > 0) {
        /*
         * findout which entry in the Fill Queue the producer "kernel" has populated.
         */
        ret = xsk_ring_prod__reserve(&xsk->umem->fq, frames, idx_fq);
        /*
         * make sure number of produced entries match what the consumer's
         */
        while (unlikely(ret != frames)) {
            if (ret < 0) {
                DBG(xc, "Thread %d xsk_ring_prod__reserve failed ret %d",
                    XDP_DAQ_GETTID(xc), ret);
                return 0;
            }
            ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd, idx_fq);
        }
	for (i = 0; i < frames; i++) {
            *xsk_ring_prod__fill_addr(&xsk->umem->fq, *idx_fq++) =
                                      xsk_alloc_umem_frame(xsk);
        }
	xsk_ring_prod__submit(&xsk->umem->fq, frames);
    }
    return (rcvd);
}

/******************************************************************************
 Name:  xdp_daq_wait_for_packet

Descr: xdp wait for poll events to know if there are packets available to process

 IN:      Xdp_Context_t *xc        - xdp per thread context

 OUT:   DAQ_RecvStatus return daq receieve status
*****************************************************************************/
static_always_inline DAQ_RecvStatus xdp_daq_wait_for_packet (Xdp_Context_t *xc)
{
    struct pollfd fd;
    int ret, nfd = 1;
    int timeout = xc->timeout;

    memset(&fd, 0, sizeof(fd));
    fd.fd = xsk_socket__fd(xc->xsk->xsk[IN_SOCK_IDX]);
    fd.events = POLLIN;

    xc->poll_calls++;
    while (timeout != 0) {
        if (xc->interrupted) {
            xc->interrupted = false;
            return DAQ_RSTAT_INTERRUPTED;
        }

        int poll_timeout;
        if (timeout >= 1000) {
            poll_timeout = 1000;
            timeout -= 1000;
        } else if (timeout > 0) {
            poll_timeout = timeout;
            timeout = 0;
        } else {
            poll_timeout = 1000;
        }

        ret = poll(&fd, nfd, poll_timeout);
        if (ret <= 0) {
            continue;
        }
        return DAQ_RSTAT_OK;
    }
    return DAQ_RSTAT_TIMEOUT;
}

/******************************************************************************
 Name:  xdp_daq_msg_receive

 Descr: xdp packets receive daq plugin call back

 IN:    void             *handle  - xdp context
        const unsigned   max_recv - Max packets received by default its set to 64
                                     use --daq-batch-size to change it if needed
        const            DAQ_Msg_t *msgs[] - array of received packets
        DAQ_RecvStatus   *rstat            - pointer to receive return code

OUT:    int daq error code
*****************************************************************************/
static unsigned xdp_daq_msg_receive (void             *handle,
                                     const unsigned   max_recv,
                                     const            DAQ_Msg_t *msgs[],
                                     DAQ_RecvStatus   *rstat)
{
    Xdp_Context_t *xc = (Xdp_Context_t *) handle;
    DAQ_RecvStatus status = DAQ_RSTAT_OK;
    struct timeval ts = { 0 };
    int recv_burst, c = 0, i;
    xsk_socket_info *xsk = xc->xsk;
    xdpPktDesc *desc;
    DAQ_Msg_t *msg;
    DAQ_PktHdr_t *daqhdr;

    DBG(xc, "Enter: Thread %d max_recv %u", XDP_DAQ_GETTID(xc), max_recv);

    while (c < max_recv) {
        u32 idx_rx = 0, idx_fq = 0;
        if (xc->interrupted) {
            xc->interrupted = false;
            status = DAQ_RSTAT_INTERRUPTED;
            break;
        }

        recv_burst = xdp_daq_rx_packets(xc, &idx_rx, &idx_fq);
        if (recv_burst) {
            xc->non_poll_calls++;
            gettimeofday(&ts, NULL);
        } else {
             if (c != 0) {
                status = DAQ_RSTAT_WOULD_BLOCK;
                break;
            }
            status = xdp_daq_wait_for_packet(xc);
            if (status != DAQ_RSTAT_OK) {
                break;
            }
            recv_burst = xdp_daq_rx_packets(xc, &idx_rx, &idx_fq);
        }

        for (i = 0; (i < recv_burst) && (c < max_recv); i++) {
            /*
             * get the rx queue buffer index in Umem array and the packet length.
             */
            u64 addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
            u32 len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->len;
            char *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

            desc = xc->pool.freelist;
            if (unlikely(!desc)) {
                status = DAQ_RSTAT_NOBUF;
                goto err;
            }

            hex_dump(xc, pkt, len, addr);

            xc->stats.packets_received++;
            desc->data = (uint8_t *)pkt;
            desc->length = len;
            desc->addr = addr;
            msg = &desc->msg;
            msg->data_len = len;
            msg->data = desc->data;

            daqhdr = &desc->pkthdr;

            daqhdr->ts = ts;
            daqhdr->pktlen = len;
            daqhdr->flags = 0;
            daqhdr->opaque = 0;
            daqhdr->address_space_id = 0;

            xc->pool.freelist = desc->next;
            desc->next = NULL;
            xc->pool.info.available--;
            msgs[c] = &desc->msg;
            c++;
            idx_rx++;
        }

        xsk->rx_npkts += recv_burst;
    }
err:
    DBG(xc, "Exit: Thread %d with status %s rx count %d",
        XDP_DAQ_GETTID(xc), xdpdaq_status_to_str[status], c);

    *rstat = status;
    return c;
}

/******************************************************************************
 Name:  xdp_daq_kick_tx

Descr: xdp system call to transmit the packets using XSK socket

 IN:      xsk_socket_info *xsk        - xdp socket info struct

 OUT:   none
*****************************************************************************/
static void xdp_daq_kick_tx (Xdp_Context_t *xc, xsk_socket_info *xsk)
{
    int ret;

    ret = sendto(xsk_socket__fd(xsk->xsk[OUT_SOCK_IDX]),
				 NULL, 0, MSG_DONTWAIT, NULL, 0);
    if (ret >= 0 || errno == ENOBUFS || errno == EAGAIN || errno == EBUSY) {
        return;
    }

    DBG(xc, "Thread %d sending to XSK socket failed ret %d",
        XDP_DAQ_GETTID(xc), errno);
}

/******************************************************************************
 Name:  xdp_tx_packet

Descr: xdp transmit one packet over XSK socket

 IN:      Xdp_Context_t *xc        - xdp per thread context
          uint8_t *pkt - pointer to packet
          uint64_t addr - buffer for the packet to send
	  uint32_t len  - packet length

 OUT:   none
*****************************************************************************/
static void xdp_tx_packet (Xdp_Context_t *xc, uint8_t * pkt, u64 addr, u32 len)
{
    xsk_socket_info *xsk = xc->xsk;
    u32 idx_cq = 0, idx = 0;

    if (xsk_ring_prod__reserve(&xsk->tx, 1, &idx) == 1) {
        xsk_ring_prod__tx_desc(&xsk->tx, idx)->addr = addr;
        xsk_ring_prod__tx_desc(&xsk->tx, idx)->len = len;
    }

    xsk_ring_prod__submit(&xsk->tx, 1);
    xsk->outstanding_tx ++;

    /*
     * FIXME: its possible send isn't done yet so we may need delay putting buffers to complete
     *  queue.
     */
    xdp_daq_kick_tx(xc, xsk);

    /* re-add completed Tx buffers */
    if (xsk_ring_cons__peek(&xsk->umem->cq, 1, &idx_cq) == 1) {
        xsk_free_umem_frame(xsk,
			    *xsk_ring_cons__comp_addr(&xsk->umem->cq, idx_cq));
        xsk_ring_cons__release(&xsk->umem->cq, 1);
        xsk->outstanding_tx --;
        xsk->tx_npkts ++;
    }
}

/******************************************************************************
 Name:  xdp_daq_msg_finalize

 Descr: xdp single packet transmit daq plugin call back

 IN:        void *handle            - xdp context
            const DAQ_Msg_t *msg    - pointer to the packet to transmit
            DAQ_Verdict verdict     - verdict based of snort inspection

 OUT:   int              return daq error code
*****************************************************************************/
static int xdp_daq_msg_finalize (void *handle,
                                 const DAQ_Msg_t *msg,
                                 DAQ_Verdict verdict)
{
    Xdp_Context_t *xc = (Xdp_Context_t *)handle;
    xsk_socket_info *xsk = xc->xsk;
    uint8_t *pkt = msg->data;
    xdpPktDesc *desc = (xdpPktDesc *) msg->priv;

    xc->stats.verdicts[verdict]++;

    verdict = verdict_translation_table[verdict];
    if (verdict == DAQ_VERDICT_PASS) {
        xdp_tx_packet(xc, pkt, desc->addr, desc->length);
    }

    /* Toss the descriptor back on the free list for reuse. */
    desc->next = xc->pool.freelist;
    xc->pool.freelist = desc;
    xc->pool.info.available++;

    /*
     * Mark Fill queue as available for kernel reuse.
     */
    xsk_ring_cons__release(&xsk->rx, xsk->rx_npkts);

    return DAQ_SUCCESS;
}

/******************************************************************************
 Name:  xdp_daq_get_msg_pool_info

 Descr: xdp get allocated daq pool info

 IN:        void *handle            - xdp context
            DAQ_MsgPoolInfo_t *info - daq msg pool info

 OUT:   int               return daq error code
*****************************************************************************/
static int xdp_daq_get_msg_pool_info (void *handle, DAQ_MsgPoolInfo_t *info)
{
    Xdp_Context_t *xc = (Xdp_Context_t *) handle;
    DBG(xc, "Enter: Thread %d",  XDP_DAQ_GETTID(xc));

    *info = xc->pool.info;
    return DAQ_SUCCESS;
}

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const  DAQ_ModuleAPI_t DAQ_MODULE_DATA =
#else
const  DAQ_ModuleAPI_t afxdp_daq_module_data =
#endif
{
    /* .api_version = */ DAQ_MODULE_API_VERSION,
    /* .api_size = */ sizeof(DAQ_ModuleAPI_t),
    /* .module_version = */ DAQ_XDP_VERSION,
    /* .name = */ "afxdp",
    /* .type = */ DAQ_TYPE_INLINE_CAPABLE | DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
    /* .load = */ xdp_daq_module_load,
    /* .unload = */ xdp_daq_module_unload,
    /* .get_variable_descs = */ xdp_daq_get_variable_descs,
    /* .instantiate  = */ xdp_daq_instantiate,
    /* .destroy = */ xdp_daq_destroy,
    /* .set_filter = */ xdp_daq_set_filter,
    /* .start = */ xdp_daq_start,
    /* .inject = */ xdp_daq_inject,
    /* .inject_relative = */ xdp_daq_inject_relative,
    /* .interrupt = */ xdp_daq_interrupt,
    /* .stop = */ xdp_daq_stop,
    /* .ioctl = */ xdp_daq_ioctl,
    /* .get_stats = */ xdp_daq_get_stats,
    /* .reset_stats = */ xdp_daq_reset_stats,
    /* .get_snaplen = */ xdp_daq_get_snaplen,
    /* .get_capabilities = */ xdp_daq_get_capabilities,
    /* .get_datalink_type = */ xdp_daq_get_datalink_type,
    /* .config_load = */ NULL,
    /* .config_swap = */ NULL,
    /* .config_free = */ NULL,
    /* .msg_receive = */ xdp_daq_msg_receive,
    /* .msg_finalize = */ xdp_daq_msg_finalize,
    /* .get_msg_pool_info = */ xdp_daq_get_msg_pool_info,
};