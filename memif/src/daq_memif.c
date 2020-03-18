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
#include <ctype.h>
#include <syslog.h>
#include <daq_dlt.h>
#include <daq.h>
#include <daq_common.h>
#include <daq_module_api.h>

#include <libmemif.h>
#include <sys/epoll.h>
#include <signal.h>
#include <pthread.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <secmod/secmod_shared_export.h>

#define DAQ_MEMIF_VERSION       1

#define DBG(mc, _fmt, args...)          \
    if (PREDICT_FALSE(mc->debug)) {     \
        clib_warning (_fmt, ## args);   \
    }
#define DEF_MEMIF_RX_QUEUES   4
#define DEF_MEMIF_TX_QUEUES   4
#define MEMIF_IFACE_RX_QUEUES MAX_MEMIF_QUEUES
#define MEMIF_IFACE_TX_QUEUES MAX_MEMIF_QUEUES
#define MEMIF_IFACE_BUFFER_SIZE 2048
#define MEMIF_IFACE_LOG2_RING_SIZE 11

typedef struct _memif_pkt_desc
{
    DAQ_Msg_t msg;
    union {
        DAQ_PktHdr_t pkthdr;
        Flow_Stats_t session;
    };
    uint8_t *data;
    unsigned int length;
    uint8_t qid;
    uint8_t buf_idx;
    struct _memif_pkt_desc *next;
} MemifPktDesc;

typedef struct _memif_msg_pool
{
    MemifPktDesc *pool;
    MemifPktDesc *freelist;
    DAQ_MsgPoolInfo_t info;
} MemifMsgPool;

typedef struct memif_context_
{
    char *device;
    int snaplen;
    int timeout;
    int epfd;
    volatile DAQ_State state;
    volatile int interrupted;
    DAQ_Stats_t stats;
    DAQ_ModuleInstance_h modinst;
    MemifMsgPool pool;
    unsigned loopback;
    unsigned dump;
    unsigned debug;
    uint64_t poll_calls;
    uint64_t non_poll_calls;
    uint64_t max_rx_burst;
    uint64_t num_rx_bursts;
    uint64_t num_rx_packets;
    uword *error_string_by_error_number;

    u32 memif_interface_id;

    memif_conn_handle_t conn;
    memif_per_thread_main_handle_t pt_handler;
    memif_socket_handle_t sock;
    memif_buffer_t *bufs[MEMIF_IFACE_RX_QUEUES];
    uint64_t tx_buf_num[MEMIF_IFACE_TX_QUEUES];
    uint64_t rx_buf_num[MEMIF_IFACE_RX_QUEUES];
    u8 ip_addr[4];
    /*
     * rx_now: represents number of packets received in single rx burst
     * from a specific Memif interface.
     */
    u16 rx_now[MEMIF_IFACE_RX_QUEUES];
    /*
     * rx_idx: represnents the actual number of proceesed packets in
     * Rx queue for a specific memif interface,
     * this introduced because memif burst size is 256 packets while snort
     * burst size by default is 64 packets, so its possible we receive a large patch
     * from memif master and break it down into small patches to snort.
     */
    u16 rx_idx[MEMIF_IFACE_RX_QUEUES];
} Memif_Context_t;

static int memif_sock_id_offset = 1;
static int memif_num_rx_queues  = DEF_MEMIF_RX_QUEUES;
static int memif_num_tx_queues  = DEF_MEMIF_TX_QUEUES;
static int thread_idx = 0;
static DAQ_VariableDesc_t memif_variable_descriptions[] = {
    { "debug", "Enable traces to stdout", DAQ_VAR_DESC_FORBIDS_ARGUMENT },
    { "dump", "Enable packets dump to stdout", DAQ_VAR_DESC_FORBIDS_ARGUMENT },
    { "loopback", "Enable loopback the memif interface", DAQ_VAR_DESC_FORBIDS_ARGUMENT },
};
static const char * memifdaq_status_to_str[MAX_DAQ_RSTAT] = {
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
#define SET_ERROR(modinst, ...) daq_base_api.set_errbuf(modinst, __VA_ARGS__)

#define MAX_MEMIF_BUFS 256
#define APP_NAME "memif_ngdaq"
#define IFACE_NAME  "memif_ngdaq_iface"
#define MEMIF_SOCK_NAME "/run/vpp/memif%02d.sock"
#define MEMIF_DAQ_GETTID(mc)  (mc->memif_interface_id)
#define MEMIF_DAQ_DEFAULT_POOL_SIZE 64

static_always_inline void memif_daq_loopback (void *handle, 
                                              const DAQ_Msg_t *msgs[],
                                              int msg_index);
/******************************************************************************
 Name:  destroy_packet_pool

 Descr: Free daq packet pools

 IN:    Memif_Context_t     *mc   - Memif thread context

 OUT:   None
*****************************************************************************/
static void destroy_packet_pool (Memif_Context_t *mc)
{
    MemifMsgPool *pool = &mc->pool;
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

 IN:   Memif_Context_t     *mc   - Memif thread context
       uint                size  - size of the daq pool and if its
                                   0 a default of 64 will be used.
 OUT:  int                 DAQ error code
*****************************************************************************/
static int create_packet_pool (Memif_Context_t *mc, unsigned size)
{
    u32 i = 0;
    MemifMsgPool *pool = &mc->pool;

    DBG(mc, "Enter: Thread %d size %d", MEMIF_DAQ_GETTID(mc), size);

    if (PREDICT_FALSE(size == 0)) {
        size = MEMIF_DAQ_DEFAULT_POOL_SIZE;
    }

    pool->pool = calloc(size, sizeof(MemifPktDesc));
    if (PREDICT_FALSE(!pool->pool)) {
        DBG(mc, "%s: Could not allocate %zu bytes for a packet descriptor pool!",
            __func__, sizeof(MemifPktDesc) * size);
        return DAQ_ERROR_NOMEM;
    }
    pool->info.mem_size = sizeof(MemifPktDesc) * size;
    while (i < size) {
        /*
        * Descriptor buffer will be assigned to memif ring buffers when
        * daq receives packets.
        */
        MemifPktDesc *desc = &pool->pool[i++];
        desc->data = NULL;
        pool->info.mem_size += mc->snaplen;

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
        msg->owner = mc->modinst;
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
 Name:  add_epoll_fd

 Descr: wrapper function for epoll system call to add entries associated with
       epoll instance for epfd

 IN:    int     epfd   - epoll file descriptor
        int     fd     - target file descriptior that add operation will be for
        uint32  events -  epoll events
 OUT:   int               return code 0 for success -1 for failure
*****************************************************************************/
static int add_epoll_fd (int epfd, int fd, uint32_t events)
{
    if (PREDICT_FALSE(fd < 0)) {
        clib_warning("%s: Invalid fd %d", __FUNCTION__, fd);
        return -1;
    }
    struct epoll_event evt;
    memset(&evt, 0, sizeof(evt));
    evt.events = events;
    evt.data.fd = fd;
    if (PREDICT_FALSE(epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &evt) < 0)) {
        clib_warning("%s: epoll_ctl: %s fd %d",
                     __FUNCTION__, strerror(errno), fd);
        return 0;
    }
    return 0;
}

/******************************************************************************
 Name:  mod_epoll_fd

 Descr: wrapper function for epoll system call to modify entries associated with
        epoll instance for epfd

 IN:    int     epfd   - epoll file descriptor
        int     fd     - target file descriptior that add operation will be for
        uint32  events -  epoll events
 OUT:   int               return code 0 for success -1 for failure
*****************************************************************************/
static int mod_epoll_fd (int epfd, int fd, uint32_t events)
{
    if (PREDICT_FALSE(fd < 0)) {
        clib_warning("%s: Invalid fd %d", __FUNCTION__, fd);
        return -1;
    }
    struct epoll_event evt;
    memset(&evt, 0, sizeof(evt));
    evt.events = events;
    evt.data.fd = fd;
    if (PREDICT_FALSE(epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &evt) < 0)) {
        clib_warning("%s: epoll_ctl: %s fd %d",
                     __FUNCTION__, strerror(errno), fd);
        return 0;
    }
    return 0;
}

/******************************************************************************
 Name:  del_epoll_fd

 Descr: wrapper function for epoll system call to delete entries associated with
        epoll instance for epfd

 IN:    int     epfd   - epoll file descriptor
        int     fd     - target file descriptior that add operation will be for
 OUT:   int               return code 0 for success -1 for failure
*****************************************************************************/
static int del_epoll_fd (int epfd, int fd)
{
    if (PREDICT_FALSE(fd < 0)) {
        clib_warning("%s: Invalid fd %d", __FUNCTION__, fd);
        return -1;
    }
    struct epoll_event evt;
    memset(&evt, 0, sizeof(evt));
    if (PREDICT_FALSE(epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &evt) < 0)) {
        clib_warning("%s: epoll_ctl: %s fd %d",
                     __FUNCTION__, strerror(errno), fd);
        return 0;
    }
    return 0;
}

/******************************************************************************
 Name:  control_fd_update

 Descr: control fd update callback registered during memif initialization

 IN:    int     fd      - target file descriptior that add operation will be for
        uint32  events  -  epoll events
        void    *handle - Opaque handle used to pass memif context
 OUT:   int               return code 0 for success -1 for failure
*****************************************************************************/
static int control_fd_update (int fd, uint8_t events, void *handle)
{
    Memif_Context_t *mc = (Memif_Context_t *) handle;
    u32 evt = 0;

    if (PREDICT_FALSE(mc == NULL)) {
       clib_warning("%s: Invalid Memif Context fd %d events %d",
                    __FUNCTION__, fd, events);
        return -1;
    }

    DBG(mc, "Thread %d: fd %d and events %02X",
        MEMIF_DAQ_GETTID(mc), fd, events);

    /* convert memif event definitions to epoll events */
    if (events & MEMIF_FD_EVENT_DEL) {
        return del_epoll_fd(mc->epfd, fd);
    }
    if (events & MEMIF_FD_EVENT_READ) {
        evt |= EPOLLIN;
    }
    if (events & MEMIF_FD_EVENT_WRITE) {
        evt |= EPOLLOUT;
    }
    if (events & MEMIF_FD_EVENT_MOD) {
        return mod_epoll_fd(mc->epfd, fd, evt);
    }
    return add_epoll_fd(mc->epfd, fd, evt);
}

/******************************************************************************
 Name:  memif_daq_close

 Descr: Memif cleanup function whihc delete alloacted socket and memif connection
        for specific memif interface

 IN:     Memif_Context_t *mc - Memif per thread context
 OUT:   int               return code 0 for success -1 for failure
*****************************************************************************/
static int memif_daq_close (Memif_Context_t *mc)
{
    int err = 0;
    DBG(mc, "Thread %d", MEMIF_DAQ_GETTID(mc));

    if (PREDICT_FALSE(!mc)) {
        return -1;
    }

    err = memif_delete(&mc->conn);
    if (PREDICT_FALSE(err != MEMIF_ERR_SUCCESS)) {
        DBG(mc, "Thread %d :memif_delete: failed with (%s)",
            MEMIF_DAQ_GETTID(mc), memif_strerror(err));
    }

    err = memif_delete_socket(&mc->sock);
    if (PREDICT_FALSE(err != MEMIF_ERR_SUCCESS)) {
        DBG(mc, "Thread %d :memif_delete_socket: failed with (%s)",
            MEMIF_DAQ_GETTID(mc), memif_strerror(err));
        err = -1;
    }
    memif_per_thread_cleanup(&mc->pt_handler);
    mc->state = DAQ_STATE_STOPPED;
    return err;
}

/******************************************************************************
 Name:  memif_daq_shutdown

 Descr: Memif shutdown will delete memif socket and all allocated memory and packet pools
        associated with this instance.

 IN:     Memif_Context_t *mc - Memif per thread context
 OUT:   int               return code 0 for success -1 for failure
*****************************************************************************/
static void memif_daq_shutdown (void *handle)
{
    Memif_Context_t *mc = (Memif_Context_t *) handle;
    int i;

    DBG(mc, "Thread %d",  MEMIF_DAQ_GETTID(mc));
    memif_daq_close(mc);
    free(mc->device);
    for (i = 0; i < memif_num_rx_queues; i++) {
        free(mc->bufs[i]);
    }
    destroy_packet_pool(mc);
    free(mc);
}

/******************************************************************************
 Name:  on_connect

 Descr: call back registered when memif_create is invoked to notify daq when memif  handshake
        reach to connected state

 IN:      memif_conn_handle_t conn  - memif connection handler alloaced during memif_init and its also
                                      cached in memif context
          void                *private_ctx - opague handler to cary memif context back to daq.
 OUT:   int               return code 0 for success -1 for failure
*****************************************************************************/
static int on_connect (memif_conn_handle_t conn, void *private_ctx)
{
    Memif_Context_t *mc = (Memif_Context_t *)private_ctx;
    int qid;

    DBG(mc, "Thread %d",  MEMIF_DAQ_GETTID(mc));
    for (qid = 0; qid < memif_num_rx_queues; qid++) {
        memif_refill_queue(mc->conn, qid, -1, 0);
    }
    return 0;
}

/******************************************************************************
 Name:  on_disconnect

 Descr: call back registered when memif_create is invoked to notify daq when memif  handshake
        reach to disconnected state

 IN:      memif_conn_handle_t conn  - memif connection handler alloaced during memif_init and its also
                                      cached in memif context
          void                *private_ctx - opague handler to cary memif context back to daq.
 OUT:   int               return code 0 for success -1 for failure
*****************************************************************************/
static int on_disconnect (memif_conn_handle_t conn, void *private_ctx)
{
    Memif_Context_t *mc = (Memif_Context_t *)private_ctx;

    DBG(mc, "Thread %d",  MEMIF_DAQ_GETTID(mc));
    mc->state = DAQ_STATE_STOPPED;
    return 0;
}

/******************************************************************************
 Name:  on_interrupt

 Descr: call back registered when memif_create is invoked when daq operate in interrupt
        mode instead of polling, currently its not used for performance reasons.

 IN:      memif_conn_handle_t conn  - memif connection handler alloaced during memif_init and its also
                                      cached in memif context
          void                *private_ctx - opague handler to cary memif context back to daq.
          uint16_t           qid    - queue id associate with this memif instance
 OUT:   int               return code 0 for success -1 for failure
*****************************************************************************/
static int on_interrupt (memif_conn_handle_t conn,
                         void *private_ctx, uint16_t qid)
{
    return 0;
}

/******************************************************************************
 Name:  memif_daq_init_memif_iface

 Descr: Memif interface initialization function

 IN:      Memif_Context_t *mc - Memif per thread context

 OUT:   int               return code 0 for success -1 for failure
*****************************************************************************/
static int memif_daq_init_memif_iface (Memif_Context_t *mc)
{
    memif_conn_args_t args;
    char ifname_buff[MAX_MEMIF_BUFS];
    char sock_buff[MAX_MEMIF_BUFS];
    int err, i, temp;
    char *memif_sock_name = getenv("MEMIF_SOCKET_FILE_PREFIX");
    char *sock_id_offset  = getenv("MEMIF_SOCKET_ID_OFFSET");
    char *num_rx_queues   = getenv("MEMIF_NUM_RX_RINGS");
    char *num_tx_queues   = getenv("MEMIF_NUM_TX_RINGS");
    if (memif_sock_name == NULL)
    {
        memif_sock_name = MEMIF_SOCK_NAME;
    }
    if (sock_id_offset != NULL)
    {
        temp = atoi(sock_id_offset);
        if (temp > 0)
            memif_sock_id_offset = temp;
    }
    if (num_rx_queues != NULL)
    {
        temp = atoi(num_rx_queues);
        if ((temp > DEF_MEMIF_RX_QUEUES) && (temp <= MEMIF_IFACE_RX_QUEUES))
            memif_num_rx_queues = temp;
    }
    if (num_tx_queues != NULL)
    {
        temp = atoi(num_tx_queues);
        if ((temp > DEF_MEMIF_RX_QUEUES) && (temp <= MEMIF_IFACE_TX_QUEUES))
            memif_num_tx_queues = temp;
    }

    memset(&args, 0, sizeof(args));
    args.mode = MEMIF_INTERFACE_MODE_ETHERNET;
    args.interface_id = mc->memif_interface_id + memif_sock_id_offset;
    args.is_master = 0;
    args.log2_ring_size = MEMIF_IFACE_LOG2_RING_SIZE;
    args.buffer_size = MEMIF_IFACE_BUFFER_SIZE;
    args.num_s2m_rings = memif_num_tx_queues;
    args.num_m2s_rings = memif_num_rx_queues;
    snprintf(ifname_buff, MAX_MEMIF_BUFS, "%s%d", IFACE_NAME,
             mc->memif_interface_id + memif_sock_id_offset);
    strncpy((char * ) args.interface_name, ifname_buff, strlen(ifname_buff));
    snprintf(sock_buff, MAX_MEMIF_BUFS,
             memif_sock_name, mc->memif_interface_id + memif_sock_id_offset);

    DBG(mc, "Thread %d create memif interface %s sock_file_name %s",
        MEMIF_DAQ_GETTID(mc), args.interface_name, sock_buff);

    err = memif_per_thread_create_socket(mc->pt_handler, &mc->sock,
                                        (char *)sock_buff, mc);
    if (PREDICT_FALSE(err != MEMIF_ERR_SUCCESS)) {
        DBG(mc, "Thread %d :memif_create_socket: failed with (%s)",
            MEMIF_DAQ_GETTID(mc), memif_strerror(err));
        return -1;
    }
    args.socket = mc->sock;
    err = memif_create(&mc->conn, &args, on_connect, on_disconnect,
                       on_interrupt, mc);
    DBG(mc, "Thread %d create memif interface %s err %d",
        MEMIF_DAQ_GETTID(mc), args.interface_name, err);
    if (PREDICT_FALSE(err != MEMIF_ERR_SUCCESS)) {
        DBG(mc, "Thread %d :memif_create: failed with (%s)",
            MEMIF_DAQ_GETTID(mc), memif_strerror(err));
        return -1;
    }

    for (i = 0; i < memif_num_rx_queues; i++) {
        mc->tx_buf_num[i] = 0;
        mc->rx_buf_num[i] = 0;
        mc->bufs[i]  =
            (memif_buffer_t *) malloc(sizeof(memif_buffer_t) * MAX_MEMIF_BUFS);
        if (PREDICT_FALSE(mc->bufs[i] == NULL)) {
            DBG(mc, "Thread %d : Failed to allocate memif buffers for queue %d",
                MEMIF_DAQ_GETTID(mc), i);
            return -1;
        }
    }
    return 0;
}

/******************************************************************************
 Name:  mmemif_daq_get_vars

 Descr: Read snort process command line args
       used to enable debugging and packet tracing in memif daq

 IN:      Memif_Context_t *mc - Memif per thread context
          const DAQ_ModuleConfig_h modcfg - daq module configration handler
          DAQ_ModuleInstance_h modinst -   daq instance specific information

 OUT:   int               return code 0 for success -1 for failure
*****************************************************************************/
static int memif_daq_get_vars (Memif_Context_t *context,
                               const DAQ_ModuleConfig_h modcfg,
                               DAQ_ModuleInstance_h modinst)
{
    const char *varKey, *varValue;
    char *p;
    daq_base_api.config_first_variable(modcfg, &varKey, &varValue);

    while (varKey) {
        if (!strcmp(varKey, "loopback")) {
            context->loopback = (unsigned)strtoul(varValue, &p, 10);
            if (!*varValue || *p) {
                SET_ERROR(modinst, "invalid loopback (%s)", varValue);
                goto err;
            }
        } else if (!strcmp(varKey, "dump")) {
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
        }
        daq_base_api.config_next_variable(modcfg, &varKey, &varValue);
    }
    return 0;
err:
    return -1;
}

/******************************************************************************
 Name:  memif_daq_fill_queues

 Descr: Memif function reead a patch of packets from memif ring to the daq

 IN:      Memif_Context_t *mc - Memif per thread context

 OUT:   int               return code 0 for success -1 for failure
*****************************************************************************/
static int memif_daq_fill_queues (Memif_Context_t *mc)
{
    int rx_qid;
    int err;
    int have_packets = 0;


    for (rx_qid = 0; rx_qid < memif_num_rx_queues; rx_qid++) {
        /* there are still packets left in the rx buffer. */
        if (mc->rx_idx[rx_qid] < mc->rx_now[rx_qid]) {
            have_packets = 1;
            continue;
        }

        err = memif_rx_burst(mc->conn, rx_qid, mc->bufs[rx_qid],
                             MAX_MEMIF_BUFS, &mc->rx_now[rx_qid]);
        mc->rx_idx[rx_qid] = 0;
        if (err == MEMIF_ERR_SUCCESS) {
            if (mc->rx_now[rx_qid]) {
                if (mc->rx_now[rx_qid] > mc->max_rx_burst) {
                    mc->max_rx_burst = mc->rx_now[rx_qid];
                }
                mc->num_rx_packets += mc->rx_now[rx_qid];
                mc->num_rx_bursts++;
                mc->rx_buf_num[rx_qid] += mc->rx_now[rx_qid];
                have_packets = 1;
            }
        }
    }
    if (have_packets) {
        DBG(mc, "Thread %d have_packets %d mc->num_rx_packets %d "
                "mc->num_rx_bursts %d mc->max_rx_burst %d",
            MEMIF_DAQ_GETTID(mc), have_packets, mc->num_rx_packets,
            mc->num_rx_bursts, mc->max_rx_burst);
    }
    return have_packets;
}

/******************************************************************************
 Name:  DumpHex

 Descr: utility to dump packet received by daq in log file for debugging

 IN:      FILE *fp      - pointer to log file
          uint8_t *data - pointer to received packet
          unsigned len  - packet length

 OUT:   none
*****************************************************************************/
static_always_inline void DumpHex (FILE *fp, const uint8_t *data, unsigned len)
{
    char str[18];
    unsigned i;
    unsigned pos;
    char c;

    for (i=0, pos=0; i<len; i++, pos++) {
        if (pos == 17) {
            str[pos] = 0;
            fprintf(fp, "  %s\n", str);
            pos = 0;
        } else if (pos == 8) {
            str[pos] = ' ';
            pos++;
            fprintf(fp, "%s", " ");
        }
        c = (char)data[i];
        if (isprint(c) && !isspace(c))
            str[pos] = c;
        else
            str[pos] = '.';
        fprintf(fp, "%02X ", data[i]);
    }
    if (pos) {
        str[pos] = 0;
        for (; pos < 17; pos++) {
            if (pos == 8) {
                str[pos] = ' ';
                pos++;
                fprintf(fp, "%s", "    ");
            } else {
                fprintf(fp, "%s", "   ");
            }
        }
        fprintf(fp, "  %s\n", str);
    }
}

/******************************************************************************
 Name:  memif_transmit_packet

 Descr: memif transmit single packet back to the memif master "vpp"

 IN:      Memif_Context_t *mc -  Memif per thread context
          MemifPktDesc *desc  -  Memif packet descriptor pointer
          DAQ_Verdict verdict -  verdict lookup result from snort

 OUT:   int               return code 0 for success -1 for failure
*****************************************************************************/
static_always_inline int memif_transmit_packet (Memif_Context_t *mc,
                                         MemifPktDesc *desc,
                                         DAQ_Verdict verdict)
{
    u16 enq_tx_cnt, tx_burst_cnt;
    int err, tx_qid;
    inspect_packet_metadata_t *meta;
    memif_buffer_t *tx_buf;
    int status = DAQ_SUCCESS;

    DBG(mc, "Enter: Thread %d",  MEMIF_DAQ_GETTID(mc));
    meta =
        (inspect_packet_metadata_t*)(desc->data - sizeof(inspect_packet_metadata_t));
    /*
     * qid and buffer index are cached during receive processing.
     */
    tx_qid = desc->qid;
    tx_buf = mc->bufs[tx_qid] + desc->buf_idx;
    meta->verdict = verdict;
    /* enque processed buffers to tx ring */
    err = memif_buffer_enq_tx(mc->conn, tx_qid, tx_buf, 1, &enq_tx_cnt);
    if (PREDICT_FALSE((err != MEMIF_ERR_SUCCESS) &&
                      (err != MEMIF_ERR_NOBUF_RING))) {
        DBG(mc, "memif buffer enq: %s", memif_strerror(err));
    }
    /* mark memif buffers and shared memory buffers as free */
    err = memif_refill_queue(mc->conn, tx_qid, 1, 0);
    if (PREDICT_FALSE(err != MEMIF_ERR_SUCCESS)) {
        DBG(mc, "Thread %d memif refill queue: %s",
            MEMIF_DAQ_GETTID(mc), memif_strerror(err));
        status = DAQ_ERROR;
    }
    /* transmit allocated buffers */
    err = memif_tx_burst(mc->conn, tx_qid, tx_buf, 1, &tx_burst_cnt);
    if (PREDICT_FALSE(err != MEMIF_ERR_SUCCESS)) {
        DBG(mc, "memif_tx_burst: %s", memif_strerror(err));
    }
    mc->tx_buf_num[tx_qid] ++;

    return status;
}

/******************************************************************************
 Name:  memif_daq_module_load

 Descr: memif daq load  memif plugin

 IN:      const DAQ_BaseAPI_t *base_api - daq api handler

 OUT:   int               return daq error code
*****************************************************************************/
static int memif_daq_module_load (const DAQ_BaseAPI_t *base_api)
{
    if (base_api->api_version != DAQ_BASE_API_VERSION ||
        base_api->api_size != sizeof(DAQ_BaseAPI_t))
        return DAQ_ERROR;

    daq_base_api = *base_api;
    return DAQ_SUCCESS;
}

/******************************************************************************
 Name:  memif_daq_module_unload

 Descr: memif daq unload  memif plugin

 IN:      None

 OUT:   int               return daq error code
*****************************************************************************/
static int memif_daq_module_unload ()
{
    memset(&daq_base_api, 0, sizeof(daq_base_api));
    return DAQ_SUCCESS;
}

/******************************************************************************
 Name:  memif_daq_get_variable_descs

 Descr: memif daq read command line args

 IN:      const DAQ_VariableDesc_t **var_desc_table - pointer to memif variables

 OUT:   int               return code 0 for success -1 for failure
*****************************************************************************/
static int memif_daq_get_variable_descs (const DAQ_VariableDesc_t **var_desc_table)
{
    *var_desc_table = memif_variable_descriptions;

    return sizeof(memif_variable_descriptions) / sizeof(DAQ_VariableDesc_t);
}

/******************************************************************************
 Name:  memif_daq_instantiate

 Descr: memif daq initiailize instance

 IN:      const DAQ_ModuleConfig_h modcfg - daq module configration handler
          DAQ_ModuleInstance_h modinst -   daq instance specific information
          void               **ctxt_ptr - pointer to Memif per thread context

 OUT:   int               return code 0 for success -1 for failure
*****************************************************************************/
static int memif_daq_instantiate (const DAQ_ModuleConfig_h  modcfg,
                                  DAQ_ModuleInstance_h      modinst,
                                  void                      **ctxt_ptr)
{
    Memif_Context_t *mc;
    int rv = DAQ_ERROR, error;
    char app_name[MAX_MEMIF_BUFS];
    uint32_t pool_size = 0;

    mc = (Memif_Context_t*)calloc(1, sizeof(*mc));
    if (PREDICT_FALSE(!mc)) {
        SET_ERROR(modinst, "Couldn't allocate memory for the context!");
        return DAQ_ERROR_NOMEM;
    }
    mc->modinst = modinst;
    mc->device = strdup(daq_base_api.config_get_input(modcfg));
    if (PREDICT_FALSE(!mc->device)) {
        SET_ERROR(modinst, "Couldn't allocate memory for the device string!");
        rv = DAQ_ERROR_NOMEM;
        goto err;
    }
    mc->snaplen = daq_base_api.config_get_snaplen(modcfg);
    mc->timeout = ((int)daq_base_api.config_get_timeout(modcfg) > 0) ?
                   (int)daq_base_api.config_get_timeout(modcfg)  : -1;
    if (PREDICT_FALSE(memif_daq_get_vars(mc, modcfg, modinst))) {
        rv = DAQ_ERROR;
        goto err;
    }

    clib_mem_init_thread_safe(0, 8 << 20);

    mc->memif_interface_id = __atomic_fetch_add(&thread_idx, 1, __ATOMIC_SEQ_CST);
    mc->epfd = epoll_create(1);

    snprintf(app_name, MAX_MEMIF_BUFS, "%s%d",
            APP_NAME, mc->memif_interface_id);
    error = memif_per_thread_init(&mc->pt_handler, mc, control_fd_update,
                                  app_name, NULL, NULL, NULL);

    DBG(mc, "Thread %d memif_per_thread_init for %s epfd %d "
        "memif_interface_id %d error %d",
        MEMIF_DAQ_GETTID(mc), app_name, mc->epfd, mc->memif_interface_id, error);

    if (PREDICT_FALSE(error != MEMIF_ERR_SUCCESS)) {
        DBG(mc, "Thread %d memif_per_thread_init: %s",
            MEMIF_DAQ_GETTID(mc), memif_strerror (error));
        rv = DAQ_ERROR;
        goto err;
    }

    /*
     * Create iface and wait for reply
     */
    error = memif_daq_init_memif_iface(mc);
    if (PREDICT_FALSE(error != 0)) {
        DBG(mc, "Thread %d failed to initialize memif interfaces",
            MEMIF_DAQ_GETTID(mc));
        rv = DAQ_ERROR;
        goto err;
    }

    /* Finally, create the message buffer pool. */
    pool_size = daq_base_api.config_get_msg_pool_size(modcfg);
    if (PREDICT_FALSE((rv = create_packet_pool(mc, pool_size)) != DAQ_SUCCESS)) {
        DBG(mc, "Thread %d failed to create packet pool",
            MEMIF_DAQ_GETTID(mc));
        goto err;
    }
    mc->state = DAQ_STATE_INITIALIZED;
    *ctxt_ptr = mc;
    return rv;

err:
    memif_daq_shutdown(mc);
    return rv;
}

/******************************************************************************
 Name:  memif_daq_destroy

 Descr: memif daq destroy call back

 IN:      Memif_Context_t *mc - Memif per thread context

 OUT:   none
*****************************************************************************/
static void memif_daq_destroy (void *handle)
{
    Memif_Context_t *mc = (Memif_Context_t *) handle;
    DBG(mc, "Enter: Thread %d", MEMIF_DAQ_GETTID(mc));
    memif_daq_shutdown(handle);
}

/******************************************************************************
 Name:  memif_daq_set_filter

 Descr: memif daq set filter call back

 IN:      Memif_Context_t *mc - Memif per thread context
          char            * filter - pointer to filer to use

 OUT:   int daq error code
*****************************************************************************/
static int memif_daq_set_filter (void *handle, const char *filter)
{
    /* TODO */
    return DAQ_ERROR_NOTSUP;
}

/******************************************************************************
 Name:  memif_daq_start

 Descr: memif daq start daq functionality

 IN:      void *handle - Memif per thread context

 OUT:   int daq error code
*****************************************************************************/
static int memif_daq_start (void *handle)
{
    Memif_Context_t *mc = (Memif_Context_t *) handle;
    DBG(mc, "Enter: Thread %d",  MEMIF_DAQ_GETTID(mc));
    mc->state = DAQ_STATE_STARTED;
    return DAQ_SUCCESS;
}

/******************************************************************************
 Name:  memif_daq_inject

 Descr: memif daq inject daq functionality

 IN:      void *handle - Memif per thread context
          DAQ_MsgType type
          const void *hdr
          const uint8_t *data
         uint32_t data_len
 OUT:   int daq error code
*****************************************************************************/
static int memif_daq_inject (void *handle, DAQ_MsgType type, const void *hdr,
                             const uint8_t *data, uint32_t data_len)
{
    /* TODO */
    Memif_Context_t *mc = (Memif_Context_t *) handle;
    DBG(mc, "Enter: Thread %d",  MEMIF_DAQ_GETTID(mc));
    return DAQ_SUCCESS;
}

/******************************************************************************
 Name:  memif_daq_inject_relative

 Descr: memif daq inject relative daq functionality

 IN:      void *handle - Memif per thread context
          const DAQ_Msg_t *msg
          const uint8_t *data
         uint32_t data_len
         int reverse
 OUT:   int daq error code
*****************************************************************************/
static int memif_daq_inject_relative (void *handle, const DAQ_Msg_t *msg, const
                                      uint8_t *data, uint32_t data_len, int reverse)
{
    /* TODO */
    Memif_Context_t *mc = (Memif_Context_t *) handle;
    DBG(mc, "Enter: Thread %d",  MEMIF_DAQ_GETTID(mc));
    return DAQ_SUCCESS;
}

/******************************************************************************
 Name:  memif_daq_interrupt

 Descr: memif daq interrupt daq functionality

 IN:      void *handle - Memif per thread context

 OUT:   int daq error code
*****************************************************************************/
static int memif_daq_interrupt (void *handle)
{
    Memif_Context_t *mc = (Memif_Context_t *) handle;
    DBG(mc, "Enter: Thread %d",  MEMIF_DAQ_GETTID(mc));
    mc->interrupted = true;
    return DAQ_SUCCESS;
}

/******************************************************************************
 Name:  memif_daq_stop

 Descr: memif daq stop daq functionality

 IN:      void *handle - Memif per thread context

 OUT:   int daq error code
*****************************************************************************/
static int memif_daq_stop (void *handle)
{
    Memif_Context_t *mc = (Memif_Context_t *) handle;
    DBG(mc, "Enter: Thread %d",  MEMIF_DAQ_GETTID(mc));
    memif_daq_close(mc);
    return DAQ_SUCCESS;
}

/******************************************************************************
 Name:  memif_daq_ioctl

 Descr: memif daq ioctl daq functionality

 IN:      void *handle - Memif per thread context
          DAQ_IoctlCmd cmd
          void *arg
        size_t arglen
 OUT:   int daq error code
*****************************************************************************/
static int memif_daq_ioctl (void *handle, DAQ_IoctlCmd cmd,
                            void *arg, size_t arglen)
{
   /* TODO */
    Memif_Context_t *mc = (Memif_Context_t *) handle;

    DBG(mc, "Enter: Thread %d",  MEMIF_DAQ_GETTID(mc));
    return DAQ_SUCCESS;
}

/******************************************************************************
 Name:  memif_daq_get_stats

 Descr: memif read daq get stats

 IN:      void *handle        - Memif per thread context
          DAQ_Stats_t * stats

 OUT:   int daq error code
*****************************************************************************/
static int memif_daq_get_stats (void *handle, DAQ_Stats_t * stats)
{
    Memif_Context_t *mc = (Memif_Context_t *) handle;
    DBG(mc, "Enter: Thread %d",  MEMIF_DAQ_GETTID(mc));

    memcpy(stats, &mc->stats, sizeof(DAQ_Stats_t));
    return DAQ_SUCCESS;
}

/******************************************************************************
 Name:  memif_daq_get_reset_stats

 Descr: memif read daq reset stats

 IN:      void *handle        - Memif per thread context

 OUT:   int daq error code
*****************************************************************************/
static void memif_daq_reset_stats (void *handle)
{
    Memif_Context_t *mc = (Memif_Context_t *) handle;
    DBG(mc, "Enter: Thread %d",  MEMIF_DAQ_GETTID(mc));
    memset(&mc->stats, 0, sizeof(DAQ_Stats_t));;
}

/******************************************************************************
 Name:  memif_daq_get_snaplen

 Descr: memif read daq reset stats

 IN:      void *handle        - Memif per thread context

 OUT:   int  buffer size
*****************************************************************************/
static int memif_daq_get_snaplen (void *handle)
{
    Memif_Context_t *mc = (Memif_Context_t *) handle;
    DBG(mc, "Enter: Thread %d",  MEMIF_DAQ_GETTID(mc));
    return mc->snaplen;
}

/******************************************************************************
 Name:  memif_daq_get_capabilities

 Descr: memif get all supported capabilities

 IN:      void *handle        - Memif per thread context

 OUT:   int capabilities
*****************************************************************************/
static uint32_t memif_daq_get_capabilities (void *handle)
{
    uint32_t capabilities = DAQ_CAPA_BLOCK          |
                            DAQ_CAPA_REPLACE        |
                            DAQ_CAPA_INJECT         |
                            DAQ_CAPA_UNPRIV_START   |
                            DAQ_CAPA_INTERRUPT      |
                            DAQ_CAPA_DEVICE_INDEX;
    Memif_Context_t *mc = (Memif_Context_t *) handle;

#ifdef LIBPCAP_AVAILABLE
    capabilities |= DAQ_CAPA_BPF;
#endif
    DBG(mc, "Enter: Thread %d capabilities = 0x%08x",
        MEMIF_DAQ_GETTID(mc), capabilities);
    return capabilities;
}

/******************************************************************************
 Name:  memif_daq_get_datalink_type

 Descr: memif get datalink type

 IN:      void *handle        - Memif per thread context

 OUT:   int datalink type
*****************************************************************************/
static int memif_daq_get_datalink_type (void *handle)
{
    Memif_Context_t *mc = (Memif_Context_t *) handle;
    DBG(mc, "Enter: Thread %d",  MEMIF_DAQ_GETTID(mc));
    return DLT_EN10MB;
}

/******************************************************************************
 Name:  memif_daq_wait_for_packet

Descr: memif wait for epoll events to know if there are packets available to process

 IN:      Memif_Context_t *mc        - Memif per thread context

 OUT:   DAQ_RecvStatus return daq receieve status
*****************************************************************************/
static_always_inline DAQ_RecvStatus memif_daq_wait_for_packet (Memif_Context_t *mc)
{
    struct epoll_event evt;
    u32 memif_events = 0;
    int ret = 0, memif_err;

    memset (&evt, 0, sizeof (evt));
    evt.events = EPOLLIN | EPOLLOUT;
    sigset_t sigset;
    sigemptyset(&sigset);

    /* Chop the timeout into one second chunks (plus any remainer) to improve responsiveness to
        interruption when there is no traffic and the timeout is very long (or unlimited). */
    int timeout = mc->timeout;
    mc->poll_calls++;
    while (timeout != 0) {
        /* If the receive has been canceled, break out of the loop and return. */
        if (mc->interrupted) {
            mc->interrupted = false;
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

        ret = epoll_pwait(mc->epfd, &evt, 1, poll_timeout, &sigset);
        /* If some number of of sockets have events returned, check them all for badness. */
        if (ret > 0) {
            /* this app does not use any other file descriptors than stds and memif control fds */
            if (evt.data.fd > 2) {
                if (evt.events & EPOLLIN) {
                    memif_events |= MEMIF_FD_EVENT_READ;
                }
                if (evt.events & EPOLLOUT) {
                    memif_events |= MEMIF_FD_EVENT_WRITE;
                }
                if (evt.events & (EPOLLERR | EPOLLHUP)) {
                    memif_events |= MEMIF_FD_EVENT_ERROR;
                }
                memif_err = memif_per_thread_control_fd_handler(mc->pt_handler,
                                                                evt.data.fd, memif_events);
                if (PREDICT_FALSE(memif_err != MEMIF_ERR_SUCCESS)) {
                    DBG(mc, "Thread %d memif_per_thread_control_fd_handler: %s",
                        MEMIF_DAQ_GETTID(mc), memif_strerror(memif_err));
                    return DAQ_RSTAT_ERROR;
                }
            } else {
                DBG(mc, "Thread %d unexpected event at memif_epfd. fd %d",
                    MEMIF_DAQ_GETTID(mc), evt.data.fd);
            }
            return DAQ_RSTAT_OK;
        } else if ((ret < 0) && (errno != EINTR)) {
            DBG(mc, "Thread %d epoll_wait: %s",
                MEMIF_DAQ_GETTID(mc), strerror(errno));
            return DAQ_RSTAT_ERROR;
        }
    }

    return DAQ_RSTAT_TIMEOUT;
}

/******************************************************************************
 Name:daq_copy_ipaddr

 Descr: copy ipaddress

 IN: uint8_t *dst
      const inspect_dp_ipaddr_t *src
      int ipv6flag

 OUT: none
******************************************************************************/
static_always_inline void daq_copy_ipaddr(struct in6_addr *dst,
                                   ip46_address_t *src,
                                   int ipv6Flag)
{
    if (ipv6Flag){
        memcpy(dst->s6_addr, src->ip6.as_u8, sizeof(*dst));
    } else {
        dst->s6_addr32[3] = src->ip4.data_u32;
        dst->s6_addr16[5] = 0xFFFF;
    }
}

/******************************************************************************
 Name:daq_process_eof_event

 Descr: handle sending eof event to snort. Definition of all functions
 called from switch-case should match.

 IN: Memif_Context_t *mc    - memif thread context
     memif_buffer_t *rx_buf - buffer with event received over memif
     int rx_qid             - queue id
     MemifPktDesc *desc     - descriptor for packet sent to snort
     struct timeval *ts     - timestamp for packet.

 OUT: none
******************************************************************************/
static_always_inline void daq_process_eof_event(Memif_Context_t *mc,
                                         memif_buffer_t *rx_buf,
                                         int rx_qid,
                                         MemifPktDesc *desc,
                                         struct timeval *ts)
{
    inspect_eof_event_msg_t   *eof;
    DAQ_Msg_t *msg;

    DBG(mc, "Enter: daq_process_eof_event - thread %d",MEMIF_DAQ_GETTID(mc));
    eof = (inspect_eof_event_msg_t *)(rx_buf->data + sizeof(inspect_packet_metadata_t));
    msg = &desc->msg;

    desc->msg.type         = DAQ_MSG_TYPE_EOF;
    desc->session.protocol = eof->real_saddr.ip_proto;
    msg->hdr_len           = sizeof(Flow_Stats_t);

    daq_copy_ipaddr((struct in6_addr *)desc->session.initiatorIp,
                    &eof->real_saddr.sip,
                    eof->real_saddr.flags.is_ipv6);
    daq_copy_ipaddr((struct in6_addr *)desc->session.responderIp,
                    &eof->real_saddr.dip,
                    eof->real_saddr.flags.is_ipv6);

    if (desc->session.protocol == IPPROTO_ICMP)
    {
        /* Assume ICMP echo request. */
        desc->session.initiatorPort = htons(8); /* type */
        desc->session.responderPort = htons(0); /* code */
    }
    else if (desc->session.protocol == IPPROTO_ICMPV6)
    {
        /* Assume ICMP echo request. */
        desc->session.initiatorPort = htons(120); /* type */
        desc->session.responderPort = htons(0); /* code */
    }
    else
    {
        desc->session.initiatorPort = eof->real_saddr.sport;
        desc->session.responderPort = eof->real_saddr.dport;
    }

    desc->session.opaque = eof->rule_id;

    desc->session.initiatorPkts         = eof->counts.dir[FLOW_FORWARD].packets;
    desc->session.initiatorBytes        = eof->counts.dir[FLOW_FORWARD].bytes;
    desc->session.initiatorPktsDropped  = eof->drop.counts.dir[FLOW_FORWARD].packets;
    desc->session.initiatorBytesDropped = eof->drop.counts.dir[FLOW_FORWARD].bytes;

    desc->session.responderPkts          = eof->counts.dir[FLOW_REVERSE].packets;
    desc->session.responderBytes         = eof->counts.dir[FLOW_REVERSE].bytes;
    desc->session.responderPktsDropped   = eof->drop.counts.dir[FLOW_REVERSE].packets;
    desc->session.responderBytesDropped  = eof->drop.counts.dir[FLOW_REVERSE].bytes;
}

/******************************************************************************
 Name:daq_process_sof_event

 Descr: Handle sending sof event to snort. definition of all functions called 
 from switch-case should match

 IN: Memif_Context_t *mc    - memif thread context
     memif_buffer_t *rx_buf - buffer with event received over memif
     int rx_qid             - queue id
     MemifPktDesc *desc     - descriptor for packet sent to snort
     struct timeval *ts     - timestamp for packet.

 OUT: none
******************************************************************************/
static_always_inline void daq_process_sof_event(Memif_Context_t *mc,
                                         memif_buffer_t *rx_buf,
                                         int rx_qid,
                                         MemifPktDesc *desc,
                                         struct timeval *ts)
{
    inspect_sof_event_msg_t   *sof;
    DAQ_Msg_t *msg;

    DBG(mc, "Enter: daq_process_sof_event - thread %d",MEMIF_DAQ_GETTID(mc));

    sof = (inspect_sof_event_msg_t *)(rx_buf->data + sizeof(inspect_packet_metadata_t));
    msg = &desc->msg;

    desc->msg.type         = DAQ_MSG_TYPE_SOF;
    msg->hdr_len           = sizeof(Flow_Stats_t);
    desc->session.protocol = sof->real_saddr.ip_proto;

    daq_copy_ipaddr((struct in6_addr *)desc->session.initiatorIp,
            &sof->real_saddr.sip,
            sof->real_saddr.flags.is_ipv6);
    daq_copy_ipaddr((struct in6_addr *)desc->session.responderIp,
            &sof->real_saddr.dip,
            sof->real_saddr.flags.is_ipv6);

    if (desc->session.protocol == IPPROTO_ICMP)
    {
        /* Assume ICMP echo request. */
        desc->session.initiatorPort = htons(8); /* type */
        desc->session.responderPort = htons(0); /* code */
    }
    else if (desc->session.protocol == IPPROTO_ICMPV6)
    {
        /* Assume ICMP echo request. */
        desc->session.initiatorPort = htons(120); /* type */
        desc->session.responderPort = htons(0); /* code */
    }
    else
    {
        desc->session.initiatorPort = sof->real_saddr.sport;
        desc->session.responderPort = sof->real_saddr.dport;
    }

    desc->session.initiatorBytes        = sof->fwd_flow_bytes;
    desc->session.opaque                = sof->rule_id;
#if 0
    desc->session.sof_timestamp.tv_sec  = sof->start_timestamp.secs;
    desc->session.sof_timestamp.tv_usec = sof->start_timestamp.usecs;
#endif
    return;
}

/******************************************************************************
 Name:daq_process_msg_type_packet

 Descr: handle sending data packet to snort

 IN: Memif_Context_t *mc    - memif threrad context
     memif_buffer_t *rx_buf - buffer with event received over memif
     int rx_qid             - queue id
     MemifPktDesc *desc     - descriptor for packet sent to snort
     struct timeval *ts     - timestamp when the vector with packet is received.

 OUT: none
******************************************************************************/
static_always_inline void daq_process_msg_type_packet(Memif_Context_t *mc,
                                               memif_buffer_t *rx_buf,
                                               int rx_qid,
                                               MemifPktDesc *desc,
                                               struct timeval *ts)
{
    u32 data_len;
    DAQ_Msg_t *msg;
    inspect_packet_metadata_t *meta;
    DAQ_PktHdr_t *daqhdr;

    meta     = (inspect_packet_metadata_t*)rx_buf->data;
    data_len = (rx_buf->len - sizeof(inspect_packet_metadata_t));

    /* Next, set up the DAQ message.  Most fields are prepopulated and unchanging. */
    msg           = &desc->msg;
    msg->data_len = data_len;
    msg->data     = desc->data;

    /* Then, set up the DAQ packet header. */
    daqhdr = &desc->pkthdr;

    daqhdr->ts = *ts;
    daqhdr->pktlen = data_len;
    daqhdr->ingress_index = (meta->virt_intfid & 0xffff);
    daqhdr->egress_index  = ((meta->virt_intfid >> 16) & 0xffff);
    daqhdr->ingress_group = DAQ_PKTHDR_UNKNOWN;
    daqhdr->egress_group  = DAQ_PKTHDR_UNKNOWN;
    daqhdr->flags         = 0;
    daqhdr->opaque        = 0;
    daqhdr->address_space_id = 0;
    return;
}

/******************************************************************************
 Name:daq_process_message

 Descr: Process message types.

 IN: Memif_Context_t *mc     - memif thread context,
     int rx_qid              - queue id
     const DAQ_Msg_t *msgs[] - array to add descriptors with packet for snort
     int msg_index           - index into msgs array
     struct timeval          - timestamp for the packet

 OUT: int - return status
******************************************************************************/
static_always_inline int daq_process_message(Memif_Context_t *mc,
                                      int rx_qid,
                                      const DAQ_Msg_t *msgs[],
                                      int *msg_index,
                                      struct timeval *ts)
{
    inspect_packet_metadata_t *meta;
    memif_buffer_t *rx_buf;
    MemifPktDesc *desc;

    /*Make sure that we have a packet descriptor available to populate. */
    desc = mc->pool.freelist;
    if (PREDICT_FALSE(!desc)) {
        return DAQ_RSTAT_NOBUF;
    }
    mc->stats.packets_received++;

    rx_buf = mc->bufs[rx_qid] + mc->rx_idx[rx_qid];
    if (mc->dump) {
        DumpHex(stderr, (const uint8_t *)rx_buf->data, rx_buf->len);
    }

    meta   = (inspect_packet_metadata_t*)rx_buf->data;
    /* setup the packet descriptor */
    desc->data    = (rx_buf->data + sizeof(inspect_packet_metadata_t));
    desc->length  = (rx_buf->len  - sizeof(*meta));
    desc->qid     = rx_qid;
    desc->buf_idx = mc->rx_idx[rx_qid];

    switch (meta->msg_hdr.msg_type) {
    case INSPECT_META_MSG_TYPE_PACKET:
        daq_process_msg_type_packet(mc, rx_buf, rx_qid, desc, ts);
        break;
    case INSPECT_META_MSG_TYPE_SOF_EVENT:
        daq_process_sof_event(mc, rx_buf, rx_qid, desc, ts);
        break;
    case INSPECT_META_MSG_TYPE_EOF_EVENT:
        daq_process_eof_event(mc, rx_buf, rx_qid, desc, ts);
        break;
    default:
        /*The descriptor is not pulled from the free list.
         So, do nothing*/
        return DAQ_RSTAT_OK;
    }

    /*extract this descriptor from the free list and
      place the message in the return vector. */
    mc->pool.freelist = desc->next;
    desc->next        = NULL;
    mc->pool.info.available--;

    msgs[*msg_index]  = &desc->msg;
    ++*msg_index;

    return DAQ_RSTAT_OK;
}

/******************************************************************************
 Name:  memif_daq_msg_receive

 Descr: memif packets receive daq plugin call back

 IN:      void             *handle  - Memif context
          const unsigned   max_recv - Max packets received by default its set to 64
                                     use --daq-batch-size to change it if needed
        const            DAQ_Msg_t *msgs[] - array of received packets
        DAQ_RecvStatus   *rstat            - pointer to receive return code

OUT:    int daq error code
*****************************************************************************/
static unsigned memif_daq_msg_receive (void             *handle,
                                       const unsigned   max_recv,
                                       const            DAQ_Msg_t *msgs[],
                                       DAQ_RecvStatus   *rstat)
{
    Memif_Context_t *mc = (Memif_Context_t *) handle;
    int c = 0, rx_qid;
    DAQ_RecvStatus status = DAQ_RSTAT_OK;
    struct timeval ts;
    int have_packets;
    int msg_index = 0;

    DBG(mc, "Enter: Thread %d max_recv %u", MEMIF_DAQ_GETTID(mc), max_recv);
    while (c < max_recv) {
        /* Check to see if the receive has been canceled.  If so, reset it and return appropriately. */
        if (mc->interrupted) {
            mc->interrupted = false;
            status = DAQ_RSTAT_INTERRUPTED;
            break;
        }

        have_packets = memif_daq_fill_queues(mc);
        if (have_packets) {
            mc->non_poll_calls++;
            gettimeofday(&ts, NULL);
        } else {
            if (c != 0) {
                status = DAQ_RSTAT_WOULD_BLOCK;
                break;
            }
            status = memif_daq_wait_for_packet(mc);
            if (status != DAQ_RSTAT_OK) {
                break;
            }
        }

        for (rx_qid = 0; (rx_qid < memif_num_rx_queues) && (c < max_recv); rx_qid++) {
            u16 old_idx = mc->rx_idx[rx_qid];

            while ((mc->rx_idx[rx_qid] < mc->rx_now[rx_qid]) && (c < max_recv)) {
                /*It is possible a frame may be dropped. The msg_index may not
                be same as "c"*/
                status = daq_process_message(mc, rx_qid, msgs, &msg_index, &ts);
                if (status != DAQ_RSTAT_OK) {
                    goto err;
                }
                c++;
                mc->rx_idx[rx_qid]++;
            }
            mc->rx_buf_num[rx_qid] -= (mc->rx_idx[rx_qid] - old_idx);
        }
    }
    if (mc->loopback) {
        DBG(mc, "memif_daq_msg_receive loopback thread %d",MEMIF_DAQ_GETTID(mc));
        memif_daq_loopback(handle, msgs, msg_index);
        msg_index=0;
    }
err:
    DBG(mc, "Exit: Thread %d with status %s rx count %d",
        MEMIF_DAQ_GETTID(mc), memifdaq_status_to_str[status], c);

    *rstat = status;
    return msg_index;
}

/******************************************************************************
 Name:  memif_daq_msg_finalize

 Descr: memif single packet transmit daq plugin call back

 IN:        void *handle            - memif context
            const DAQ_Msg_t *msg    - pointer to the packet to transmit
                                      back to master "vpp"
            DAQ_Verdict verdict     - verdict based of snort inspection
                                      lookup to send back to master

 OUT:   int               return daq error code
*****************************************************************************/
static int memif_daq_msg_finalize (void *handle,
                                   const DAQ_Msg_t *msg,
                                   DAQ_Verdict verdict)
{
    inspect_packet_metadata_t *meta;
    Memif_Context_t *mc = (Memif_Context_t *) handle;
    MemifPktDesc *desc = (MemifPktDesc *) msg->priv;
    memif_buffer_t *tx_buf;

    tx_buf = mc->bufs[desc->qid] + desc->buf_idx;
    meta = (inspect_packet_metadata_t*)tx_buf->data;

    DBG(mc, "Enter: Thread %d verdict %d ",
        MEMIF_DAQ_GETTID(mc), verdict);

    if(PREDICT_TRUE(meta->msg_hdr.msg_type == INSPECT_META_MSG_TYPE_PACKET)) {
        /* Sanitize and enact the verdict. */
        if (verdict >= MAX_DAQ_VERDICT) {
            verdict = DAQ_VERDICT_PASS;
        }
        mc->stats.verdicts[verdict]++;
        verdict = verdict_translation_table[verdict];
        if (verdict == DAQ_VERDICT_PASS) {
            memif_transmit_packet(mc, desc, verdict);
        }
    } else {
        /*Packets like events (SOF/EOF) being dropped.*/
        tx_buf->flags &= ~MEMIF_BUFFER_FLAG_RX;
    }

    /* Toss the descriptor back on the free list for reuse. */
    desc->next = mc->pool.freelist;
    mc->pool.freelist = desc;
    mc->pool.info.available++;
    return DAQ_SUCCESS;
}

/******************************************************************************
 Name:  memif_daq_get_msg_pool_info

 Descr: memif get allocated daq pool info

 IN:        void *handle            - memif context
            DAQ_MsgPoolInfo_t *info - daq msg pool info

 OUT:   int               return daq error code
*****************************************************************************/
static int memif_daq_get_msg_pool_info (void *handle, DAQ_MsgPoolInfo_t *info)
{
    Memif_Context_t *mc = (Memif_Context_t *) handle;
    DBG(mc, "Enter: Thread %d",  MEMIF_DAQ_GETTID(mc));

    *info = mc->pool.info;
    return DAQ_SUCCESS;
}

/******************************************************************************
 Name:  memif_daq_loopback

 Descr: memif loopback packets back over memif 

 IN:        void *handle            - memif context
            const DAQ_Msg_t *msg    - pointer to the packet to transmit
                                      back to master "vpp"
            int msg_count           - Total number of packets in msgs array.

 OUT:   int               return daq error code
*****************************************************************************/
static_always_inline void memif_daq_loopback (void *handle, 
                                              const DAQ_Msg_t *msgs[],
                                              int msg_count)
{
    int xmit_idx = 0;
    Memif_Context_t *mc = (Memif_Context_t *) handle;

    DBG(mc, "memif_daq_loopback %d msg count %d", MEMIF_DAQ_GETTID(mc), msg_count);
    while(xmit_idx < msg_count){
        memif_daq_msg_finalize(handle, msgs[xmit_idx], DAQ_VERDICT_PASS);
        xmit_idx++;
    }
}

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const  DAQ_ModuleAPI_t DAQ_MODULE_DATA =
#else
const  DAQ_ModuleAPI_t memif_daq_module_data =
#endif
{
    /* .api_version = */ DAQ_MODULE_API_VERSION,
    /* .api_size = */ sizeof(DAQ_ModuleAPI_t),
    /* .module_version = */ DAQ_MEMIF_VERSION,
    /* .name = */ "memif",
    /* .type = */ DAQ_TYPE_INLINE_CAPABLE | DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
    /* .load = */ memif_daq_module_load,
    /* .unload = */ memif_daq_module_unload,
    /* .get_variable_descs = */ memif_daq_get_variable_descs,
    /* .instantiate  = */ memif_daq_instantiate,
    /* .destroy = */ memif_daq_destroy,
    /* .set_filter = */ memif_daq_set_filter,
    /* .start = */ memif_daq_start,
    /* .inject = */ memif_daq_inject,
    /* .inject_relative = */ memif_daq_inject_relative,
    /* .interrupt = */ memif_daq_interrupt,
    /* .stop = */ memif_daq_stop,
    /* .ioctl = */ memif_daq_ioctl,
    /* .get_stats = */ memif_daq_get_stats,
    /* .reset_stats = */ memif_daq_reset_stats,
    /* .get_snaplen = */ memif_daq_get_snaplen,
    /* .get_capabilities = */ memif_daq_get_capabilities,
    /* .get_datalink_type = */ memif_daq_get_datalink_type,
    /* .config_load = */ NULL,
    /* .config_swap = */ NULL,
    /* .config_free = */ NULL,
    /* .msg_receive = */ memif_daq_msg_receive,
    /* .msg_finalize = */ memif_daq_msg_finalize,
    /* .get_msg_pool_info = */ memif_daq_get_msg_pool_info,
};
