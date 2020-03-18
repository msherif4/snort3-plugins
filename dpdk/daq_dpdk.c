/*
** Copyright (C) 2020 Cisco and/or its affiliates. All rights reserved.
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
#include <getopt.h>
#include <net/if.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <daq_dlt.h>
#include <daq.h>
#include <daq_common.h>
#include <daq_module_api.h>

#include <rte_config.h>
#include <rte_eal.h>
#include <rte_ethdev.h>

#include <daq_dpdk.h>

#define DAQ_DPDK_VERSION       1
#define APP_NAME "dpdk_ngdaq"
#define DPDK_DAQ_DEFAULT_POOL_SIZE 64

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define MAX_ARGS 64

#define RX_RING_NUM 1
#define TX_RING_NUM 1

#define RX_RING_SIZE 128
#define TX_RING_SIZE 512

#define SET_ERROR(modinst, ...) daq_base_api.set_errbuf(modinst, __VA_ARGS__)
#define DBG(dpdkc, _fmt, args...)          \
    if (unlikely(dpdkc->debug)) {     \
        fprintf(stdout, "\n"_fmt, ##args);   \
    }

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {
        .max_rx_pkt_len = ETHER_MAX_LEN,
    }
};

typedef struct _dpdk_instance
{
    struct _dpdk_instance *peer;
    char dev[IFNAMSIZ];
#define DPDKINST_STARTED       0x1
    uint32_t flags;
    int rx_rings;
    int tx_rings;
    int port;
    int index;
    struct rte_mempool *mbuf_pool;
    struct rte_mbuf *tx_burst;
} DpdkInstance;

typedef struct _Dpdk_pkt_desc
{
    DAQ_Msg_t msg;
    DAQ_PktHdr_t pkthdr;
    uint8_t *data;
    unsigned int length;
    DpdkInstance *peer;
    int peer_queue;
    struct _DPDK_pkt_desc *next;
} DpdkPktDesc;

typedef struct _DPDK_msg_pool
{
    DpdkPktDesc *pool;
    DpdkPktDesc *freelist;
    DAQ_MsgPoolInfo_t info;
} DpdkifMsgPool;

typedef struct _dpdk_context
{
    char *device;
    char *filter;
    int snaplen;
    int timeout;
#define DPDK_DAQ_GETID(dpdkc)  (dpdkc->dpdk_interface_id)
    uint32_t dpdk_interface_id;

    DAQ_ModuleInstance_h modinst;
    DpdkifMsgPool pool;
    unsigned dump;
    unsigned debug;
    const char *dpdk_args;
#define DEV_IDX 0
#define PEER_IDX 1
#define NUM_INSTANCES 2
    DpdkInstance instances[NUM_INSTANCES];
    int num_intfs;
    int promisc_flag;
    DAQ_Stats_t stats;
    DAQ_State state;
    volatile int interrupted;
    char errbuf[256];
} Dpdk_Context_t;

static uint32_t thread_idx = 0;

static DAQ_VariableDesc_t DPDK_variable_descriptions[] = {
    { "debug", "Enable traces to stdout", DAQ_VAR_DESC_FORBIDS_ARGUMENT },
    { "dump", "Enable packets dump to stdout", DAQ_VAR_DESC_FORBIDS_ARGUMENT },
    { "dpdk_args", "DPDK configrations"}
};

static const char * dpdkdaq_status_to_str[MAX_DAQ_RSTAT] = {
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

 IN:    Dpdk_Context_t     *dpdk   - DPDK thread context

 OUT:   None
*****************************************************************************/
static void destroy_packet_pool (Dpdk_Context_t *dpdk)
{
    DpdkifMsgPool *pool = &dpdk->pool;
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

 IN:   Dpdk_Context_t     *dpdk   - DPDK thread context
       uint                size  - size of the daq pool and if its
                                   0 a default of 64 will be used.
 OUT:  int                 DAQ error code
*****************************************************************************/
static int create_packet_pool (Dpdk_Context_t *dpdk, unsigned size)
{
    uint32_t i = 0;
    DpdkifMsgPool *pool = &dpdk->pool;

    DBG(dpdk, "Enter: Thread %d size %d", DPDK_DAQ_GETID(dpdk), size);

    if (unlikely(size == 0)) {
        size = DPDK_DAQ_DEFAULT_POOL_SIZE;
    }

    pool->pool = calloc(size, sizeof(DpdkPktDesc));
    if (unlikely(!pool->pool)) {
        DBG(dpdk, "%s: Could not allocate %zu bytes for a packet descriptor pool!",
            __func__, sizeof(DpdkPktDesc) * size);
        return DAQ_ERROR_NOMEM;
    }
    pool->info.mem_size = sizeof(DpdkPktDesc) * size;
    while (i < size) {
        /*
        * Descriptor buffer will be assigned to DPDK ring buffers when
        * daq receives packets.
        */
        DpdkPktDesc *desc = &pool->pool[i++];
        pool->info.mem_size += dpdk->snaplen;

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
        msg->owner = dpdk->modinst;
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

 IN:      Dpdk_Context_t *dpdk      - pointer to DPDK dap context
          void *pkt              - pointer to received packet
          size_t len             - packet length
          uint64_t   addr             - buffer address in user-space

 OUT:   none
*****************************************************************************/
static void hex_dump(Dpdk_Context_t *dpdk, void *pkt, size_t length, uint64_t addr)
{
    const unsigned char *address = (unsigned char *)pkt;
    const unsigned char *line = address;
    size_t line_size = 32;
    unsigned char c;
    char buf[32];
    int i = 0;

    if (!dpdk->dump) {
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
 Name:  dpdk_daq_close

 Descr: DPDK cleanup function 

 IN:     Dpdk_Context_t *dpdk - DPDK per thread context
 OUT:   int               return code 0 for success -1 for failure
*****************************************************************************/
static int dpdk_daq_close (Dpdk_Context_t *dpdk)
{
    int err = 0;
    DBG(dpdk, "Thread %d", DPDK_DAQ_GETID(dpdk));

    if (unlikely(!dpdk)) {
        return -1;
    }

    dpdk->state = DAQ_STATE_STOPPED;
    return err;
}

/******************************************************************************
 Name:  dpdk_daq_shutdown

 Descr: DPDK shutdown will delete DPDK socket and all allocated memory and packet pools
        associated with this instance.

 IN:     Dpdk_Context_t *dpdk - DPDK per thread context
 OUT:   int               return code 0 for success -1 for failure
*****************************************************************************/
static void dpdk_daq_shutdown (void *handle)
{
    Dpdk_Context_t *dpdk = (Dpdk_Context_t *) handle;

    DBG(dpdk, "Thread %d",  DPDK_DAQ_GETID(dpdk));
    dpdk_daq_close(dpdk);

    if (dpdk->device) {
        free(dpdk->device);
    }
    destroy_packet_pool(dpdk);
    free(dpdk);
}

/******************************************************************************
 Name:  dpdk_daq_get_vars

 Descr: Read snort process command line args
       used to enable debugging and packet tracing in DPDK daq

 IN:      Dpdk_Context_t *dpdk - DPDK per thread context
          const DAQ_ModuleConfig_h modcfg - daq module configration handler
          DAQ_ModuleInstance_h modinst -   daq instance specific information

 OUT:   int               return code 0 for success -1 for failure
*****************************************************************************/
static int dpdk_daq_get_vars (Dpdk_Context_t *context,
                              const DAQ_ModuleConfig_h modcfg,
                              DAQ_ModuleInstance_h modinst)
{
    const char *varKey, *varValue;
    char *p;
    char *dev;
    size_t len;
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
        } else if (!strcmp(varKey, "dpdk_args")) {
            context->dpdk_args = varValue;
            if (!*varValue) {
                SET_ERROR(modinst, "invalid dpdk_args (%s)", varValue);
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
           goto err;
        }
        if (context->num_intfs > NUM_INSTANCES) {
           SET_ERROR(modinst, "Edpdkeeded number of supported interfaces");
           goto err;
        }
        if (len != 0) {
           snprintf(context->instances[context->num_intfs++].dev, len + 1, "%s", dev);
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
 Name:  dpdk_daq_module_load

 Descr: DPDK daq load  DPDK plugin

 IN:      const DAQ_BaseAPI_t *base_api - daq api handler

 OUT:   int               return daq error code
*****************************************************************************/
static int dpdk_daq_module_load (const DAQ_BaseAPI_t *base_api)
{
    if (base_api->api_version != DAQ_BASE_API_VERSION ||
        base_api->api_size != sizeof(DAQ_BaseAPI_t)) {
        return DAQ_ERROR;
    }
    daq_base_api = *base_api;
    return DAQ_SUCCESS;
}

/******************************************************************************
 Name:  dpdk_daq_module_unload

 Descr: DPDK daq unload  DPDK plugin

 IN:      None

 OUT:   int               return daq error code
*****************************************************************************/
static int dpdk_daq_module_unload ()
{
    memset(&daq_base_api, 0, sizeof(daq_base_api));
    return DAQ_SUCCESS;
}

/******************************************************************************
 Name:  dpdk_daq_get_variable_descs

 Descr: DPDK daq read command line args

 IN:      const DAQ_VariableDesc_t **var_desc_table - pointer to DPDK variables

 OUT:   int               return code 0 for success -1 for failure
*****************************************************************************/
static int dpdk_daq_get_variable_descs (const DAQ_VariableDesc_t **var_desc_table)
{
    *var_desc_table = DPDK_variable_descriptions;

    return sizeof(DPDK_variable_descriptions) / sizeof(DAQ_VariableDesc_t);
}

static int start_instance (Dpdk_Context_t *dpdkc, DpdkInstance *instance)
{
    int rx_rings = RX_RING_NUM, tx_rings = TX_RING_NUM;
    struct rte_eth_conf port_conf = port_conf_default;
    int port, queue, ret;

    port = instance->port;

    ret = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (ret != 0) {
        DBG(dpdkc, "Thread %d %s: Couldn't configure port %d",  
            DPDK_DAQ_GETID(dpdkc), __FUNCTION__, port);
        return DAQ_ERROR;
    }

    instance->rx_rings = rx_rings;
    instance->tx_rings = tx_rings;

    for (queue = 0; queue < rx_rings; queue++) {
        ret = rte_eth_rx_queue_setup(port, queue, RX_RING_SIZE,
                                     rte_eth_dev_socket_id(port),
                                     NULL, instance->mbuf_pool);
        if (ret != 0) {
            DBG(dpdkc, "Thread %d %s: Couldn't setup rx queue %d for port %d\n", 
                DPDK_DAQ_GETID(dpdkc),__FUNCTION__, queue, port);
            return DAQ_ERROR;
        }
    }

    for (queue = 0; queue < tx_rings; queue++) {
        ret = rte_eth_tx_queue_setup(port, queue, TX_RING_SIZE,
                                     rte_eth_dev_socket_id(port),
                                     NULL);
        if (ret != 0) {
            DBG(dpdkc, "Thread %d %s: Couldn't setup tx queue %d for port %d\n", 
                DPDK_DAQ_GETID(dpdkc),__FUNCTION__, queue, port);
            return DAQ_ERROR;
        }
    }

    ret = rte_eth_dev_start(instance->port);
    if (ret != 0) {
        DBG(dpdkc, "Thread %d %s: Couldn't start device for port %d\n", 
            DPDK_DAQ_GETID(dpdkc), __FUNCTION__, port);
        return DAQ_ERROR;
    }

    instance->flags |= DPDKINST_STARTED;

    if (dpdkc->promisc_flag) {
        rte_eth_promiscuous_enable(instance->port);
    }
    return DAQ_SUCCESS;
}

static void destroy_instance (DpdkInstance *instance)
{
    int i;

    if (instance) {
        if (instance->flags & DPDKINST_STARTED) {
            rte_pktmbuf_free(instance->tx_burst);

            rte_eth_dev_stop(instance->port);
            instance->flags &= ~DPDKINST_STARTED;
        }
    }
}

static DpdkInstance *create_instance (Dpdk_Context_t *dpdkc, const char *device)
{
    DpdkInstance *instance;
    char poolname[64];
    static int index = 0;
    instance = &dpdkc->instances[index];

    instance->index = index++;

    instance->port = instance->index;

    snprintf(poolname, sizeof(poolname), "MBUF_POOL%d", instance->port);
    instance->mbuf_pool = rte_pktmbuf_pool_create(poolname, NUM_MBUFS,
                                                  MBUF_CACHE_SIZE, 0, 
                                                  RTE_MBUF_DEFAULT_BUF_SIZE, 
                                                  rte_socket_id());
    if (instance->mbuf_pool == NULL) {
        DBG(dpdkc, "Thread %d %s: Couldn't create mbuf pool!.\n", 
            DPDK_DAQ_GETID(dpdkc),__FUNCTION__);
        goto err;
    }

    return instance;

err:
    destroy_instance(instance);
    return NULL;
}

static int create_bridge (Dpdk_Context_t *dpdkc, const int port1, const int port2)
{
    dpdkc->instances[port1].peer = &dpdkc->instances[port2];
    dpdkc->instances[port2].peer = &dpdkc->instances[port1];

    return DAQ_SUCCESS;
}

static int dpdk_close(Dpdk_Context_t *dpdkc)
{
    int num_intf;
    if (!dpdkc)
        return -1;

    /* Free all of the device instances. */
    for (num_intf = 0; num_intf < dpdkc->num_intfs; num_intf++) {
        destroy_instance(&dpdkc->instances[num_intf]);
    }

    dpdkc->state = DAQ_STATE_STOPPED;

    return 0;
}

static int parse_args(const char *inputstring, char **argv)
{
    char **ap;

    for (ap = argv; (*ap = strsep(&inputstring, " \t")) != NULL;) {
        if (**ap != '\0') {
            if (++ap >= &argv[MAX_ARGS]) {
                break;
            }
        }
    }
    return ap - argv;
}

/******************************************************************************
 Name:  dpdk_daq_instantiate

 Descr: DPDK daq initiailize instance

 IN:      const DAQ_ModuleConfig_h modcfg - daq module configration handler
          DAQ_ModuleInstance_h modinst -   daq instance specific information
          void               **ctxt_ptr - pointer to DPDK per thread context

 OUT:   int               return code 0 for success -1 for failure
*****************************************************************************/
static int dpdk_daq_instantiate (const DAQ_ModuleConfig_h  modcfg,
                                 DAQ_ModuleInstance_h      modinst,
                                 void                      **ctxt_ptr)
{
    Dpdk_Context_t *dpdkc;
    DpdkInstance *instance;
    int num_ports = 0;
    int port1, port2, ports;
    int rval = DAQ_ERROR, ret;
    char argv0[] = APP_NAME;
    char *argv[MAX_ARGS + 1];
    uint32_t pool_size = 0;
    int argc;
    int num_intfs = 0;

    dpdkc = calloc(1, sizeof(Dpdk_Context_t));
    if (!dpdkc) {
        SET_ERROR(modinst, "%s: Couldn't allocate memory for the new DPDK context!", __FUNCTION__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }

    dpdkc->modinst = modinst;
    dpdkc->device = strdup(daq_base_api.config_get_input(modcfg));
    if (unlikely(!dpdkc->device)) {
        SET_ERROR(modinst, "%s: Couldn't allocate memory for the device string!", __FUNCTION__);
        rval = DAQ_ERROR_NOMEM;
        goto err;
    }

    dpdkc->snaplen = daq_base_api.config_get_snaplen(modcfg);
    dpdkc->timeout = ((int)daq_base_api.config_get_timeout(modcfg) > 0) ?
                      (int)daq_base_api.config_get_timeout(modcfg)  : -1;

    dpdkc->dpdk_interface_id = __atomic_fetch_add(&thread_idx, 1, __ATOMIC_SEQ_CST);

    if (unlikely(dpdk_daq_get_vars(dpdkc, modcfg, modinst))) {
        rval = DAQ_ERROR_INVAL;
        goto err;
    }

	argv[0] = argv0;
	argc = parse_args(dpdkc->dpdk_args, &argv[1]) + 1;
	optind = 1;

	ret = rte_eal_init(argc, argv);
	if (unlikely(ret < 0)) {
		SET_ERROR(modinst, "%s: Invalid EAL arguments!\n", __FUNCTION__);
		rval = DAQ_ERROR_INVAL;
		goto err;
	}
	ports = rte_eth_dev_count();
	if (ports == 0) {
	   SET_ERROR(modinst, "%s: No Ethernet ports!\n", __FUNCTION__);
	   rval = DAQ_ERROR_NODEV;
	   goto err;
	}

    for (ports = 0; ports < NUM_INSTANCES; ports++) {
        instance = create_instance(dpdkc, dpdkc->instances[ports].dev);
        if (!instance) {
	        SET_ERROR(modinst, "%s: Create rx device failed for pord %d!\n", 
                      __FUNCTION__, num_ports);
            goto err;
        }
        num_intfs ++;
    }

    if (daq_base_api.config_get_mode(modcfg) != DAQ_MODE_PASSIVE) {
        if (num_intfs == NUM_INSTANCES) {
            port1 = dpdkc->instances[DEV_IDX].port;
            port2 = dpdkc->instances[PEER_IDX].port;

            if (create_bridge(dpdkc, port1, port2) != DAQ_SUCCESS) {
                SET_ERROR(modinst,"%s: Couldn't create the bridge between dpdk%d and dpdk%d!",
                          __FUNCTION__, port1, port2);
                goto err;
            }
        }
    }

    pool_size = daq_base_api.config_get_msg_pool_size(modcfg);
    if (unlikely((rval = create_packet_pool(dpdkc, pool_size)) != DAQ_SUCCESS)) {
        DBG(dpdkc, "Thread %d failed to create packet pool",
            DPDK_DAQ_GETID(dpdkc));
        goto err;
    }

    dpdkc->state = DAQ_STATE_INITIALIZED;

    *ctxt_ptr = dpdkc;
    return DAQ_SUCCESS;

err:
    if (dpdkc) {
        dpdk_close(dpdkc);
        if (dpdkc->device) {
            free(dpdkc->device);
        }
        free(dpdkc);
    }
    return rval;
}

/******************************************************************************
 Name:  dpdk_daq_destroy

 Descr: DPDK daq destroy call back

 IN:      Dpdk_Context_t *dpdk - DPDK per thread context

 OUT:   none
*****************************************************************************/
static void dpdk_daq_destroy (void *handle)
{
    Dpdk_Context_t *dpdk = (Dpdk_Context_t *) handle;
    DBG(dpdk, "Enter: Thread %d", DPDK_DAQ_GETID(dpdk));
    dpdk_daq_shutdown(handle);
}

/******************************************************************************
 Name:  dpdk_daq_set_filter

 Descr: DPDK daq set filter call back

 IN:      Dpdk_Context_t *dpdk - DPDK per thread context
          char            * filter - pointer to filer to use

 OUT:   int daq error code
*****************************************************************************/
static int dpdk_daq_set_filter (void *handle, const char *filter)
{
    /* TODO */
    return DAQ_ERROR_NOTSUP;
}

/******************************************************************************
 Name:  dpdk_daq_inject

 Descr: DPDK daq inject daq functionality

 IN:      void *handle - DPDK per thread context
          DAQ_MsgType type
          const void *hdr
          const uint8_t *data
         uint32_t data_len
 OUT:   int daq error code
*****************************************************************************/
static int dpdk_daq_inject (void *handle, DAQ_MsgType type, const void *hdr,
                             const uint8_t *data, uint32_t data_len)
{
    /* TODO */
    Dpdk_Context_t *dpdk = (Dpdk_Context_t *) handle;
    DBG(dpdk, "Enter: Thread %d",  DPDK_DAQ_GETID(dpdk));
    return DAQ_SUCCESS;
}

/******************************************************************************
 Name:  dpdk_daq_inject_relative

 Descr: DPDK daq inject relative daq functionality

 IN:      void *handle - DPDK per thread context
          const DAQ_Msg_t *msg
          const uint8_t *data
         uint32_t data_len
         int reverse
 OUT:   int daq error code
*****************************************************************************/
static int dpdk_daq_inject_relative (void *handle, const DAQ_Msg_t *msg, const
                                      uint8_t *data, uint32_t data_len, int reverse)
{
    /* TODO */
    Dpdk_Context_t *dpdk = (Dpdk_Context_t *) handle;
    DBG(dpdk, "Enter: Thread %d",  DPDK_DAQ_GETID(dpdk));
    return DAQ_SUCCESS;
}

/******************************************************************************
 Name:  dpdk_daq_interrupt

 Descr: DPDK daq interrupt daq functionality

 IN:      void *handle - DPDK per thread context

 OUT:   int daq error code
*****************************************************************************/
static int dpdk_daq_interrupt (void *handle)
{
    Dpdk_Context_t *dpdk = (Dpdk_Context_t *) handle;
    DBG(dpdk, "Enter: Thread %d",  DPDK_DAQ_GETID(dpdk));
    dpdk->interrupted = true;
    return DAQ_SUCCESS;
}

/******************************************************************************
 Name:  dpdk_daq_stop

 Descr: DPDK daq stop daq functionality

 IN:      void *handle - DPDK per thread context

 OUT:   int daq error code
*****************************************************************************/
static int dpdk_daq_stop (void *handle)
{
    Dpdk_Context_t *dpdk = (Dpdk_Context_t *) handle;
    DBG(dpdk, "Enter: Thread %d",  DPDK_DAQ_GETID(dpdk));
    dpdk_daq_close(dpdk);
    return DAQ_SUCCESS;
}

/******************************************************************************
 Name:  dpdk_daq_ioctl

 Descr: DPDK daq ioctl daq functionality

 IN:      void *handle - DPDK per thread context
          DAQ_IoctlCmd cmd
          void *arg
        size_t arglen
 OUT:   int daq error code
*****************************************************************************/
static int dpdk_daq_ioctl (void *handle, DAQ_IoctlCmd cmd,
                            void *arg, size_t arglen)
{
   /* TODO */
    Dpdk_Context_t *dpdk = (Dpdk_Context_t *) handle;

    DBG(dpdk, "Enter: Thread %d",  DPDK_DAQ_GETID(dpdk));
    return DAQ_SUCCESS;
}

/******************************************************************************
 Name:  dpdk_daq_get_stats

 Descr: DPDK read daq get stats

 IN:      void *handle        - DPDK per thread context
          DAQ_Stats_t * stats

 OUT:   int daq error code
*****************************************************************************/
static int dpdk_daq_get_stats (void *handle, DAQ_Stats_t * stats)
{
    Dpdk_Context_t *dpdk = (Dpdk_Context_t *) handle;
    DBG(dpdk, "Enter: Thread %d",  DPDK_DAQ_GETID(dpdk));

    memcpy(stats, &dpdk->stats, sizeof(DAQ_Stats_t));
    return DAQ_SUCCESS;
}

/******************************************************************************
 Name:  dpdk_daq_get_reset_stats

 Descr: DPDK read daq reset stats

 IN:      void *handle        - DPDK per thread context

 OUT:   int daq error code
*****************************************************************************/
static void dpdk_daq_reset_stats (void *handle)
{
    Dpdk_Context_t *dpdk = (Dpdk_Context_t *) handle;
    DBG(dpdk, "Enter: Thread %d",  DPDK_DAQ_GETID(dpdk));
    memset(&dpdk->stats, 0, sizeof(DAQ_Stats_t));;
}

/******************************************************************************
 Name:  dpdk_daq_get_snaplen

 Descr: DPDK read daq reset stats

 IN:      void *handle        - DPDK per thread context

 OUT:   int  buffer size
*****************************************************************************/
static int dpdk_daq_get_snaplen (void *handle)
{
    Dpdk_Context_t *dpdk = (Dpdk_Context_t *) handle;
    DBG(dpdk, "Enter: Thread %d",  DPDK_DAQ_GETID(dpdk));
    return dpdk->snaplen;
}

/******************************************************************************
 Name:  dpdk_daq_get_capabilities

 Descr: DPDK get all supported capabilities

 IN:      void *handle        - DPDK per thread context

 OUT:   int capabilities
*****************************************************************************/
static uint32_t dpdk_daq_get_capabilities (void *handle)
{
    uint32_t capabilities = DAQ_CAPA_BLOCK          |
                            DAQ_CAPA_REPLACE        |
                            DAQ_CAPA_INJECT         |
                            DAQ_CAPA_UNPRIV_START   |
                            DAQ_CAPA_INTERRUPT      |
                            DAQ_CAPA_DEVICE_INDEX;
    Dpdk_Context_t *dpdk = (Dpdk_Context_t *) handle;

#ifdef LIBPCAP_AVAILABLE
    capabilities |= DAQ_CAPA_BPF;
#endif
    DBG(dpdk, "Enter: Thread %d capabilities = 0x%08x",
        DPDK_DAQ_GETID(dpdk), capabilities);
    return capabilities;
}

/******************************************************************************
 Name:  dpdk_daq_get_datalink_type

 Descr: DPDK get datalink type

 IN:      void *handle        - DPDK per thread context

 OUT:   int datalink type
*****************************************************************************/
static int dpdk_daq_get_datalink_type (void *handle)
{
    Dpdk_Context_t *dpdk = (Dpdk_Context_t *) handle;
    DBG(dpdk, "Enter: Thread %d",  DPDK_DAQ_GETID(dpdk));
    return DLT_EN10MB;
}

/******************************************************************************
 Name:  dpdk_daq_msg_receive

 Descr: DPDK packets receive daq plugin call back

 IN:    void             *handle  - DPDK context
        const unsigned   max_recv - Max packets received by default its set to 64
                                     use --daq-batch-size to change it if needed
        const            DAQ_Msg_t *msgs[] - array of received packets
        DAQ_RecvStatus   *rstat            - pointer to receive return code

OUT:    int daq error code
*****************************************************************************/
static unsigned dpdk_daq_msg_receive (void             *handle,
                                      const unsigned   max_recv,
                                      const            DAQ_Msg_t *msgs[],
                                      DAQ_RecvStatus   *rstat)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
    DAQ_RecvStatus status = DAQ_RSTAT_OK;
    DpdkInstance *instance, *peer;
    DpdkPktDesc *desc;
    DAQ_Msg_t *msg;
    DAQ_PktHdr_t *daqhdr;
    const uint8_t *data;
    uint16_t len;
    int c = 0, burst_size;
    int i, queue, inst;
    struct timeval ts;

    while (c < max_recv || max_recv <= 0) {
        struct rte_mbuf *bufs[BURST_SIZE];

        for (inst = 0; inst< dpdkc->num_intfs; inst++ ) {
            if (dpdkc->interrupted) {
                dpdkc->interrupted = false;
                status = DAQ_RSTAT_INTERRUPTED;
                goto err;
            }
            instance = &dpdkc->instances[inst];
            peer = instance->peer;

            for (queue = 0; queue < instance->rx_rings; queue++) {
                gettimeofday(&ts, NULL);

                if (max_recv <= 0 || max_recv - c >= BURST_SIZE) {
                    burst_size = BURST_SIZE;
                } else {
                    burst_size = max_recv - c;
                }

                const uint16_t nb_rx = rte_eth_rx_burst(instance->port, queue,
                                                        bufs, burst_size);


                if (unlikely(nb_rx == 0)) {
                    continue;
                }

                for (i = 0; i < nb_rx; i++) {
                    data = rte_pktmbuf_mtod(bufs[i], void *);
                    len = rte_pktmbuf_data_len(bufs[i]);
                    desc = dpdkc->pool.freelist;
                    if (unlikely(!desc)) {
                        status = DAQ_RSTAT_NOBUF;
                        goto err;
                    }
                    hex_dump(dpdkc, data, len, (uint64_t)bufs[i]);

                    dpdkc->stats.packets_received++;
                    desc->data = (uint8_t *)data;
                    desc->length = len;
                    if (peer) {
                        peer->tx_burst = bufs[i];
                    }
                    desc->peer = peer;
                    desc->peer_queue = queue;
                    msg = &desc->msg;
                    msg->data_len = len;
                    msg->data = desc->data;

                    daqhdr = &desc->pkthdr;

                    daqhdr->ts = ts;
                    daqhdr->pktlen = len;
                    daqhdr->flags = 0;
                    daqhdr->opaque = 0;
                    daqhdr->address_space_id = 0;

                    dpdkc->pool.freelist = desc->next;
                    if (unlikely(!desc)) {
                        status = DAQ_RSTAT_NOBUF;
                        goto err;
                    }
                    desc->next = NULL;
                    dpdkc->pool.info.available--;
                    msgs[c] = &desc->msg;
                    c++;
                }
            }
        }
    }
err:
    DBG(dpdkc, "Exit: Thread %d with status %s rx count %d",
        DPDK_DAQ_GETID(dpdkc), dpdkdaq_status_to_str[status], c);

    *rstat = status;
    return c;
}

/******************************************************************************
 Name:  dpdk_daq_msg_finalize

 Descr: DPDK single packet transmit daq plugin call back

 IN:        void *handle            - DPDK context
            const DAQ_Msg_t *msg    - pointer to the packet to transmit
            DAQ_Verdict verdict     - verdict based of snort inspection

 OUT:   int              return daq error code
*****************************************************************************/
static int dpdk_daq_msg_finalize (void *handle,
                                  const DAQ_Msg_t *msg,
                                  DAQ_Verdict verdict)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *)handle;
    DpdkPktDesc *desc = (DpdkPktDesc *) msg->priv;
    DpdkInstance *peer;
    struct rte_mbuf *tx_burst;
    int peer_queue;

    dpdkc->stats.verdicts[verdict]++;

    peer = desc->peer;
    peer_queue = desc->peer_queue;
    tx_burst = peer->tx_burst;
    verdict = verdict_translation_table[verdict];
    if (verdict == DAQ_VERDICT_PASS) {
       (void)rte_eth_tx_burst(peer->port, peer_queue, &tx_burst, 1);
    }

    /* Toss the descriptor back on the free list for reuse. */
    desc->next = dpdkc->pool.freelist;
    dpdkc->pool.freelist = desc;
    dpdkc->pool.info.available++;

    rte_pktmbuf_free(tx_burst);
    return DAQ_SUCCESS;
}

/******************************************************************************
 Name:  dpdk_daq_start

 Descr: DPDK daq start daq functionality

 IN:      void *handle - DPDK per thread context

 OUT:   int daq error code
*****************************************************************************/
static int dpdk_daq_start (void *handle)
{
    Dpdk_Context_t *dpdkc = (Dpdk_Context_t *) handle;
    DpdkInstance *instance;
    uint32_t inst;

    for (inst = 0; inst < dpdkc->num_intfs; inst++) {
        instance = &dpdkc->instances[inst];
        if (start_instance(dpdkc, instance) != DAQ_SUCCESS) {
            return DAQ_ERROR;
        }
    }

    dpdk_daq_reset_stats(handle);

    dpdkc->state = DAQ_STATE_STARTED;

    return DAQ_SUCCESS;
}

/******************************************************************************
 Name:  dpdk_daq_get_msg_pool_info

 Descr: DPDK get allocated daq pool info

 IN:        void *handle            - DPDK context
            DAQ_MsgPoolInfo_t *info - daq msg pool info

 OUT:   int               return daq error code
*****************************************************************************/
static int dpdk_daq_get_msg_pool_info (void *handle, DAQ_MsgPoolInfo_t *info)
{
    Dpdk_Context_t *dpdk = (Dpdk_Context_t *) handle;
    DBG(dpdk, "Enter: Thread %d",  DPDK_DAQ_GETID(dpdk));

    *info = dpdk->pool.info;
    return DAQ_SUCCESS;
}

#ifdef BUILDING_SO
DAQ_SO_PUBLIC const  DAQ_ModuleAPI_t DAQ_MODULE_DATA =
#else
const  DAQ_ModuleAPI_t dpdk_daq_module_data =
#endif
{
    /* .api_version = */ DAQ_MODULE_API_VERSION,
    /* .api_size = */ sizeof(DAQ_ModuleAPI_t),
    /* .module_version = */ DAQ_DPDK_VERSION,
    /* .name = */ "dpdk",
    /* .type = */ DAQ_TYPE_INLINE_CAPABLE | DAQ_TYPE_INTF_CAPABLE | DAQ_TYPE_MULTI_INSTANCE,
    /* .load = */ dpdk_daq_module_load,
    /* .unload = */ dpdk_daq_module_unload,
    /* .get_variable_descs = */ dpdk_daq_get_variable_descs,
    /* .instantiate  = */ dpdk_daq_instantiate,
    /* .destroy = */ dpdk_daq_destroy,
    /* .set_filter = */ dpdk_daq_set_filter,
    /* .start = */ dpdk_daq_start,
    /* .inject = */ dpdk_daq_inject,
    /* .inject_relative = */ dpdk_daq_inject_relative,
    /* .interrupt = */ dpdk_daq_interrupt,
    /* .stop = */ dpdk_daq_stop,
    /* .ioctl = */ dpdk_daq_ioctl,
    /* .get_stats = */ dpdk_daq_get_stats,
    /* .reset_stats = */ dpdk_daq_reset_stats,
    /* .get_snaplen = */ dpdk_daq_get_snaplen,
    /* .get_capabilities = */ dpdk_daq_get_capabilities,
    /* .get_datalink_type = */ dpdk_daq_get_datalink_type,
    /* .config_load = */ NULL,
    /* .config_swap = */ NULL,
    /* .config_free = */ NULL,
    /* .msg_receive = */ dpdk_daq_msg_receive,
    /* .msg_finalize = */ dpdk_daq_msg_finalize,
    /* .get_msg_pool_info = */ dpdk_daq_get_msg_pool_info,
};