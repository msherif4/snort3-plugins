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
#ifndef DAQ_MEMIF_H
#define DAQ_MEMIF_H

#define MEMIF_IFACE_LOG2_RING_SIZE 11
#define MEMIF_IFACE_BUFFER_SIZE (1 << MEMIF_IFACE_LOG2_RING_SIZE)

#define MAX_MEMIF_BUFS 256

#include <daq_common.h>

typedef struct _memif_pkt_desc
{
    DAQ_Msg_t msg;
    DAQ_NAPTInfo_t nat_info;
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

#endif /* DAQ_MEMIF_H */
