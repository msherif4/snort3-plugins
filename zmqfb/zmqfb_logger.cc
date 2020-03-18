//--------------------------------------------------------------------------
// Copyright (C) 2020 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//--------------------------------------------------------------------------

/* zmqfb_logger.cc
 * Mohamed S. Mahmoud
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "flatbuffers/flatbuffers.h"
#include "flatbuffers/idl.h"
#include "flatbuffers/minireflect.h"
#include "flatbuffers/registry.h"
#include "flatbuffers/util.h"
#include "IntrusionEvent_generated.h"
#include <detection/signature.h>
#include <detection/detection_util.h>
#include <events/event.h>
#include <framework/logger.h>
#include <framework/module.h>
#include <framework/counts.h>
#include <log/messages.h>
#include <log/obfuscator.h>
#include <main/snort_config.h>
#include <network_inspectors/appid/appid_api.h>
#include <packet_io/active.h>
#include <protocols/icmp4.h>
#include <protocols/packet.h>
#include <stream/stream.h>
#include <utils/safec.h>
#include <utils/util.h>
#include <utils/util_cstring.h>
#include <zmq.h>

using namespace snort;
using namespace std;

#define S_NAME "zmqfb"

/*------------------ Data structures --------------------------*/
struct ZmqFbConfig
{
    /* Zmq socket configuration */
    uint32_t highwatermark;
    uint32_t send_timeout_ms;
    const char *tcpsocket;
    uint32_t ipv6Enabled;
};

static const PegInfo zmqfbstats_peg_names[] =
{
    { CountType::SUM, "zmq_queue_full", "number of times Zmq Queue is full" },
    { CountType::END, nullptr, nullptr }
};

struct ZmqFb
{
    void *zmq_context;
    void *zmq_sender;
};

struct ZmqFbStats
{
    PegCount zmq_queue_full;    
};

/*-------------------- Global Variables ----------------------*/
static THREAD_LOCAL ZmqFb zmqfb;
static THREAD_LOCAL ZmqFbStats zmqfbstats;
/*-------------------- Local Functions -----------------------*/

static void alert_event(Packet* p, const char*, ZmqFbConfig* config, const Event* event)
{
    int rc;
    flatbuffers::FlatBufferBuilder fbBuilder;
    SfIpString srcIP = "", dstIP = "";

    if ( p && p->ptrs.ip_api.is_ip() ) {
        memcpy(srcIP, p->ptrs.ip_api.get_src()->get_ip6_ptr(), sizeof(SfIpString));
        memcpy(dstIP, p->ptrs.ip_api.get_dst()->get_ip6_ptr(), sizeof(SfIpString));
    }

    std::vector<uint8_t> srcIP_vector((uint8_t*) srcIP, ((uint8_t*) srcIP) + sizeof(struct in6_addr));
    auto InitiatorIP = fbBuilder.CreateVector(srcIP_vector);
    std::vector<uint8_t> dstIP_vector((uint8_t*) dstIP, ((uint8_t*) dstIP) + sizeof(struct in6_addr));
    auto ResponderIP = fbBuilder.CreateVector(dstIP_vector);

    IntrusionEventBuilder eventBuilder(fbBuilder);

    eventBuilder.add_EventID(event->event_id);
    eventBuilder.add_EventSecond(event->ref_time.tv_sec);
    eventBuilder.add_EventMicrosecond(event->ref_time.tv_usec);

    eventBuilder.add_GeneratorID(event->sig_info->gid);
    eventBuilder.add_SignatureID(event->sig_info->sid);
    eventBuilder.add_SignatureRevision(event->sig_info->rev);
    eventBuilder.add_ClassificationID(event->sig_info->class_id);
    eventBuilder.add_PriorityID(event->sig_info->priority);

    if ( p )
    {
        eventBuilder.add_IntrusionPolicyUUID(p->user_ips_policy_id);
        if ( p->ptrs.ip_api.is_ip() ) {
            eventBuilder.add_InitiatorIP(InitiatorIP);
            eventBuilder.add_ResponderIP(ResponderIP);
        }
        eventBuilder.add_InitiatorPort(p->ptrs.sp);
        eventBuilder.add_ResponderPort(p->ptrs.dp);

        eventBuilder.add_ProtocolID((uint8_t)p->get_ip_proto_next());
        eventBuilder.add_Action(p->active->get_action());
        eventBuilder.add_Status(p->active->get_status());
    }

    auto fbb = eventBuilder.Finish();
    fbBuilder.Finish(fbb);
    auto zmqfb_event_buffer = fbBuilder.GetBufferPointer();

    rc = zmq_send(zmqfb.zmq_sender, zmqfb_event_buffer,
                  fbBuilder.GetSize(), ZMQ_NOBLOCK);
    if (rc < 0) {
        if (errno == EAGAIN) {
            if (zmqfbstats.zmq_queue_full == 0) {
                LogMessage("WARNING: AlertZmqFb: Unable to send ZMQ Endpoint's queue is Full "
                            "%s.\n", get_error(errno));
            }
            zmqfbstats.zmq_queue_full++;
        } else if (errno != EINTR) {
            FatalError("AlertZmqFb: zmq_send failed with %s\n", get_error(errno));
        }
    }
    fbBuilder.Clear();
}

//-------------------------------------------------------------------------
// zmqfb module
//-------------------------------------------------------------------------
static const Parameter s_params[] =
{
    { "highwatermark", Parameter::PT_INT, "0:maxSZ", "0",
      "set ZMQ socket highwater mark threshold" },
    { "send_timeout_ms", Parameter::PT_INT, "0:maxSZ", "0",
      "set ZMQ socket send timeout" },
    { "ipv6Enabled", Parameter::PT_INT, "0:maxSZ", "0",
      "set ZMQ socket ipv6 enable flag" },
    { "tcpsocket", Parameter::PT_STRING, nullptr, nullptr,
      "TCP socket used to communicate with ZMQ endpoints" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "output event and packet in FlatBuffer format over ZMQ PUSH/PULL socket"

class ZmqFbModule : public Module
{
public:
    ZmqFbModule() : Module(S_NAME, s_help, s_params) { }

    bool set(const char*, Value&, SnortConfig*) override;
    bool begin(const char*, int, SnortConfig*) override;
    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;
    Usage get_usage() const override
    { return CONTEXT; }

public:
    uint32_t highwatermark;
    uint32_t send_timeout_ms;
    const char *tcpsocket;
    uint32_t ipv6Enabled;
};

const PegInfo* ZmqFbModule::get_pegs() const
{
    return zmqfbstats_peg_names;
}

PegCount* ZmqFbModule::get_counts() const
{
    return (PegCount*)&zmqfbstats;
}

bool ZmqFbModule::set(const char*, Value& v, SnortConfig*)
{
    if ( v.is("highwatermark") ) {
        highwatermark = v.get_uint32();
    } else if ( v.is("tcpsocket") ) {
        tcpsocket = strdup(v.get_string());
        if (tcpsocket == NULL) {
            return false;
        }
    } else if ( v.is("ipv6Enabled") ) {
        ipv6Enabled = v.get_uint32();
    } else if ( v.is("send_timeout_ms") ) {
        send_timeout_ms = v.get_uint32();
    } else {
        return false;
    }
    return true;
}

bool ZmqFbModule::begin(const char*, int, SnortConfig*)
{
    // Initial values which can be overwritten by commandline args.
    highwatermark = 110000;
    tcpsocket = "tcp://localhost:5558";
    ipv6Enabled = 0;
    send_timeout_ms = 1000;
    return true;
}

//-------------------------------------------------------------------------
// logger stuff
//-------------------------------------------------------------------------

class ZmqFbLogger : public Logger
{
public:
    ZmqFbLogger(ZmqFbModule*);

    void open() override;
    void close() override;

    void alert(Packet*, const char* msg, const Event&) override;

private:
    ZmqFbConfig config;
};

ZmqFbLogger::ZmqFbLogger(ZmqFbModule* m)
{
    config.highwatermark = m->highwatermark;
    config.tcpsocket = m->tcpsocket;
    config.ipv6Enabled = m->ipv6Enabled;
    config.send_timeout_ms = m->send_timeout_ms;
}

void ZmqFbLogger::open()
{
    int rc;
    zmqfb.zmq_context = zmq_ctx_new();
    if (!zmqfb.zmq_context) {
        FatalError("AlertZmqFb: zmq_ctx_new failed\n");
        return;
    }

    //Socket to send messages on
    zmqfb.zmq_sender = zmq_socket(zmqfb.zmq_context, ZMQ_PUSH);
    if (!zmqfb.zmq_sender) {
        FatalError("AlertZmqFb: zmq_socket failed with %s\n", get_error(errno));
        return;
    }

    //Set socket highwater mark
    rc = zmq_setsockopt(zmqfb.zmq_sender, ZMQ_SNDHWM, &config.highwatermark,
                        sizeof(config.highwatermark));
    if (rc < 0) {
        FatalError("AlertZmqFb: zmq_setsockopt high water mark failed with %s\n", get_error(errno));
        return;
    }

    //Set socket send timeout
    rc = zmq_setsockopt(zmqfb.zmq_sender, ZMQ_SNDTIMEO, &config.send_timeout_ms, 
                        sizeof(config.send_timeout_ms));
    if (rc < 0) {
        FatalError("AlertZmqFb: zmq_setsockopt send timeout failed with %s\n", get_error(errno));
        return;
    }

    //Set IPv6 mode
    rc = zmq_setsockopt(zmqfb.zmq_sender, ZMQ_IPV6, &config.ipv6Enabled,
                        sizeof(config.ipv6Enabled));
    if (rc < 0) {
        FatalError("AlertZmqFb: zmq_setsockopt ipv6 enabled failed with %s\n", get_error(errno));
        return;
    }

    rc = zmq_connect(zmqfb.zmq_sender, config.tcpsocket);
    if (rc < 0) {
        FatalError("AlertZmqFb: zmq_connect failed with %s\n", get_error(errno));
    }

    zmqfbstats.zmq_queue_full = 0;
}

void ZmqFbLogger::close()
{
    free((void *)config.tcpsocket);
    zmq_close(zmqfb.zmq_sender);
    zmq_ctx_destroy(zmqfb.zmq_context);
}

void ZmqFbLogger::alert(Packet* p, const char* msg, const Event& event)
{
    alert_event(p, msg, &config, &event);

}

//-------------------------------------------------------------------------
// api stuff
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new ZmqFbModule; }

static void mod_dtor(Module* m)
{ delete m; }

static Logger* zmqfb_ctor(SnortConfig*, Module* mod)
{ return new ZmqFbLogger((ZmqFbModule*)mod); }

static void zmqfb_dtor(Logger* p)
{ delete p; }

static LogApi zmqfb_api
{
    {
        PT_LOGGER,
        sizeof(LogApi),
        LOGAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        S_NAME,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OUTPUT_TYPE_FLAG__ALERT,
    zmqfb_ctor,
    zmqfb_dtor
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* alert_zmqfb[] =
#endif
{
    &zmqfb_api.base,
    nullptr
};
