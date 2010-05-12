/****************************************************************************
 *
 * Copyright (C) 2005-2008 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 ****************************************************************************/
 
#ifndef STREAM5_COMMON_H_
#define STREAM5_COMMON_H_

#include <sys/types.h>
#ifndef WIN32
#include <netinet/in.h>
#endif
#include "parser/IpAddrSet.h"

#include "stream_api.h"
#include "mempool.h"
#include "sf_types.h"

#ifdef TARGET_BASED
#include "target-based/sftarget_hostentry.h"
#endif

//#define DEBUG_STREAM5 DEBUG

/* Only track a maximum number of alerts per session */
#define MAX_SESSION_ALERTS 8

/* Define the maximum ports */
#define MAX_PORTS 65536

/* defaults and limits */
#define S5_DEFAULT_SSN_TIMEOUT  30        /* seconds to timeout a session */
#define S5_MAX_SSN_TIMEOUT      3600*24   /* max timeout (approx 1 day) */
#define S5_MIN_SSN_TIMEOUT      1         /* min timeout (1 second) */
#define S5_MIN_ALT_HS_TIMEOUT   0         /* min timeout (0 seconds) */
#define S5_DEFAULT_MIN_TTL      1         /* default for min TTL */
#define S5_MIN_MIN_TTL          1         /* min for min TTL */
#define S5_MAX_MIN_TTL          255       /* max for min TTL */
#define S5_TRACK_YES            1
#define S5_TRACK_NO             0
#define S5_MAX_MAX_WINDOW       0x3FFFc000 /* max window allowed by TCP */
                                           /* 65535 << 14 (max wscale) */
#define S5_MIN_MAX_WINDOW       0

/* target-based policy types */
#define STREAM_POLICY_FIRST     1
#define STREAM_POLICY_LINUX     2
#define STREAM_POLICY_BSD       3
#define STREAM_POLICY_OLD_LINUX 4
#define STREAM_POLICY_LAST      5
#define STREAM_POLICY_WINDOWS   6
#define STREAM_POLICY_SOLARIS   7
#define STREAM_POLICY_HPUX11    8
#define STREAM_POLICY_IRIX      9
#define STREAM_POLICY_MACOS     10
#define STREAM_POLICY_HPUX10    11
#define STREAM_POLICY_VISTA     12
#define STREAM_POLICY_WINDOWS2K3 13
#define STREAM_POLICY_DEFAULT   STREAM_POLICY_BSD

#define STREAM5_CONFIG_STATEFUL_INSPECTION      0x00000001
#define STREAM5_CONFIG_ENABLE_ALERTS            0x00000002
#define STREAM5_CONFIG_LOG_STREAMS              0x00000004
#define STREAM5_CONFIG_REASS_CLIENT             0x00000008
#define STREAM5_CONFIG_REASS_SERVER             0x00000010
#define STREAM5_CONFIG_ASYNC                    0x00000020
#define STREAM5_CONFIG_SHOW_PACKETS             0x00000040
#define STREAM5_CONFIG_FLUSH_ON_ALERT           0x00000080
#define STREAM5_CONFIG_REQUIRE_3WHS             0x00000100
#define STREAM5_CONFIG_MIDSTREAM_DROP_NOALERT   0x00000200
#define STREAM5_CONFIG_IGNORE_ANY               0x00000400
#define STREAM5_CONFIG_PERFORMANCE              0x00000800
#define STREAM5_CONFIG_STATIC_FLUSHPOINTS       0x00001000
#define STREAM5_CONFIG_DEFAULT_TCP_POLICY_SET   0x00002000
#define STREAM5_CONFIG_CHECK_SESSION_HIJACKING  0x00004000

/* traffic direction identification */
#define FROM_SERVER     0
#define FROM_RESPONDER  0
#define FROM_CLIENT     1
#define FROM_SENDER     1

#define STREAM5_STATE_NONE                  0x0000
#define STREAM5_STATE_SYN                   0x0001
#define STREAM5_STATE_SYN_ACK               0x0002
#define STREAM5_STATE_ACK                   0x0004
#define STREAM5_STATE_ESTABLISHED           0x0008
#define STREAM5_STATE_DROP_CLIENT           0x0010
#define STREAM5_STATE_DROP_SERVER           0x0020
#define STREAM5_STATE_MIDSTREAM             0x0040
#define STREAM5_STATE_RESET                 0x0080
#define STREAM5_STATE_CLIENT_RESET          0x0100
#define STREAM5_STATE_SERVER_RESET          0x0200
#define STREAM5_STATE_TIMEDOUT              0x0400
#define STREAM5_STATE_UNREACH               0x0800
#define STREAM5_STATE_SENDER_SEEN           0x1000
#define STREAM5_STATE_RECEIVER_SEEN         0x2000
#define STREAM5_STATE_CLOSED                0x4000

#define TCP_HZ          100

/*  D A T A   S T R U C T U R E S  **********************************/
typedef struct _SessionKey
{
/* XXX If this data structure changes size, HashKeyCmp must be updated! */
#ifdef SUP_IP6
    u_int32_t   ip_l[4]; /* Low IP */
    u_int32_t   ip_h[4]; /* High IP */
#else
    u_int32_t   ip_l; /* Low IP */
    u_int32_t   ip_h; /* High IP */
#endif
    u_int16_t   port_l; /* Low Port - 0 if ICMP */
    u_int16_t   port_h; /* High Port - 0 if ICMP */
    u_int16_t   vlan_tag;
    char        protocol;
    char        pad;
#ifdef MPLS
    u_int32_t   mplsLabel; /* MPLS label */
    u_int32_t   mplsPad;
#endif
/* XXX If this data structure changes size, HashKeyCmp must be updated! */
} SessionKey;

typedef struct _Stream5AppData
{
    u_int32_t   protocol;
    void        *dataPointer;
    struct _Stream5AppData *next;
    struct _Stream5AppData *prev;
    StreamAppDataFree freeFunc;
} Stream5AppData;

typedef struct _Stream5AlertInfo
{
    /* For storing alerts that have already been seen on the session */
    u_int32_t sid;
    u_int32_t gid;
    u_int32_t seq;
} Stream5AlertInfo;

typedef struct _Stream5LWSession
{
    SessionKey  key;

    snort_ip        client_ip;
    snort_ip        server_ip;
    u_int16_t   client_port;
    u_int16_t   server_port;
    char        protocol;
#ifdef TARGET_BASED
    int16_t ipprotocol;
    int16_t application_protocol;
#endif

    long        last_data_seen;
    UINT64      expire_time;
    char        direction;
    /* flag to ignore traffic on this session */
    char        ignore_direction;

    MemBucket   *proto_specific_data;
    u_int16_t   session_state;

    u_int32_t   session_flags;

    u_int32_t   application_protocols;
#if 0
    u_int16_t   process_as_port1; /* client/sender port equivalency */
    u_int16_t   process_as_port2; /* server/responder port equivalency */
#endif

    Stream5AppData *appDataList;

    /* add flowbits */
    MemBucket *flowdata;
} Stream5LWSession;

typedef struct _Stream5GlobalConfig
{
    char        track_tcp_sessions;
    u_int32_t   max_tcp_sessions;
    u_int32_t   tcp_packet_memcap;
    char        track_udp_sessions;
    u_int32_t   max_udp_sessions;
    char        track_icmp_sessions;
    u_int32_t   max_icmp_sessions;
    u_int32_t   memcap;
    u_int32_t   mem_in_use;
    u_int32_t   flags;
} Stream5GlobalConfig;

typedef struct _Stream5Stats
{
    u_int32_t   total_tcp_sessions;
    u_int32_t   total_udp_sessions;
    u_int32_t   total_icmp_sessions;
    u_int32_t   tcp_prunes;
    u_int32_t   udp_prunes;
    u_int32_t   icmp_prunes;
    u_int32_t   tcp_timeouts;
    u_int32_t   tcp_streamtrackers_created;
    u_int32_t   tcp_streamtrackers_released;
    u_int32_t   tcp_streamsegs_created;
    u_int32_t   tcp_streamsegs_released;
    u_int32_t   tcp_rebuilt_packets;
    u_int32_t   tcp_rebuilt_seqs_used;
    u_int32_t   tcp_overlaps;
    u_int32_t   tcp_discards;
    u_int32_t   udp_timeouts;
    u_int32_t   udp_sessions_created;
    u_int32_t   udp_sessions_released;
    u_int32_t   udp_discards;
    u_int32_t   icmp_timeouts;
    u_int32_t   icmp_sessions_created;
    u_int32_t   icmp_sessions_released;
    u_int32_t   events;
} Stream5Stats;

extern Stream5GlobalConfig s5_global_config;
extern Stream5Stats s5stats;
extern u_int32_t firstPacketTime;
extern MemPool s5FlowMempool;

void Stream5DisableInspection(Stream5LWSession *lwssn, Packet *p);

int Stream5Expire(Packet *p, Stream5LWSession *ssn);
void Stream5SetExpire(Packet *p, Stream5LWSession *ssn, u_int32_t timeout);
void MarkupPacketFlags(Packet *p, Stream5LWSession *ssn);
#ifdef TARGET_BASED
void Stream5SetApplicationProtocolIdFromHostEntry(Stream5LWSession *lwssn,
                                           HostAttributeEntry *host_entry,
                                           int direction);
#endif

#endif /* STREAM5_COMMON_H_ */
