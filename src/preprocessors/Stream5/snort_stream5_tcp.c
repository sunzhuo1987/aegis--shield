/* $Id$ */
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

/**
 * @file    snort_stream5_tcp.c
 * @author  Martin Roesch <roesch@sourcefire.com>
 * @author  Steven Sturges <ssturges@sourcefire.com>
 *
 */

/*
 * TODOs:
 * - midstream ssn pickup (done, SAS 10/14/2005)
 * - syn flood protection (done, SAS 9/27/2005)
 *
 * - review policy anomaly detection
 *   + URG pointer (TODO)
 *   + data on SYN (done, SAS 10/12/2005)
 *   + data on FIN (done, SAS 10/12/2005)
 *   + data after FIN (done, SAS 10/13/2005)
 *   + window scaling/window size max (done, SAS 10/13/2005)
 *   + PAWS, TCP Timestamps (done, SAS 10/12/2005)
 *
 * - session shutdown/Reset handling (done, SAS)
 * - flush policy for Window/Consumed
 * - limit on number of overlapping packets (done, SAS)
 */

/*
 * Copyright (C) 2004-2008 Sourcefire, Inc.
 */
#include "debug.h"
#include "detect.h"
#include "plugbase.h"
#include "mstring.h"
#include "sfxhash.h"
#include "util.h"
#include "sflsq.h"
#include "bounds.h"
#include "generators.h"
#include "event_queue.h"
#include "snort.h"
#include "parser/IpAddrSet.h"

#include "decode.h"
#include "log.h"

#include "stream5_common.h"
#include "stream_api.h"
#include "snort_stream5_session.h"
#include "stream_ignore.h"

#include "inline.h"
#include <errno.h>

#ifdef TARGET_BASED
#include "sftarget_protocol_reference.h"
#include "sftarget_hostentry.h"
#endif

#include "profiler.h"

#include "ipv6_port.h"
#include "sf_iph.h"

#include "sp_preprocopt.h"

#ifdef PERF_PROFILING
PreprocStats s5TcpPerfStats;
PreprocStats s5TcpNewSessPerfStats;
PreprocStats s5TcpStatePerfStats;
PreprocStats s5TcpDataPerfStats;
PreprocStats s5TcpInsertPerfStats;
PreprocStats s5TcpFlushPerfStats;
PreprocStats s5TcpBuildPacketPerfStats;
PreprocStats s5TcpProcessRebuiltPerfStats;
#endif

/*  M A C R O S  **************************************************/

/* TCP flags */
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_NORESERVED (TH_FIN|TH_SYN|TH_RST|TH_PUSH|TH_ACK|TH_URG)

/* TCP states */
#define TCP_STATE_NONE         0
#define TCP_STATE_LISTEN       1
#define TCP_STATE_SYN_RCVD     2
#define TCP_STATE_SYN_SENT     3
#define TCP_STATE_ESTABLISHED  4
#define TCP_STATE_CLOSE_WAIT   5
#define TCP_STATE_LAST_ACK     6
#define TCP_STATE_FIN_WAIT_1   7
#define TCP_STATE_CLOSING      8
#define TCP_STATE_FIN_WAIT_2   9
#define TCP_STATE_TIME_WAIT   10
#define TCP_STATE_CLOSED      11

/* Macros to deal with sequence numbers - p810 TCP Illustrated vol 2 */
#define SEQ_LT(a,b)  ((int)((a) - (b)) <  0)
#define SEQ_LEQ(a,b) ((int)((a) - (b)) <= 0)
#define SEQ_GT(a,b)  ((int)((a) - (b)) >  0)
#define SEQ_GEQ(a,b) ((int)((a) - (b)) >= 0)
#define SEQ_EQ(a,b)  ((int)((a) - (b)) == 0)

#define PAWS_WINDOW         60
#define PAWS_24DAYS         2073600         /* 24 days in seconds */

/* for state transition queuing */
#define CHK_SEQ         0
#define NO_CHK_SEQ      1

#define S5_UNALIGNED       0
#define S5_ALIGNED         1

/* actions */
#define ACTION_NOTHING                  0x00000000
#define ACTION_FLUSH_SENDER_STREAM      0x00000001
#define ACTION_FLUSH_RECEIVER_STREAM    0x00000002
#define ACTION_DROP_SESSION             0x00000004
#define ACTION_ACK_SENDER_DATA          0x00000008
#define ACTION_ACK_RECEIVER_DATA        0x00000010
#define ACTION_SET_SSN                  0x00000040
#define ACTION_COMPLETE_TWH             0x00000080
#define ACTION_RST                      0x00000100
#define ACTION_BAD_SEQ                  0x00000200
#define ACTION_BAD_PKT                  0x00000400

/* events */
#define EVENT_SYN_ON_EST                0x00000001
#define EVENT_DATA_ON_SYN               0x00000002
#define EVENT_DATA_ON_CLOSED            0x00000004
#define EVENT_BAD_TIMESTAMP             0x00000008
#define EVENT_BAD_SEGMENT               0x00000010
#define EVENT_WINDOW_TOO_LARGE          0x00000020
#define EVENT_EXCESSIVE_TCP_OVERLAPS    0x00000040
#define EVENT_DATA_AFTER_RESET          0x00000080
#define EVENT_SESSION_HIJACK_CLIENT     0x00000100
#define EVENT_SESSION_HIJACK_SERVER     0x00000200
#define EVENT_DATA_WITHOUT_FLAGS        0x00000400

#define TF_NONE                     0x00
#define TF_WSCALE                   0x01
#define TF_TSTAMP                   0x02
#define TF_TSTAMP_ZERO              0x04
#define TF_MSS                      0x08
#define TF_FORCE_FLUSH              0x10
#define TF_MISSING_PKT              0x20
#define TF_PKT_MISSED               0x40
#define TF_MISSING_PREV_PKT         0x80
#define TF_ALL                      0xFF

#define STREAM_INSERT_OK            0
#define STREAM_INSERT_ANOMALY       1
#define STREAM_INSERT_TIMEOUT       2
#define STREAM_INSERT_FAILED        3

#define S5_DEFAULT_TCP_PACKET_MEMCAP  8388608  /* 8MB */
#define S5_MIN_OVERLAP_LIMIT 0
#define S5_MAX_OVERLAP_LIMIT 255

#define REASSEMBLY_POLICY_FIRST     1
#define REASSEMBLY_POLICY_LINUX     2
#define REASSEMBLY_POLICY_BSD       3
#define REASSEMBLY_POLICY_OLD_LINUX 4
#define REASSEMBLY_POLICY_LAST      5
#define REASSEMBLY_POLICY_WINDOWS   6
#define REASSEMBLY_POLICY_SOLARIS   7
#define REASSEMBLY_POLICY_HPUX11    8
#define REASSEMBLY_POLICY_IRIX      9
#define REASSEMBLY_POLICY_MACOS     10
#define REASSEMBLY_POLICY_HPUX10    11
#define REASSEMBLY_POLICY_VISTA     12
#define REASSEMBLY_POLICY_WINDOWS2K3 13
#define REASSEMBLY_POLICY_DEFAULT   REASSEMBLY_POLICY_BSD

#define STREAM_MAX_PACKET (IP_MAXPACKET - (ETHERNET_HEADER_LEN + IP_HEADER_LEN + TCP_HEADER_LEN))

#ifdef DEBUG_STREAM5
#define STREAM5_DEBUG_WRAP(x) DEBUG_WRAP(x)
#else
#define STREAM5_DEBUG_WRAP(x)
#endif

/* client/server ip/port dereference */
#define tcp_client_ip lwssn->client_ip
#define tcp_client_port lwssn->client_port
#define tcp_server_ip lwssn->server_ip
#define tcp_server_port lwssn->server_port
/*  D A T A  S T R U C T U R E S  ***********************************/
typedef struct _TcpDataBlock
{
    snort_ip        sip;
    snort_ip        dip;
    u_int32_t   seq;
    u_int32_t   ack;
    u_int32_t   win;
    u_int32_t   end_seq;
    u_int32_t   ts;
} TcpDataBlock;

typedef struct _StateMgr
{
    u_int8_t    state;
    u_int8_t    state_queue;
    u_int8_t    expected_flags;
    u_int32_t   transition_seq;
    u_int32_t   stq_get_seq;
} StateMgr;

#define RAND_FLUSH_POINTS 64
#ifndef DYNAMIC_RANDOM_FLUSH_POINTS
typedef struct _FlushPointList
{
    u_int8_t    current;
    u_int8_t    initialized;

    u_int32_t   flush_range;
    u_int32_t   flush_base;  /* Set as value - range/2 */
    /* flush_pt is split evently on either side of flush_value, within
     * the flush_range.  flush_pt can be from:
     * (flush_value - flush_range/2) to (flush_value + flush_range/2)
     *
     * For example:
     * flush_value = 192
     * flush_range = 128
     * flush_pt will vary from 128 to 256
     */
    u_int32_t *flush_points;
} FlushPointList;
#endif

typedef struct _FlushMgr
{
    u_int32_t   flush_pt;
    u_int8_t    flush_policy;
} FlushMgr;

typedef struct _FlushConfig
{
    FlushMgr client;
    FlushMgr server;
    //SF_LIST *dynamic_policy;
#ifdef TARGET_BASED
    u_int8_t configured;
#endif
} FlushConfig;

typedef struct _CustomFlushPolicy
{
    FlushMgr client;
    FlushMgr server;
    IpAddrSet *bound_addrs;
} CustomFlushPolicy;

typedef struct _StreamSegment
{
    struct pcap_pkthdr pkth;

    u_int8_t    *pktOrig;
    u_int8_t    *pkt;
    u_int32_t   cksum;
    u_int32_t   caplen;
    u_int32_t   ts;

    u_int8_t    *data;
    u_int8_t    *payload;
    u_int16_t   size;
    u_int32_t   seq;

    u_int16_t   urg_offset;
    u_int8_t    buffered;
    u_int8_t    blocked;

    struct _StreamSegment *prev;
    struct _StreamSegment *next;
#ifdef DEBUG
    int ordinal;
#endif
} StreamSegment;

typedef struct _Stream5TcpPolicy
{
    u_int16_t   policy;
    u_int16_t   reassembly_policy;
    u_int32_t   session_timeout;
    u_int8_t    min_ttl;
    u_int32_t   max_window;
    u_int32_t   overlap_limit;
    u_int32_t   hs_timeout;
    u_int16_t   flags;
    IpAddrSet   *bound_addrs;
    FlushConfig flush_config[MAX_PORTS];
#ifdef TARGET_BASED
    FlushConfig flush_config_protocol[MAX_PROTOCOL_ORDINAL];
#endif
    FlushPointList flush_point_list;
} Stream5TcpPolicy;

typedef struct _StreamTracker
{
    u_int16_t os_policy;
    u_int16_t reassembly_policy;
    Stream5TcpPolicy *tcp_policy;
    u_int8_t  mac_addr[6];

    u_int8_t  flags;        /* bitmap flags (TF_xxx) */
    StateMgr  s_mgr;        /* state tracking goodies */
    FlushMgr  flush_mgr;    /* please flush twice, it's a long way to
                             * the bitbucket... */

    u_int32_t isn;          /* initial sequence number */
    u_int8_t  ttl;          /* base ttl at session startup */

    u_int32_t ts_last_pkt;  /* last packet timestamp we got */

    /* tcp option handling */
    u_int32_t ts_last;      /* last timestamp (for PAWS) */
    u_int16_t wscale;       /* window scale setting */
    u_int16_t mss;          /* max segment size */

    /* Local in the context of these variables means the local part
     * of the connection.  For example, if this particular StreamTracker
     * was tracking the client side of a connection, the l_unackd value
     * would represent the client side of the connection's last unacked
     * sequence number
     */
    u_int32_t l_unackd;     /* local unack'd seq number */
    u_int32_t l_nxt_seq;    /* local next expected sequence */
    u_int32_t l_window;     /* local receive window */

    u_int32_t r_nxt_ack;    /* next expected ack from remote side */
    u_int32_t r_win_base;   /* remote side window base sequence number
                             * (i.e. the last ack we got)
                             */

    u_int32_t gap_seq;      /* sequence of next packet after a gap */

    StreamSegment *seglist;       /* first queued segment */
    StreamSegment *seglist_tail;  /* last queued segment */
    u_int32_t seglist_base_seq;   /* seq of first queued segment */
    u_int32_t seg_count;          /* number of current queued segments */
    u_int32_t seg_bytes_total;    /* total bytes currently queued */
    u_int32_t seg_bytes_logical;  /* logical bytes queued (total - overlaps) */
    u_int32_t total_bytes_queued; /* total bytes queued (life of session) */
    u_int32_t total_segs_queued;  /* number of segments queued (life) */
    u_int32_t overlap_count;      /* overlaps encountered */

    Stream5AlertInfo alerts[MAX_SESSION_ALERTS]; /* history of alerts */
    int alert_count;              /* number alerts stored */
#ifdef DEBUG
    int segment_ordinal;
#endif
} StreamTracker;

typedef struct _TcpSession
{
    Stream5LWSession *lwssn;
    StreamTracker client;
    StreamTracker server;

#ifdef DEBUG
    struct timeval ssn_time;
#endif

    //u_int8_t    c_ttl;
    //u_int8_t    s_ttl;
} TcpSession;

int default_ports[] =
{
    21, 23, 25, 42, 53, 80, 110, 111, 135, 136, 137, 139, 143, 445,
    513, 514, 1433, 1521, 2401, 3306
};
static FlushConfig ignore_flush_policy[MAX_PORTS];

/*  P R O T O T Y P E S  ********************************************/
static void Stream5ParseTcpArgs(char *, Stream5TcpPolicy *);
static void Stream5PrintTcpConfig(Stream5TcpPolicy *);

static void Stream5InitPacket();
static INLINE void SetupTcpDataBlock(TcpDataBlock *, Packet *);
static int ProcessTcp(Stream5LWSession *, Packet *, TcpDataBlock *,
        Stream5TcpPolicy *);
#if OLD_CODE_NOLONGER_USED_DEPENDS_ON_CURRENT_STATE
static INLINE void QueueState(u_int8_t, StreamTracker*, u_int8_t,
        u_int32_t, u_int8_t);
static INLINE int EvalStateQueue(StreamTracker *, u_int8_t, u_int32_t);
#endif
static int CheckFlushPolicy(TcpSession *, StreamTracker *, StreamTracker *,
                TcpDataBlock *, Packet *);
static void Stream5SeglistAddNode(StreamTracker *, StreamSegment *,
                StreamSegment *);
static int Stream5SeglistDeleteNode(StreamTracker *, StreamSegment *);
static int AddStreamNode(StreamTracker *st, Packet *p,
                  u_int32_t ts,
                  TcpSession *tcpssn,
                  int16_t len,
                  u_int32_t slide,
                  u_int32_t trunc,
                  u_int32_t seq,
                  StreamSegment *left,
                  StreamSegment **retSeg);

static u_int32_t Stream5GetWscale(Packet *, u_int16_t *);
static u_int32_t Stream5PacketHasWscale(Packet *);
static u_int32_t Stream5GetMss(Packet *, u_int16_t *);
static u_int32_t Stream5GetTcpTimestamp(Packet *, u_int32_t *);
static int FlushStream(StreamTracker *st, /* Packet *p, */ u_int8_t *flushbuf, 
        int size);
void TcpSessionCleanup(Stream5LWSession *ssn);

int s5TcpStreamSizeInit(char *name, char *parameters, void **dataPtr);
int s5TcpStreamSizeEval(void *p, const u_int8_t **cursor, void *dataPtr);
void s5TcpStreamSizeCleanup(void *dataPtr);
static INLINE void ResetFlushMgrs(void);
/*  G L O B A L S  **************************************************/
static Stream5SessionCache *tcp_lws_cache;
static MemPool tcp_session_mempool;
#ifdef SUP_IP6
static Packet *s5_pkt_6 = NULL;
#endif
static Packet *s5_pkt = NULL;
static Stream5TcpPolicy **tcpPolicyList = NULL; /* List of Policies configured */
static u_int8_t numTcpPolicies = 0;
static char midstream_allowed = 0;

/* enum for policy names */
static char *reassembly_policy_names[] = {
    "no policy!",
    "FIRST",
    "LINUX",
    "BSD",
    "OLD LINUX",
    "LAST",
    "WINDOWS",
    "SOLARIS",
    "HPUX11",
    "IRIX",
    "MACOS",
    "HPUX10",
    "WINDOWS VISTA",
    "WINDOWS 2003"
};

#ifdef DEBUG_STREAM5
static char *state_names[] = { 
    "NONE",
    "LISTEN",
    "SYN_RCVD",
    "SYN_SENT",
    "ESTABLISHED",
    "CLOSE_WAIT",
    "LAST_ACK",
    "FIN_WAIT_1",
    "CLOSING",
    "FIN_WAIT_2",
    "TIME_WAIT",
    "CLOSED"
};
#endif

static char *flush_policy_names[] = {
    "None",
    "Footprint",
    "Logical",
    "Response",
    "Sliding Window",
    "Consumed",
    "Ignore"};

static int s5_tcp_cleanup = 0;

/*  F U N C T I O N S  **********************************************/
static u_int32_t g_static_points[RAND_FLUSH_POINTS] =
                         { 128, 217, 189, 130, 240, 221, 134, 129,
                           250, 232, 141, 131, 144, 177, 201, 130,
                           230, 190, 177, 142, 130, 200, 173, 129,
                           250, 244, 174, 151, 201, 190, 180, 198,
                           220, 201, 142, 185, 219, 129, 194, 140,
                           145, 191, 197, 183, 199, 220, 231, 245,
                           233, 135, 143, 158, 174, 194, 200, 180,
                           201, 142, 153, 187, 173, 199, 143, 201 };

static INLINE u_int32_t GenerateFlushPoint(FlushPointList *flush_point_list)
{
    return (rand() % flush_point_list->flush_range) + flush_point_list->flush_base;
}

static INLINE void InitFlushPointList(FlushPointList *flush_point_list, u_int32_t value, u_int32_t range, char use_static)
{
    u_int32_t i;
    u_int32_t flush_range = range;
    u_int32_t flush_base = value - range/2;

    if (!flush_point_list)
        return;

    if (!flush_point_list->initialized)
    {
        flush_point_list->flush_range = flush_range;
        flush_point_list->flush_base = flush_base;
#ifndef DYNAMIC_RANDOM_FLUSH_POINTS
        flush_point_list->current = 0;

        flush_point_list->flush_points = SnortAlloc(sizeof(u_int32_t) * RAND_FLUSH_POINTS);
        for (i=0;i<RAND_FLUSH_POINTS;i++)
        {
            if (use_static)
            {
                flush_point_list->flush_points[i] = g_static_points[i];
            }
            else
            {
                flush_point_list->flush_points[i] = GenerateFlushPoint(flush_point_list);
            }
        }
#endif
        flush_point_list->initialized = 1;
    }
}

static INLINE void UpdateFlushMgr(FlushMgr *mgr, FlushPointList *flush_point_list)
{
    switch (mgr->flush_policy)
    {
        case STREAM_FLPOLICY_FOOTPRINT:
        case STREAM_FLPOLICY_LOGICAL:
            /* Ideally, we would call rand() each time, but that
             * is a performance headache waiting to happen. */
#ifdef DYNAMIC_RANDOM_FLUSH_POINTS
            mgr->flush_pt = GenerateFlushPoint();
#else
            if (flush_point_list)
            {
                /* Handle case where it wasn't initialized... */
                if (flush_point_list->initialized == 0)
                {
                    InitFlushPointList(flush_point_list, 192, 128, 0);
                }
                mgr->flush_pt = flush_point_list->flush_points[flush_point_list->current];
                flush_point_list->current = (flush_point_list->current+1) % RAND_FLUSH_POINTS;
            }
#endif
        default:
            break;
    }
}

static INLINE void InitFlushMgr(FlushMgr *mgr, FlushPointList *flush_point_list, u_int8_t policy)
{
    mgr->flush_policy = policy;
    if ((policy == STREAM_FLPOLICY_FOOTPRINT) ||
        (policy == STREAM_FLPOLICY_LOGICAL))
    {
        UpdateFlushMgr(mgr, flush_point_list);
    }
}

static INLINE void ResetFlushMgrs(void)
{
    int i, j;
    u_int8_t flush_policy;
    Stream5TcpPolicy *policy;
    FlushPointList *fpl;
    FlushMgr *client, *server;

    for (i = 0; i < numTcpPolicies; i++)
    {
        policy = tcpPolicyList[i];
        fpl = &policy->flush_point_list;
        fpl->current = 0;

        for (j = 0; j < MAX_PORTS; j++)
        {
            client = &policy->flush_config[j].client;
            flush_policy = policy->flush_config[j].client.flush_policy;
            InitFlushMgr(client, fpl, flush_policy);

            server = &policy->flush_config[j].server;
            flush_policy = policy->flush_config[j].server.flush_policy;
            InitFlushMgr(server, fpl, flush_policy);
        }
#ifdef TARGET_BASED
        for (j = 0; j < MAX_PROTOCOL_ORDINAL; j++)
        {
            client = &policy->flush_config_protocol[j].client;
            flush_policy = policy->flush_config_protocol[j].client.flush_policy;
            InitFlushMgr(client, fpl, flush_policy);

            server = &policy->flush_config_protocol[j].server;
            flush_policy = policy->flush_config_protocol[j].server.flush_policy;
            InitFlushMgr(server, fpl, flush_policy);
        }
#endif
    }
}

void Stream5UpdatePerfBaseState(SFBASE *sfBase,
                                Stream5LWSession *lwssn,
                                char newState)
{
    if (!lwssn)
    {
        return;
    }

    switch (newState)
    {
    case TCP_STATE_SYN_SENT:
        if (!(lwssn->session_flags & SSNFLAG_COUNTED_INITIALIZE))
        {
            sfBase->iSessionsInitializing++;
            lwssn->session_flags |= SSNFLAG_COUNTED_INITIALIZE;
        }
        break;
    case TCP_STATE_ESTABLISHED:
        if (!(lwssn->session_flags & SSNFLAG_COUNTED_ESTABLISH))
        {
            sfBase->iSessionsEstablished++;
            lwssn->session_flags |= SSNFLAG_COUNTED_ESTABLISH;
            if (lwssn->session_flags & SSNFLAG_COUNTED_INITIALIZE)
            {
                sfBase->iSessionsInitializing--;
            }
        }
        break;
    case TCP_STATE_CLOSING:
        if (!(lwssn->session_flags & SSNFLAG_COUNTED_CLOSING))
        {
            sfBase->iSessionsClosing++;
            lwssn->session_flags |= SSNFLAG_COUNTED_CLOSING;
            if (lwssn->session_flags & SSNFLAG_COUNTED_ESTABLISH)
            {
                sfBase->iSessionsEstablished--;
            }
            else if (lwssn->session_flags & SSNFLAG_COUNTED_INITIALIZE)
            {
                sfBase->iSessionsInitializing--;
            }
        }
        break;
    case TCP_STATE_CLOSED:
        if (lwssn->session_flags & SSNFLAG_COUNTED_CLOSING)
        {
            sfBase->iSessionsClosing--;
        }
        else if (lwssn->session_flags & SSNFLAG_COUNTED_ESTABLISH)
        {
            sfBase->iSessionsEstablished--;
        }
        else if (lwssn->session_flags & SSNFLAG_COUNTED_INITIALIZE)
        {
            sfBase->iSessionsInitializing--;
        }
        break;
    default:
        break;
    }
}

void Stream5InitTcp()
{
    int i;

    if((tcp_lws_cache == NULL) && s5_global_config.track_tcp_sessions)
    {
        tcp_lws_cache = InitLWSessionCache(s5_global_config.max_tcp_sessions,
                30, 5, 0, &TcpSessionCleanup);

        if(!tcp_lws_cache)
        {
            FatalError("Unable to init stream5 TCP session cache, no TCP "
                       "stream inspection!\n");
        }

        mempool_init(&tcp_session_mempool, s5_global_config.max_tcp_sessions, sizeof(TcpSession));
    }

    /* Default is to ignore, for all ports */
    for(i=0;i<MAX_PORTS;i++)
    {
        ignore_flush_policy[i].client.flush_policy = STREAM_FLPOLICY_IGNORE;
        ignore_flush_policy[i].server.flush_policy = STREAM_FLPOLICY_IGNORE;
    }

    /* Seed the flushpoint random generator */
    srand( (unsigned int) sizeof(default_ports) + (unsigned int) time(NULL) );

#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("s5TcpNewSess", &s5TcpNewSessPerfStats, 2, &s5TcpPerfStats);
    RegisterPreprocessorProfile("s5TcpState", &s5TcpStatePerfStats, 2, &s5TcpPerfStats);
    RegisterPreprocessorProfile("s5TcpData", &s5TcpDataPerfStats, 3, &s5TcpStatePerfStats);
    RegisterPreprocessorProfile("s5TcpPktInsert", &s5TcpInsertPerfStats, 4, &s5TcpDataPerfStats);
    RegisterPreprocessorProfile("s5TcpFlush", &s5TcpFlushPerfStats, 3, &s5TcpStatePerfStats);
    RegisterPreprocessorProfile("s5TcpBuildPacket", &s5TcpBuildPacketPerfStats, 4, &s5TcpFlushPerfStats);
    RegisterPreprocessorProfile("s5TcpProcessRebuilt", &s5TcpProcessRebuiltPerfStats, 4, &s5TcpFlushPerfStats);
#endif

#ifdef DYNAMIC_PLUGIN
    /* Register the 'stream_size' rule option */
    RegisterPreprocessorRuleOption("stream_size", &s5TcpStreamSizeInit, &s5TcpStreamSizeEval, &s5TcpStreamSizeCleanup);
#endif
       
    return;
}

void Stream5TcpPolicyInit(char *args)
{
    Stream5TcpPolicy *s5TcpPolicy;
    s5TcpPolicy = (Stream5TcpPolicy *) SnortAlloc(sizeof(Stream5TcpPolicy));
    //s5TcpPolicy->bound_addrs = (IpAddrSet *) SnortAlloc(sizeof(IpAddrSet));

    /* Initialize flush policy to Ignore */
    memcpy(&s5TcpPolicy->flush_config, ignore_flush_policy,
            sizeof(FlushConfig) * MAX_PORTS);

    Stream5ParseTcpArgs(args, s5TcpPolicy);

    /* Now add this context to the internal list */
    if (tcpPolicyList == NULL)
    {
        numTcpPolicies = 1;
        tcpPolicyList = (Stream5TcpPolicy **)SnortAlloc(sizeof (Stream5TcpPolicy *)
            * numTcpPolicies);
    }
    else
    {
        Stream5TcpPolicy **tmpPolicyList =
            (Stream5TcpPolicy **)SnortAlloc(sizeof (Stream5TcpPolicy *)
            * (++numTcpPolicies));
        memcpy(tmpPolicyList, tcpPolicyList,
            sizeof(Stream5TcpPolicy *) * (numTcpPolicies-1));
        free(tcpPolicyList);
        
        tcpPolicyList = tmpPolicyList;
    }
    tcpPolicyList[numTcpPolicies-1] = s5TcpPolicy;

    Stream5PrintTcpConfig(s5TcpPolicy);

    return;
}

static INLINE u_int16_t StreamPolicyIdFromName(char *name)
{
    if (!name)
    {
        return STREAM_POLICY_DEFAULT;
    }

    if(!strcasecmp(name, "bsd"))
    {
        return STREAM_POLICY_BSD;
    }
    else if(!strcasecmp(name, "old-linux"))
    {
        return STREAM_POLICY_OLD_LINUX;
    }
    else if(!strcasecmp(name, "linux"))
    {
        return STREAM_POLICY_LINUX;
    }
    else if(!strcasecmp(name, "first"))
    {
        return STREAM_POLICY_FIRST;
    }
    else if(!strcasecmp(name, "last"))
    {
        return STREAM_POLICY_LAST;
    }
    else if(!strcasecmp(name, "windows"))
    {
        return STREAM_POLICY_WINDOWS;
    }
    else if(!strcasecmp(name, "solaris"))
    {
        return STREAM_POLICY_SOLARIS;
    }
    else if(!strcasecmp(name, "win2003") ||
            !strcasecmp(name, "win2k3"))
    {
        return STREAM_POLICY_WINDOWS2K3;
    }
    else if(!strcasecmp(name, "vista"))
    {
        return STREAM_POLICY_VISTA;
    }
    else if(!strcasecmp(name, "hpux") ||
            !strcasecmp(name, "hpux11"))
    {
        return STREAM_POLICY_HPUX11;
    }
    else if(!strcasecmp(name, "hpux10"))
    {
        return STREAM_POLICY_HPUX10;
    }
    else if(!strcasecmp(name, "irix"))
    {
        return STREAM_POLICY_IRIX;
    }
    else if(!strcasecmp(name, "macos") ||
            !strcasecmp(name, "grannysmith"))
    {
        return STREAM_POLICY_MACOS;
    }

    return STREAM_POLICY_DEFAULT; /* BSD is the default */
}

static INLINE u_int16_t GetTcpReassemblyPolicy(int os_policy)
{
    switch (os_policy)
    {
        case STREAM_POLICY_FIRST:
            return REASSEMBLY_POLICY_FIRST;
            break;
        case STREAM_POLICY_LINUX:
            return REASSEMBLY_POLICY_LINUX;
            break;
        case STREAM_POLICY_BSD:
            return REASSEMBLY_POLICY_BSD;
            break;
        case STREAM_POLICY_OLD_LINUX:
            return REASSEMBLY_POLICY_OLD_LINUX;
            break;
        case STREAM_POLICY_LAST:
            return REASSEMBLY_POLICY_LAST;
            break;
        case STREAM_POLICY_WINDOWS:
            return REASSEMBLY_POLICY_WINDOWS;
            break;
        case STREAM_POLICY_SOLARIS:
            return REASSEMBLY_POLICY_SOLARIS;
            break;
        case STREAM_POLICY_WINDOWS2K3:
            return REASSEMBLY_POLICY_WINDOWS2K3;
            break;
        case STREAM_POLICY_VISTA:
            return REASSEMBLY_POLICY_VISTA;
            break;
        case STREAM_POLICY_HPUX11:
            return REASSEMBLY_POLICY_HPUX11;
            break;
        case STREAM_POLICY_HPUX10:
            return REASSEMBLY_POLICY_HPUX10;
            break;
        case STREAM_POLICY_IRIX:
            return REASSEMBLY_POLICY_IRIX;
            break;
        case STREAM_POLICY_MACOS:
            return REASSEMBLY_POLICY_MACOS;
            break;
        default:
            return REASSEMBLY_POLICY_DEFAULT;
            break;
    }
}

static void Stream5ParseTcpArgs(char *args, Stream5TcpPolicy *s5TcpPolicy)
{
    char **toks;
    int num_toks;
    int i;
    char *index;
    char **stoks = NULL;
    int s_toks;
    char *endPtr = NULL;
    char use_static = 0;
    char set_flush_policy = 0;
    int reassembly_direction = SSN_DIR_CLIENT;
    int32_t long_val = 0;

    s5TcpPolicy->policy = STREAM_POLICY_DEFAULT;
    s5TcpPolicy->reassembly_policy = REASSEMBLY_POLICY_DEFAULT;
    s5TcpPolicy->session_timeout = S5_DEFAULT_SSN_TIMEOUT;
    //s5TcpPolicy->ttl_delta_limit = S5_DEFAULT_TTL_LIMIT;
    s5TcpPolicy->min_ttl = S5_DEFAULT_MIN_TTL;
    s5TcpPolicy->max_window = 0;
    s5TcpPolicy->flags = 0;
    //s5TcpPolicy->flags |=  STREAM5_CONFIG_STATEFUL_INSPECTION;
    //s5TcpPolicy->flags |=  STREAM5_CONFIG_ENABLE_ALERTS;
    //s5TcpPolicy->flags |=  STREAM5_CONFIG_REASS_CLIENT;

    if(args != NULL && strlen(args) != 0)
    {
        toks = mSplit(args, ",", 13, &num_toks, 0);

        i=0;

        while(i < num_toks)
        {
            index = toks[i];

            while(isspace((int)*index)) index++;

            stoks = mSplit(index, " ", 3, &s_toks, 0);

            if (s_toks == 0)
            {
                FatalError("%s(%d) => Missing parameter in Stream5 TCP config.\n",
                    file_name, file_line);
            }

            if(!strcasecmp(stoks[0], "timeout"))
            {
                if(stoks[1])
                {
                    s5TcpPolicy->session_timeout = strtoul(stoks[1], &endPtr, 10);
                }
                
                if (!stoks[1] || (endPtr == &stoks[1][0]))
                {
                    FatalError("%s(%d) => Invalid timeout in config file.  "
                        "Integer parameter required.\n",
                        file_name, file_line);
                }

                if ((s5TcpPolicy->session_timeout > S5_MAX_SSN_TIMEOUT) ||
                    (s5TcpPolicy->session_timeout < S5_MIN_SSN_TIMEOUT))
                {
                    FatalError("%s(%d) => Invalid timeout in config file.  "
                        "Must be between %d and %d\n",
                        file_name, file_line,
                        S5_MIN_SSN_TIMEOUT, S5_MAX_SSN_TIMEOUT);
                }
                if (s_toks > 2)
                {
                    FatalError("%s(%d) => Invalid Stream5 TCP Policy option.  Missing comma?\n",
                        file_name, file_line);
                }
            }
#if 0
            else if(!strcasecmp(stoks[0], "ttl_limit"))
            {
                if(stoks[1])
                {
                    s5TcpPolicy->ttl_delta_limit = strtoul(stoks[1], &endPtr, 10);
                }
                
                if (!stoks[1] || (endPtr == &stoks[1][0]))
                {
                    FatalError("%s(%d) => Invalid TTL Limit in config file.  Integer parameter required\n",
                            file_name, file_line);
                }
            }
#endif
            else if(!strcasecmp(stoks[0], "min_ttl"))
            {
                if(stoks[1])
                {
                    long_val = strtol(stoks[1], &endPtr, 10);
                    if (errno == ERANGE)
                    {
                        errno = 0;
                        long_val = -1;
                    }
                    s5TcpPolicy->min_ttl = (u_int8_t)long_val;
                }

                if (!stoks[1] || (endPtr == &stoks[1][0]))
                {
                    FatalError("%s(%d) => Invalid min TTL in config file.  Integer parameter required\n",
                            file_name, file_line);
                }

                if ((long_val > S5_MAX_MIN_TTL) ||
                    (long_val < S5_MIN_MIN_TTL))
                {
                    FatalError("%s(%d) => Invalid min TTL in config file.  "
                        "Must be between %d and %d\n",
                        file_name, file_line,
                        S5_MIN_MIN_TTL, S5_MAX_MIN_TTL);
                }
                if (s_toks > 2)
                {
                    FatalError("%s(%d) => Invalid Stream5 TCP Policy option.  Missing comma?\n",
                        file_name, file_line);
                }
            }
            else if(!strcasecmp(stoks[0], "overlap_limit"))
            {
                if(stoks[1])
                {
                    long_val = strtol(stoks[1], &endPtr, 10);
                    if (errno == ERANGE)
                    {
                        errno = 0;
                        long_val = -1;
                    }
                    s5TcpPolicy->overlap_limit = (u_int8_t)long_val;
                }

                if (!stoks[1] || (endPtr == &stoks[1][0]))
                {
                    FatalError("%s(%d) => Invalid overlap limit in config file."
                            "Integer parameter required\n",
                            file_name, file_line);
                }

                if ((long_val > S5_MAX_OVERLAP_LIMIT) ||
                    (long_val < S5_MIN_OVERLAP_LIMIT))
                {
                    FatalError("%s(%d) => Invalid overlap limit in config file."
                        "  Must be between %d and %d\n",
                        file_name, file_line,
                        S5_MIN_OVERLAP_LIMIT, S5_MAX_OVERLAP_LIMIT);
                }
                if (s_toks > 2)
                {
                    FatalError("%s(%d) => Invalid Stream5 TCP Policy option.  Missing comma?\n",
                        file_name, file_line);
                }
            }
            else if(!strcasecmp(stoks[0], "detect_anomalies"))
            {
                s5TcpPolicy->flags |=  STREAM5_CONFIG_ENABLE_ALERTS;
                if (s_toks > 1)
                {
                    FatalError("%s(%d) => Invalid Stream5 TCP Policy option.  Missing comma?\n",
                        file_name, file_line);
                }
            }
            else if(!strcasecmp(stoks[0], "policy"))
            {
                s5TcpPolicy->policy = StreamPolicyIdFromName(stoks[1]);

                if ((s5TcpPolicy->policy == STREAM_POLICY_DEFAULT) &&
                    (strcasecmp(stoks[1], "bsd")))
                {
                    /* Default is BSD.  If we don't have "bsd", its
                     * the default and invalid.
                     */
                    FatalError("%s(%d) => Bad policy name \"%s\"\n",
                            file_name, file_line, stoks[1]);
                }

                s5TcpPolicy->reassembly_policy = GetTcpReassemblyPolicy(s5TcpPolicy->policy);
                if (s_toks > 2)
                {
                    FatalError("%s(%d) => Invalid Stream5 TCP Policy option.  Missing comma?\n",
                        file_name, file_line);
                }
            }
            else if(!strcasecmp(stoks[0], "require_3whs"))
            {
                s5TcpPolicy->flags |= STREAM5_CONFIG_REQUIRE_3WHS;

                if (s_toks > 1)
                {
                    s5TcpPolicy->hs_timeout = strtoul(stoks[1], &endPtr, 10);
                }

                if ((s_toks > 1) && (endPtr == &stoks[1][0]))
                {
                    FatalError("%s(%d) => Invalid 3Way Handshake allowable.  Integer parameter required.\n",
                            file_name, file_line);
                }

                if (s_toks > 1)
                {
                    if ((s5TcpPolicy->hs_timeout > S5_MAX_SSN_TIMEOUT) ||
                        (s5TcpPolicy->hs_timeout < S5_MIN_ALT_HS_TIMEOUT))
                    {
                        FatalError("%s(%d) => Invalid handshake timeout in "
                            "config file.  Must be between %d and %d\n",
                            file_name, file_line,
                            S5_MIN_ALT_HS_TIMEOUT, S5_MAX_SSN_TIMEOUT);
                    }
                }
                if (s_toks > 2)
                {
                    FatalError("%s(%d) => Invalid Stream5 TCP Policy option.  Missing comma?\n",
                        file_name, file_line);
                }
            }
            else if(!strcasecmp(stoks[0], "bind_to"))
            {
                if(strstr(stoks[1], "["))
                {
                    FatalError("%s(%d) => Invalid Stream5 TCP Policy option.  IP lists are not allowed.\n",
                        file_name, file_line);
                }

                s5TcpPolicy->bound_addrs = IpAddrSetParse(stoks[1]);

                if (s_toks > 2)
                {
                    FatalError("%s(%d) => Invalid Stream5 TCP Policy option.  Missing comma?\n",
                        file_name, file_line);
                }
            }
            else if(!strcasecmp(stoks[0], "max_window"))
            {
                if(stoks[1])
                {
                    long_val = strtol(stoks[1], &endPtr, 10);
                    if (errno == ERANGE)
                    {
                        errno = 0;
                        FatalError("%s(%d) => Invalid Max Window size.  Integer parameter required.\n",
                            file_name, file_line);
                    }
                    s5TcpPolicy->max_window = (u_int32_t)long_val;
                }
                
                if (!stoks[1] || (endPtr == &stoks[1][0]))
                {
                    FatalError("%s(%d) => Invalid Max Window size.  Integer parameter required.\n",
                            file_name, file_line);
                }

                if (s_toks > 2)
                {
                    FatalError("%s(%d) => Invalid Stream5 TCP Policy option.  Missing comma?\n",
                        file_name, file_line);
                }
                if ((long_val > S5_MAX_MAX_WINDOW) ||
                    (long_val < S5_MIN_MAX_WINDOW))
                {
                    FatalError("%s(%d) => Invalid Max Window size."
                        "  Must be between %d and %d\n",
                        file_name, file_line,
                        S5_MIN_MAX_WINDOW, S5_MAX_MAX_WINDOW);
                }
            }
            else if(!strcasecmp(stoks[0], "use_static_footprint_sizes"))
            {
                s5TcpPolicy->flags |= STREAM5_CONFIG_STATIC_FLUSHPOINTS;
                use_static = 1;
                InitFlushPointList(&s5TcpPolicy->flush_point_list, 192, 128, use_static);
                if (s_toks > 1)
                {
                    FatalError("%s(%d) => Invalid Stream5 TCP Policy option.  Missing comma?\n",
                        file_name, file_line);
                }
            }
            else if(!strcasecmp(stoks[0], "dont_store_large_packets"))
            {
                s5TcpPolicy->flags |= STREAM5_CONFIG_PERFORMANCE;
                if (s_toks > 1)
                {
                    FatalError("%s(%d) => Invalid Stream5 TCP Policy option.  Missing comma?\n",
                        file_name, file_line);
                }
            }
            else if(!strcasecmp(stoks[0], "check_session_hijacking"))
            {
                s5TcpPolicy->flags |= STREAM5_CONFIG_CHECK_SESSION_HIJACKING;
                if (s_toks > 1)
                {
                    FatalError("%s(%d) => Invalid Stream5 TCP Policy option.  Missing comma?\n",
                        file_name, file_line);
                }
            }
            else if (!strcasecmp(stoks[0], "ports"))
            {
                if (s_toks > 1)
                {
                    if(!strcasecmp(stoks[1], "client"))
                    {
                        reassembly_direction = SSN_DIR_CLIENT;
                    }
                    else if(!strcasecmp(stoks[1], "server"))
                    {
                        reassembly_direction = SSN_DIR_SERVER;
                    }
                    else
                    {
                        reassembly_direction = SSN_DIR_BOTH;
                    }
                }

                if (s_toks > 2)
                {
                    char **ptoks;
                    int num_ptoks;
                    int j;
                    unsigned short port = 0;
                    long long_port = 0;

                    /* Initialize it if not already... */
                    InitFlushPointList(&s5TcpPolicy->flush_point_list, 192, 128, use_static);

                    if (!strcasecmp(stoks[2], "all"))
                    {
                        for (j=0; j<MAX_PORTS; j++)
                        {
                            if (reassembly_direction & SSN_DIR_CLIENT)
                            {
                                FlushMgr *flush_mgr = &s5TcpPolicy->flush_config[j].client;
                                FlushPointList *flush_point_list = &s5TcpPolicy->flush_point_list;
                                InitFlushMgr(flush_mgr, flush_point_list, STREAM_FLPOLICY_FOOTPRINT);
                            }
                            if (reassembly_direction & SSN_DIR_SERVER)
                            {
                                FlushMgr *flush_mgr = &s5TcpPolicy->flush_config[j].server;
                                FlushPointList *flush_point_list = &s5TcpPolicy->flush_point_list;
                                InitFlushMgr(flush_mgr, flush_point_list, STREAM_FLPOLICY_FOOTPRINT);
                            }
                        }
                    }
                    else if (!strcasecmp(stoks[2], "none"))
                    {
                        for (j=0; j<MAX_PORTS; j++)
                        {
                            if (reassembly_direction & SSN_DIR_CLIENT)
                            {
                                FlushMgr *flush_mgr = &s5TcpPolicy->flush_config[j].client;
                                flush_mgr->flush_policy = STREAM_FLPOLICY_IGNORE;
                            }
                            if (reassembly_direction & SSN_DIR_SERVER)
                            {
                                FlushMgr *flush_mgr = &s5TcpPolicy->flush_config[j].server;
                                flush_mgr->flush_policy = STREAM_FLPOLICY_IGNORE;
                            }
                        }
                    }
                    else
                    {
                        ptoks = mSplit(stoks[2], " ", MAX_PORTS, &num_ptoks, 0);

                        for (j=0;j<num_ptoks;j++)
                        {
                            if (ptoks[j])
                            {
                                long_port = strtol(ptoks[j], &endPtr, 10);
                            }
                            if (!ptoks[j] || (endPtr == &ptoks[j][0]))
                            {
                                FatalError("%s(%d) => Invalid Port list.  Integer parameter required.\n",
                                    file_name, file_line);
                            }

                            if ((long_port < 0) || (long_port > MAX_PORTS-1))
                            {
                                FatalError("%s(%d) => Invalid port %d, must be between 0 and %d, inclusive\n", 
                                    file_name, file_line, long_port, MAX_PORTS-1);
                            }
                            port = (unsigned short)long_port;

                            if (reassembly_direction & SSN_DIR_CLIENT)
                            {
                                FlushMgr *flush_mgr = &s5TcpPolicy->flush_config[port].client;
                                FlushPointList *flush_point_list = &s5TcpPolicy->flush_point_list;
                                InitFlushMgr(flush_mgr, flush_point_list, STREAM_FLPOLICY_FOOTPRINT);
                            }
                            if (reassembly_direction & SSN_DIR_SERVER)
                            {
                                FlushMgr *flush_mgr = &s5TcpPolicy->flush_config[port].server;
                                FlushPointList *flush_point_list = &s5TcpPolicy->flush_point_list;
                                InitFlushMgr(flush_mgr, flush_point_list, STREAM_FLPOLICY_FOOTPRINT);
                            }
                        }
                        mSplitFree(&ptoks, num_ptoks);
                    }
                    set_flush_policy = 1;
                }
            }
#ifdef TARGET_BASED
            else if (!strcasecmp(stoks[0], "protocol"))
            {
                if (s_toks > 1)
                {
                    if(!strcasecmp(stoks[1], "client"))
                    {
                        reassembly_direction = SSN_DIR_CLIENT;
                    }
                    else if(!strcasecmp(stoks[1], "server"))
                    {
                        reassembly_direction = SSN_DIR_SERVER;
                    }
                    else
                    {
                        reassembly_direction = SSN_DIR_BOTH;
                    }
                }

                if (s_toks > 2)
                {
                    char **ptoks;
                    int num_ptoks;
                    int j;

                    /* Initialize it if not already... */
                    InitFlushPointList(&s5TcpPolicy->flush_point_list, 192, 128, use_static);

                    if (!strcasecmp(stoks[2], "all"))
                    {
                        for (j=0; j<MAX_PROTOCOL_ORDINAL; j++)
                        {
                            if (reassembly_direction & SSN_DIR_CLIENT)
                            {
                                FlushMgr *flush_mgr = &s5TcpPolicy->flush_config_protocol[j].client;
                                FlushPointList *flush_point_list = &s5TcpPolicy->flush_point_list;
                                InitFlushMgr(flush_mgr, flush_point_list, STREAM_FLPOLICY_FOOTPRINT);
                            }
                            if (reassembly_direction & SSN_DIR_SERVER)
                            {
                                FlushMgr *flush_mgr = &s5TcpPolicy->flush_config_protocol[j].server;
                                FlushPointList *flush_point_list = &s5TcpPolicy->flush_point_list;
                                InitFlushMgr(flush_mgr, flush_point_list, STREAM_FLPOLICY_FOOTPRINT);
                            }
                            s5TcpPolicy->flush_config_protocol[j].configured = 1;
                        }
                    }
                    else if (!strcasecmp(stoks[2], "none"))
                    {
                        for (j=0; j<MAX_PROTOCOL_ORDINAL; j++)
                        {
                            if (reassembly_direction & SSN_DIR_CLIENT)
                            {
                                FlushMgr *flush_mgr = &s5TcpPolicy->flush_config_protocol[j].client;
                                flush_mgr->flush_policy = STREAM_FLPOLICY_IGNORE;
                            }
                            if (reassembly_direction & SSN_DIR_SERVER)
                            {
                                FlushMgr *flush_mgr = &s5TcpPolicy->flush_config_protocol[j].server;
                                flush_mgr->flush_policy = STREAM_FLPOLICY_IGNORE;
                            }
                            s5TcpPolicy->flush_config_protocol[j].configured = 1;
                        }
                    }
                    else
                    {
                        ptoks = mSplit(stoks[2], " ", MAX_PROTOCOL_ORDINAL, &num_ptoks, 0);

                        for (j=0;j<num_ptoks;j++)
                        {
                            int16_t proto_ordinal;
                            if (!ptoks[j])
                            {
                                FatalError("%s(%d) => Invalid Protocol Name.  Protocol name must be specified.\n",
                                    file_name, file_line);
                            }
                            /* First look it up */
                            proto_ordinal = FindProtocolReference(ptoks[j]);
                            if (proto_ordinal == SFTARGET_UNKNOWN_PROTOCOL)
                            {
                                /* Not known -- add it */
                                proto_ordinal = AddProtocolReference(ptoks[j]);
                                if (proto_ordinal == SFTARGET_UNKNOWN_PROTOCOL)
                                {
                                    FatalError("%s(%d) => Failed to find protocol reference for '%s'\n", 
                                    file_name, file_line, ptoks[j]);
                                }
                            }

                            if (reassembly_direction & SSN_DIR_CLIENT)
                            {
                                FlushMgr *flush_mgr = &s5TcpPolicy->flush_config_protocol[proto_ordinal].client;
                                FlushPointList *flush_point_list = &s5TcpPolicy->flush_point_list;
                                InitFlushMgr(flush_mgr, flush_point_list, STREAM_FLPOLICY_FOOTPRINT);
                            }
                            if (reassembly_direction & SSN_DIR_SERVER)
                            {
                                FlushMgr *flush_mgr = &s5TcpPolicy->flush_config_protocol[proto_ordinal].server;
                                FlushPointList *flush_point_list = &s5TcpPolicy->flush_point_list;
                                InitFlushMgr(flush_mgr, flush_point_list, STREAM_FLPOLICY_FOOTPRINT);
                            }
                            s5TcpPolicy->flush_config_protocol[proto_ordinal].configured = 1;
                        }
                        mSplitFree(&ptoks, num_ptoks);
                    }
                }
            }
#endif
            else
            {
                FatalError("%s(%d) => Invalid Stream5 TCP policy option\n", 
                            file_name, file_line);
            }

            mSplitFree(&stoks, s_toks);
            i++;
        }

        mSplitFree(&toks, num_toks);
    }

    if(s5TcpPolicy->bound_addrs == NULL)
    {
        /* allocate and initializes the
         * IpAddrSet at the same time
         * set to "any"
         */
        if (s5_global_config.flags & STREAM5_CONFIG_DEFAULT_TCP_POLICY_SET)
        {
            FatalError("%s(%d) => Default Stream5 TCP Policy alread set. "
                "This policy must be bound to a specific host or "
                "network.\n", file_name, file_line);
        }
        s5TcpPolicy->bound_addrs = (IpAddrSet *) SnortAlloc(sizeof(IpAddrSet));
        s5_global_config.flags |= STREAM5_CONFIG_DEFAULT_TCP_POLICY_SET;
    }

    if (!set_flush_policy)
    {
        /* Initialize it if not already... */
        InitFlushPointList(&s5TcpPolicy->flush_point_list, 192, 128, use_static);
        for (i=0;i<sizeof(default_ports)/sizeof(int); i++)
        {
            if (reassembly_direction & SSN_DIR_CLIENT)
            {
                FlushMgr *flush_mgr = &s5TcpPolicy->flush_config[default_ports[i]].client;
                FlushPointList *flush_point_list = &s5TcpPolicy->flush_point_list;
                InitFlushMgr(flush_mgr, flush_point_list, STREAM_FLPOLICY_FOOTPRINT);
            }
            if (reassembly_direction & SSN_DIR_SERVER)
            {
                FlushMgr *flush_mgr = &s5TcpPolicy->flush_config[default_ports[i]].server;
                FlushPointList *flush_point_list = &s5TcpPolicy->flush_point_list;
                InitFlushMgr(flush_mgr, flush_point_list, STREAM_FLPOLICY_FOOTPRINT);
            }
        }
    }

    return;
}

static void Stream5PrintTcpConfig(Stream5TcpPolicy *s5TcpPolicy)
{
    int i=0, j=0;
    LogMessage("Stream5 TCP Policy config:\n");
    LogMessage("    Reassembly Policy: %s\n",
        reassembly_policy_names[s5TcpPolicy->reassembly_policy]);
    LogMessage("    Timeout: %d seconds\n", s5TcpPolicy->session_timeout);
    LogMessage("    Min ttl:  %d\n", s5TcpPolicy->min_ttl);
    //LogMessage("    Stream ttl_limit: %d\n", s5TcpPolicy->ttl_delta_limit);
    if (s5TcpPolicy->max_window != 0)
        LogMessage("    Max TCP Window: %u\n", s5TcpPolicy->max_window);
    if (s5TcpPolicy->overlap_limit)
        LogMessage("    Limit on TCP Overlaps: %d\n", s5TcpPolicy->overlap_limit);
    if (s5TcpPolicy->flags)
    {
        LogMessage("    Options:\n");
        if (s5TcpPolicy->flags & STREAM5_CONFIG_REQUIRE_3WHS)
        {
            LogMessage("        Require 3-Way Handshake: YES\n");
            if (s5TcpPolicy->hs_timeout != 0)
            {
                LogMessage("        3-Way Handshake Timeout: %d\n",
                    s5TcpPolicy->hs_timeout);
            }
        }
        if (s5TcpPolicy->flags & STREAM5_CONFIG_ENABLE_ALERTS)
        {
            LogMessage("        Detect Anomalies: YES\n");
        }
        if (s5TcpPolicy->flags & STREAM5_CONFIG_STATIC_FLUSHPOINTS)
        {
            LogMessage("        Static Flushpoint Sizes: YES\n");
        }
        if (s5TcpPolicy->flags & STREAM5_CONFIG_PERFORMANCE)
        {
            LogMessage("        Don't Queue Large Packets for Reassembly: YES\n");
        }
        if (s5TcpPolicy->flags & STREAM5_CONFIG_CHECK_SESSION_HIJACKING)
        {
            LogMessage("        Check for TCP Session Hijacking: YES\n");
        }
    }
    LogMessage("    Reassembly Ports:\n");
    for (i=0; i<MAX_PORTS && j<20; i++)
    {
        int direction = 0;
        int client_flushpolicy = s5TcpPolicy->flush_config[i].client.flush_policy;
        int server_flushpolicy = s5TcpPolicy->flush_config[i].server.flush_policy;
        char client_policy_str[STD_BUF];
        char server_policy_str[STD_BUF];
        client_policy_str[0] = server_policy_str[0] = '\0';

        if (client_flushpolicy != STREAM_FLPOLICY_IGNORE)
        {
            direction |= SSN_DIR_CLIENT;

            if (client_flushpolicy <= STREAM_FLPOLICY_MAX)
                SnortSnprintf(client_policy_str, STD_BUF, "client (%s)",
                              flush_policy_names[client_flushpolicy]);
        }
        if (server_flushpolicy != STREAM_FLPOLICY_IGNORE)
        {
            direction |= SSN_DIR_SERVER;

            if (server_flushpolicy <= STREAM_FLPOLICY_MAX)
                SnortSnprintf(server_policy_str, STD_BUF, "server (%s)",
                              flush_policy_names[server_flushpolicy]);
        }
        if (direction)
        {
            LogMessage("      %d %s %s\n", i,
                client_policy_str, server_policy_str);
#ifndef DEBUG
            /* Don't increment, so we print the full list in
             * debug mode. */
            j++;
#endif
        }
    }

#ifdef SUP_IP6
// XXX-IPv6 var printing
#else
    IpAddrSetPrint("    Bound Addresses:", s5TcpPolicy->bound_addrs);
#endif

}

#ifdef TARGET_BASED
int StreamPolicyIdFromHostAttributeEntry(HostAttributeEntry *host_entry)
{
    if (!host_entry || !host_entry->hostInfo.streamPolicyName)
        return 0;

    host_entry->hostInfo.streamPolicy = StreamPolicyIdFromName(host_entry->hostInfo.streamPolicyName);
    host_entry->hostInfo.streamPolicySet = 1;

    STREAM5_DEBUG_WRAP(
        DebugMessage(DEBUG_STREAM_STATE,
            "STREAM5 INIT: %s(%d) for Entry %s:%s:%s (%s)\n",
            reassembly_policy_names[host_entry->hostInfo.streamPolicy],
            host_entry->hostInfo.streamPolicy,
            host_entry->hostInfo.operatingSystem.value.s_value,
            host_entry->hostInfo.vendor.value.s_value,
            host_entry->hostInfo.version.value.s_value,
            host_entry->hostInfo.streamPolicyName););
    return 0;
}
#endif

int Stream5VerifyTcpConfig()
{
    if (!tcp_lws_cache)
    {
        LogMessage("WARNING: Stream5 TCP Session Cache not initialized\n");
        return -1;
    }

    if (numTcpPolicies < 1)
    {
        LogMessage("WARNING: Stream5 TCP no policies specified in configuration\n");
        return -1;
    }

    if (!(s5_global_config.flags & STREAM5_CONFIG_DEFAULT_TCP_POLICY_SET))
    {
        LogMessage("WARNING: Stream5 TCP default policy not specified in configuration\n");
        return -1;
    }

    /* Do this now
     * verify config is called after all preprocs (static & dynamic)
     * are inited.  Gives us the correct number of bits for
     * p->preprocessor_bits
     */
    if (!s5_pkt)
        Stream5InitPacket();

#ifdef TARGET_BASED
    SFAT_SetPolicyIds(StreamPolicyIdFromHostAttributeEntry);
#endif

    return 0;
}


void Stream5ResetTcp(void)
{
    DecoderFlags decoder_flags;
    int ret;

    ret = SafeMemcpy(&decoder_flags, &pv.decoder_flags, sizeof(decoder_flags),
                     &decoder_flags,
                     (u_int8_t *)(&decoder_flags) + sizeof(decoder_flags));
    if (ret != SAFEMEM_SUCCESS)
        return;

    memset(&pv.decoder_flags, 0, sizeof(pv.decoder_flags));

    s5_tcp_cleanup = 1;
    PurgeLWSessionCache(tcp_lws_cache);
    s5_tcp_cleanup = 0;
    mempool_clean(&tcp_session_mempool);

    ret = SafeMemcpy(&pv.decoder_flags, &decoder_flags, sizeof(pv.decoder_flags),
                     &pv.decoder_flags,
                     (u_int8_t *)(&pv.decoder_flags) + sizeof(pv.decoder_flags));
    if (ret != SAFEMEM_SUCCESS)
        return;

    ResetFlushMgrs();
}


void Stream5CleanTcp()
{
    DecoderFlags decoder_flags;
    int policyIndex;
    Stream5TcpPolicy *policy = NULL;


    /* Turn off decoder alerts since we're decoding stored
     * packets that we already alerted on.
     */
    memcpy(&decoder_flags, &pv.decoder_flags, sizeof(DecoderFlags));
    memset(&pv.decoder_flags, 0, sizeof(DecoderFlags));

    /* Set s5_tcp_cleanup to force a flush of all queued data */
    s5_tcp_cleanup = 1;
    /* Clean up hash table -- delete all sessions */
    DeleteLWSessionCache(tcp_lws_cache);
    tcp_lws_cache = NULL;

    /* Cleanup the rebuilt packet */
    if (s5_pkt)
    {
        free((void *)s5_pkt->pkth);
        boFreeBITOP(s5_pkt->preprocessor_bits);
        free(s5_pkt->preprocessor_bits);
        boFreeBITOP(s5_pkt->preproc_reassembly_pkt_bits);
        free(s5_pkt->preproc_reassembly_pkt_bits);
        free(s5_pkt);
        s5_pkt = NULL;
    }
#ifdef SUP_IP6
    if (s5_pkt_6)
    {
        free((void *)s5_pkt_6->pkth);
        boFreeBITOP(s5_pkt_6->preprocessor_bits);
        free(s5_pkt_6->preprocessor_bits);
        boFreeBITOP(s5_pkt_6->preproc_reassembly_pkt_bits);
        free(s5_pkt_6->preproc_reassembly_pkt_bits);
        free(s5_pkt_6);
        s5_pkt_6 = NULL;
    }
#endif

    /* Reset this */
    s5_tcp_cleanup = 0;

    mempool_destroy(&tcp_session_mempool);

    /* And turn decoder alerts back on (or whatever they were set to) */
    memcpy(&pv.decoder_flags, &decoder_flags, sizeof(DecoderFlags));

    /* Cleanup TCP Policies and the list */
    for (policyIndex = 0; policyIndex < numTcpPolicies; policyIndex++)
    {
        policy = tcpPolicyList[policyIndex];
        free(policy->flush_point_list.flush_points);
#ifdef SUP_IP6
        sfvar_free(policy->bound_addrs);
#else
        IpAddrSetDestroy(policy->bound_addrs);
        free(policy->bound_addrs);
#endif
        free(policy);
    }
    free(tcpPolicyList);
    tcpPolicyList = NULL;
}

#ifdef DEBUG_STREAM5
static void PrintStateMgr(StateMgr *s)
{
    LogMessage("StateMgr:\n");
    LogMessage("    state:          %s\n", state_names[s->state]);
    LogMessage("    state_queue:    %s\n", state_names[s->state_queue]);
    LogMessage("    expected_flags: 0x%X\n", s->expected_flags);
    LogMessage("    transition_seq: 0x%X\n", s->transition_seq);
    LogMessage("    stq_get_seq:    %d\n", s->stq_get_seq);
}

static void PrintStreamTracker(StreamTracker *s)
{
    LogMessage(" + StreamTracker +\n");
    LogMessage("    isn:                0x%X\n", s->isn);
    LogMessage("    ttl:                %d\n", s->ttl);
    LogMessage("    ts_last:            %lu\n", s->ts_last);
    LogMessage("    wscale:             %lu\n", s->wscale);
    LogMessage("    mss:                0x%08X\n", s->mss);
    LogMessage("    l_unackd:           %X\n", s->l_unackd);
    LogMessage("    l_nxt_seq:          %X\n", s->l_nxt_seq);
    LogMessage("    l_window:           %lu\n", s->l_window);
    LogMessage("    r_nxt_ack:          %X\n", s->r_nxt_ack);
    LogMessage("    r_win_base:         %X\n", s->r_win_base);
    LogMessage("    seglist_base_seq:   %X\n", s->seglist_base_seq);
    LogMessage("    seglist:            %p\n", s->seglist);
    LogMessage("    seglist_tail:       %p\n", s->seglist_tail);
    LogMessage("    seg_count:          %d\n", s->seg_count);
    LogMessage("    seg_bytes_total:    %d\n", s->seg_bytes_total);
    LogMessage("    seg_bytes_logical:  %d\n", s->seg_bytes_logical);

    PrintStateMgr(&s->s_mgr);
}

static void PrintTcpSession(TcpSession *ts)
{
    LogMessage("TcpSession:\n");
#ifdef DEBUG
    LogMessage("    ssn_time:           %lu\n", ts->ssn_time.tv_sec);
#endif
    LogMessage("    server IP:          0x%08X\n", ts->tcp_server_ip);
    LogMessage("    client IP:          0x%08X\n", ts->tcp_client_ip);
    LogMessage("    server port:        %d\n", ts->tcp_server_port);
    LogMessage("    client port:        %d\n", ts->tcp_client_port);

    LogMessage("    flags:              0x%X\n", ts->lwssn->session_flags);

    LogMessage("Client Tracker:\n");
    PrintStreamTracker(&ts->client);
    LogMessage("Server Tracker:\n");
    PrintStreamTracker(&ts->server);
}

static void PrintTcpDataBlock(TcpDataBlock *tdb)
{
    LogMessage("TcpDataBlock:\n");
    LogMessage("    sip:    0x%08X\n", tdb->sip);
    LogMessage("    dip:    0x%08X\n", tdb->dip);
    LogMessage("    seq:    0x%08X\n", tdb->seq);
    LogMessage("    ack:    0x%08X\n", tdb->ack);
    LogMessage("    win:    %d\n", tdb->win);
    LogMessage("    end:    0x%08X\n", tdb->end_seq);
}

static void PrintFlushMgr(FlushMgr *fm)
{
    if(fm == NULL)
        return;

    switch(fm->flush_policy)
    {
        case STREAM_FLPOLICY_NONE: 
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "    NONE\n"););
            break;
        case STREAM_FLPOLICY_FOOTPRINT:
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "    FOOTPRINT %d\n", fm->flush_pt););
            break;
        case STREAM_FLPOLICY_LOGICAL:
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "    LOGICAL %d\n", fm->flush_pt););
            break;
        case STREAM_FLPOLICY_RESPONSE:
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "    RESPONSE\n"););
            break;
        case STREAM_FLPOLICY_SLIDING_WINDOW:
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "    SLIDING_WINDOW %d\n", fm->flush_pt););
            break;
#if 0
        case STREAM_FLPOLICY_CONSUMED:
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "          CONSUMED %d\n", fm->flush_pt););
            break;
#endif
        case STREAM_FLPOLICY_IGNORE:
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "    IGNORE\n"););
            break;
    }
}
#endif

static INLINE void EventSynOnEst(Stream5TcpPolicy *s5TcpPolicy)
{
    if(!(s5TcpPolicy->flags & STREAM5_CONFIG_ENABLE_ALERTS))
        return;

    s5stats.events++;

    SnortEventqAdd(GENERATOR_SPP_STREAM5,       /* GID */
            STREAM5_SYN_ON_EST,                 /* SID */
            1,                                  /* rev */
            0,                                  /* class */
            3,                                  /* priority */
            STREAM5_SYN_ON_EST_STR,             /* event msg */
            NULL);                              /* rule info ptr */
}

static INLINE void EventExcessiveOverlap(Stream5TcpPolicy *s5TcpPolicy)
{
    if(!(s5TcpPolicy->flags & STREAM5_CONFIG_ENABLE_ALERTS))
        return;

    s5stats.events++;

    SnortEventqAdd(GENERATOR_SPP_STREAM5,       /* GID */
            STREAM5_EXCESSIVE_TCP_OVERLAPS,     /* SID */
            1,                                  /* rev */
            0,                                  /* class */
            3,                                  /* priority */
            STREAM5_EXCESSIVE_TCP_OVERLAPS_STR, /* event msg */
            NULL);                              /* rule info ptr */
}

static INLINE void EventBadTimestamp(Stream5TcpPolicy *s5TcpPolicy)
{
    if(!(s5TcpPolicy->flags & STREAM5_CONFIG_ENABLE_ALERTS))
        return;

    s5stats.events++;

    SnortEventqAdd(GENERATOR_SPP_STREAM5,       /* GID */
            STREAM5_BAD_TIMESTAMP,              /* SID */
            1,                                  /* rev */
            0,                                  /* class */
            3,                                  /* priority */
            STREAM5_BAD_TIMESTAMP_STR,          /* event msg */
            NULL);                              /* rule info ptr */
}

static INLINE void EventWindowTooLarge(Stream5TcpPolicy *s5TcpPolicy)
{
    if(!(s5TcpPolicy->flags & STREAM5_CONFIG_ENABLE_ALERTS))
        return;

    s5stats.events++;

    SnortEventqAdd(GENERATOR_SPP_STREAM5,       /* GID */
            STREAM5_WINDOW_TOO_LARGE,           /* SID */
            1,                                  /* rev */
            0,                                  /* class */
            3,                                  /* priority */
            STREAM5_WINDOW_TOO_LARGE_STR,       /* event msg */
            NULL);                              /* rule info ptr */
}

static INLINE void EventDataOnSyn(Stream5TcpPolicy *s5TcpPolicy)
{
    if(!(s5TcpPolicy->flags & STREAM5_CONFIG_ENABLE_ALERTS))
        return;

    s5stats.events++;

    SnortEventqAdd(GENERATOR_SPP_STREAM5,       /* GID */
            STREAM5_DATA_ON_SYN,                /* SID */
            1,                                  /* rev */
            0,                                  /* class */
            3,                                  /* priority */
            STREAM5_DATA_ON_SYN_STR,            /* event msg */
            NULL);                              /* rule info ptr */
}

static INLINE void EventDataOnClosed(Stream5TcpPolicy *s5TcpPolicy)
{
    if(!(s5TcpPolicy->flags & STREAM5_CONFIG_ENABLE_ALERTS))
        return;

    s5stats.events++;

    SnortEventqAdd(GENERATOR_SPP_STREAM5,       /* GID */
            STREAM5_DATA_ON_CLOSED,             /* SID */
            1,                                  /* rev */
            0,                                  /* class */
            3,                                  /* priority */
            STREAM5_DATA_ON_CLOSED_STR,         /* event msg */
            NULL);                              /* rule info ptr */
}

static INLINE void EventDataAfterReset(Stream5TcpPolicy *s5TcpPolicy)
{
    if(!(s5TcpPolicy->flags & STREAM5_CONFIG_ENABLE_ALERTS))
        return;

    s5stats.events++;

    SnortEventqAdd(GENERATOR_SPP_STREAM5,       /* GID */
            STREAM5_DATA_AFTER_RESET,           /* SID */
            1,                                  /* rev */
            0,                                  /* class */
            3,                                  /* priority */
            STREAM5_DATA_AFTER_RESET_STR,       /* event msg */
            NULL);                              /* rule info ptr */
}

static INLINE void EventBadSegment(Stream5TcpPolicy *s5TcpPolicy)
{
    if(!(s5TcpPolicy->flags & STREAM5_CONFIG_ENABLE_ALERTS))
        return;

    s5stats.events++;

    SnortEventqAdd(GENERATOR_SPP_STREAM5,       /* GID */
            STREAM5_BAD_SEGMENT,                /* SID */
            1,                                  /* rev */
            0,                                  /* class */
            3,                                  /* priority */
            STREAM5_BAD_SEGMENT_STR,            /* event msg */
            NULL);                              /* rule info ptr */
}

static INLINE void EventSessionHijackedClient(Stream5TcpPolicy *s5TcpPolicy)
{
    if(!(s5TcpPolicy->flags & STREAM5_CONFIG_ENABLE_ALERTS))
        return;

    s5stats.events++;

    SnortEventqAdd(GENERATOR_SPP_STREAM5,       /* GID */
            STREAM5_SESSION_HIJACKED_CLIENT,    /* SID */
            1,                                  /* rev */
            0,                                  /* class */
            3,                                  /* priority */
            STREAM5_SESSION_HIJACKED_CLIENT_STR, /* event msg */
            NULL);                              /* rule info ptr */
}
static INLINE void EventSessionHijackedServer(Stream5TcpPolicy *s5TcpPolicy)
{
    if(!(s5TcpPolicy->flags & STREAM5_CONFIG_ENABLE_ALERTS))
        return;

    s5stats.events++;

    SnortEventqAdd(GENERATOR_SPP_STREAM5,       /* GID */
            STREAM5_SESSION_HIJACKED_SERVER,    /* SID */
            1,                                  /* rev */
            0,                                  /* class */
            3,                                  /* priority */
            STREAM5_SESSION_HIJACKED_SERVER_STR, /* event msg */
            NULL);                              /* rule info ptr */
}

static INLINE void EventDataWithoutFlags(Stream5TcpPolicy *s5TcpPolicy)
{
    if(!(s5TcpPolicy->flags & STREAM5_CONFIG_ENABLE_ALERTS))
        return;

    s5stats.events++;

    SnortEventqAdd(GENERATOR_SPP_STREAM5,       /* GID */
            STREAM5_DATA_WITHOUT_FLAGS,         /* SID */
            1,                                  /* rev */
            0,                                  /* class */
            3,                                  /* priority */
            STREAM5_DATA_WITHOUT_FLAGS_STR,     /* event msg */
            NULL);                              /* rule info ptr */
}

/*
 *  Utility functions for TCP stuff
 */
static INLINE int IsBetween(u_int32_t low, u_int32_t high, u_int32_t cur)
{
    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "(%X, %X, %X) = (low, high, cur)\n", low,high,cur););

    /* If we haven't seen anything, ie, low & high are 0, return true */
    if ((low == 0) && (low == high))
        return 1;

    return (SEQ_GEQ(cur, low) && SEQ_LEQ(cur, high));
}           

static INLINE u_int32_t Stream5GetWindow(StreamTracker *st)
{
    int32_t window;

    /* If we're in readback mode and haven't seen the other
     * side yet, window is r_next_ack - r_win_base.
     */
    if ((st->l_window == 0) && (pv.readmode_flag == 1))
    {
        window = st->r_nxt_ack - st->r_win_base + 1;
    }
    else
    {
        //window = st->r_win_base + (st->l_window - st->r_nxt_ack);
        window = st->l_window;
    }

    if(window <  0)
        return 0;
    else
        return (u_int32_t) window;
}

static INLINE int ValidRst(StreamTracker *st, TcpDataBlock *tdb)
{
    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Checking end_seq (%X) > r_win_base (%X) && "
                "seq (%X) < r_nxt_ack(%X)\n", 
                tdb->end_seq, st->r_win_base, tdb->seq, 
                st->r_nxt_ack+Stream5GetWindow(st)););

    switch (st->os_policy)
    {
        case STREAM_POLICY_HPUX11:
            if (SEQ_GEQ(tdb->seq, st->r_nxt_ack))
            {
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "rst is valid seq (>= next seq)!\n"););
                return 1;
            }
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "rst is not valid seq (>= next seq)!\n"););
            return 0;
            break;
        case STREAM_POLICY_FIRST:
        case STREAM_POLICY_LAST:
        /* Uh, who knows */
        case STREAM_POLICY_BSD:
        case STREAM_POLICY_MACOS:
        case STREAM_POLICY_WINDOWS:
        case STREAM_POLICY_VISTA:
        case STREAM_POLICY_WINDOWS2K3:
        case STREAM_POLICY_HPUX10:
        case STREAM_POLICY_IRIX:
            if (SEQ_EQ(tdb->seq, st->r_nxt_ack))
            {
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "rst is valid seq (next seq)!\n"););
                return 1;
            }
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "rst is not valid seq (next seq)!\n"););
            return 0;
            break;
        case STREAM_POLICY_LINUX:
        case STREAM_POLICY_OLD_LINUX:
        case STREAM_POLICY_SOLARIS:
            if(SEQ_GEQ(tdb->end_seq, st->r_win_base))
            {
                if(SEQ_LT(tdb->seq, st->r_nxt_ack+Stream5GetWindow(st)))
                {
                    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "rst is valid seq (within window)!\n"););
                return 1;
                }
            }
            
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "rst is not valid seq (within window)!\n"););
            return 0;
            break;
    }

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "rst is not valid!\n"););
    return 0;
}

static INLINE int ValidTimestamp(StreamTracker *talker,
                                 StreamTracker *listener,
                                 TcpDataBlock *tdb,
                                 Packet *p,
                                 int *eventcode,
                                 int *got_ts)
{
    if (!eventcode || !got_ts)
        return ACTION_NOTHING;

    /*
     * check PAWS
     */
    if((talker->flags & TF_TSTAMP) && (listener->flags & TF_TSTAMP))
    {
        char validate_timestamp = 1;
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Checking timestamps for PAWS\n"););

        *got_ts = Stream5GetTcpTimestamp(p, &tdb->ts);

        if (*got_ts)
        {
            if (listener->tcp_policy->policy == STREAM_POLICY_HPUX11)
            {
                /* HPUX 11 ignores timestamps for out of order segments */
                if ((listener->flags & TF_MISSING_PKT) ||
                    !SEQ_EQ(listener->r_nxt_ack, tdb->seq))
                {
                    validate_timestamp = 0;
                }
            }

            if (talker->flags & TF_TSTAMP_ZERO)
            {
                /* Handle the case where the 3whs used a 0 timestamp.  Next packet
                 * from that endpoint should have a valid timestamp... */
                if ((listener->tcp_policy->policy == STREAM_POLICY_LINUX) ||
                    (listener->tcp_policy->policy == STREAM_POLICY_WINDOWS2K3))
                {
                    /* Linux, Win2k3 et al.  do not support timestamps if
                     * the 3whs used a 0 timestamp. */
                    talker->flags &= ~TF_TSTAMP;
                    listener->flags &= ~TF_TSTAMP;
                    validate_timestamp = 0;
                }
                else if ((listener->tcp_policy->policy == STREAM_POLICY_OLD_LINUX) ||
                         (listener->tcp_policy->policy == STREAM_POLICY_WINDOWS) ||
                         (listener->tcp_policy->policy == STREAM_POLICY_VISTA))
                {
                    /* Older Linux (2.2 kernel & earlier), Win32 (non 2K3)
                     * allow the 3whs to use a 0 timestamp. */
                    talker->flags &= ~TF_TSTAMP_ZERO;
                    if(SEQ_EQ(listener->r_nxt_ack, tdb->seq))
                    {
                        talker->ts_last = tdb->ts;
                        validate_timestamp = 0; /* Ignore the timestamp for this
                                                 * first packet, next one will
                                                 * checked. */
                    }
                }
            }

            if (validate_timestamp)
            {
                int result = 0;
                if (listener->tcp_policy->policy == STREAM_POLICY_LINUX)
                {
                    /* Linux 2.6 accepts timestamp values that are off
                     * by one. */
                    result = (int)((tdb->ts - talker->ts_last) + 1); 
                }
                else
                {
                    result = (int)(tdb->ts - talker->ts_last);  
                }

                if(result < 0)
                {
                    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                                "Packet outside PAWS window, dropping\n"););
                    //s5stats.tcp_discards++;
                    /* bail, we've got a packet outside the PAWS window! */
                    *eventcode |= EVENT_BAD_TIMESTAMP;
                    //LogTcpEvents(listener->tcp_policy, eventcode);
                    //PREPROC_PROFILE_END(s5TcpStatePerfStats);
                    //return ACTION_BAD_PKT | retcode;
                    return ACTION_BAD_PKT;
                }
                else if ((talker->ts_last != 0) &&
                        ((u_int32_t)p->pkth->ts.tv_sec > talker->ts_last_pkt+PAWS_24DAYS))
                {
                    /* this packet is from way too far into the future */
                    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                                "packet PAWS timestamp way too far ahead of"
                                "last packet %d %d...\n", p->pkth->ts.tv_sec,
                                talker->ts_last_pkt););
                    //s5stats.tcp_discards++;
                    *eventcode |= EVENT_BAD_TIMESTAMP;
                    //LogTcpEvents(listener->tcp_policy, eventcode);
                    //PREPROC_PROFILE_END(s5TcpStatePerfStats);
                    //return ACTION_BAD_PKT | retcode;
                    return ACTION_BAD_PKT;
                }
                else
                {
                    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                                "packet PAWS ok...\n"););
                }
            }
        }
        else
        {
            /* we've got a packet with no timestamp, but 3whs indicated talker
             * was doing timestamps.  This breaks protocol, however, some servers
             * still ack the packet with the missing timestamp.  Log an alert,
             * but continue to process the packet
             */
            *eventcode |= EVENT_BAD_TIMESTAMP;
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                        "packet no timestamp, had one earlier from this side...ok for now...\n"););

            if (listener->tcp_policy->policy == STREAM_POLICY_SOLARIS)
            {
                /* Solaris stops using timestamps if it receives a packet
                 * without a timestamp and there were timestamps in use.
                 */
                listener->flags &= ~TF_TSTAMP;
            }
        }
    }
    else
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "listener not doing timestamps...\n"););
        *got_ts = Stream5GetTcpTimestamp(p, &tdb->ts);
        if (*got_ts)
        {
            if (!(talker->flags & TF_TSTAMP))
            {
                /* Since we skipped the SYN, may have missed the talker's
                 * timestamp there, so set it now.
                 */
                talker->flags |= TF_TSTAMP;
                if (tdb->ts == 0)
                {
                    talker->flags |= TF_TSTAMP_ZERO;
                }
            }

            /* Only valid to test this if listener is using timestamps.
             * Otherwise, timestamp in this packet is not used, regardless
             * of its value. */
            if ((tdb->ts == 0) && (listener->flags & TF_TSTAMP))
            {
                switch (listener->os_policy)
                {
                case STREAM_POLICY_WINDOWS:
                case STREAM_POLICY_VISTA:
                case STREAM_POLICY_WINDOWS2K3:
                case STREAM_POLICY_OLD_LINUX:
                case STREAM_POLICY_SOLARIS:
                    /* Old Linux & Windows allows a 0 timestamp value. */
                    break;
                default:
                    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                                "Packet with 0 timestamp, dropping\n"););
                    //s5stats.tcp_discards++;
                    /* bail */
                    *eventcode |= EVENT_BAD_TIMESTAMP;
                    //LogTcpEvents(listener->tcp_policy, eventcode);
                    //PREPROC_PROFILE_END(s5TcpStatePerfStats);
                    //return ACTION_BAD_PKT | retcode;
                    return ACTION_BAD_PKT;
                    //break;
                }
            }
        }
    }
    return ACTION_NOTHING;
}

static INLINE int ValidSeq(StreamTracker *st, TcpDataBlock *tdb)
{
    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Checking end_seq (%X) > r_win_base (%X) && "
                "seq (%X) < r_nxt_ack(%X)\n", 
                tdb->end_seq, st->r_win_base, tdb->seq, 
                st->r_nxt_ack+Stream5GetWindow(st)););

    if(SEQ_GEQ(tdb->end_seq, st->r_win_base))
    {
        if(SEQ_LT(tdb->seq, st->r_nxt_ack+Stream5GetWindow(st)))
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "seq is within window!\n"););
            return 1;
        }
        else
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "seq is past the end of the window!\n"););
        }
    }
    else
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "end_seq is before win_base\n"););
    }
    return 0;
}

static INLINE void UpdateSsn(StreamTracker *rcv, StreamTracker *snd, 
        TcpDataBlock *tdb)
{
    if(SEQ_GT(tdb->ack, rcv->l_unackd) && SEQ_GT(tdb->ack, rcv->l_nxt_seq))
        rcv->l_unackd = tdb->ack;

    snd->l_unackd = tdb->seq;
    //snd->l_nxt_seq = tdb->seq + 1;
    if (SEQ_GT(tdb->end_seq, snd->l_nxt_seq))
        snd->l_nxt_seq = tdb->end_seq;
    snd->r_win_base = tdb->ack;
    snd->l_window = tdb->win;
}

extern unsigned int num_preprocs;

static void Stream5InitPacket()
{
    s5_pkt = (Packet *) SnortAlloc(sizeof(Packet));
    s5_pkt->pkth = SnortAlloc(sizeof(struct pcap_pkthdr)+
            ETHERNET_HEADER_LEN +
            SPARC_TWIDDLE + IP_MAXPACKET);
    
    if (s5_pkt->pkth == NULL)
    {
        FatalError("Stream5InitPacket() => Failed to allocate memory\n");
    }

    s5_pkt->pkt = ((u_int8_t *)s5_pkt->pkth) + sizeof(struct pcap_pkthdr);
    s5_pkt->eh = (EtherHdr *)((u_int8_t *)s5_pkt->pkt + SPARC_TWIDDLE);
    s5_pkt->iph =
        (IPHdr *)((u_int8_t *)s5_pkt->eh + ETHERNET_HEADER_LEN);
    s5_pkt->tcph = (TCPHdr *)((u_int8_t *)s5_pkt->iph + IP_HEADER_LEN);

    s5_pkt->data = (u_int8_t *)s5_pkt->tcph + TCP_HEADER_LEN;

    /*  s5_pkt->data is now pkt +
     *  IPMAX_PACKET - (IP_HEADER_LEN + TCP_HEADER_LEN + ETHERNET_HEADER_LEN)
     *  in size
     *
     * This is MAX_STREAM_SIZE
     */
    ((EtherHdr *)s5_pkt->eh)->ether_type = htons(0x0800);
    SET_IP_VER((IPHdr *)s5_pkt->iph, 0x4);
    SET_IP_HLEN((IPHdr *)s5_pkt->iph, 0x5);
    ((IPHdr *)s5_pkt->iph)->ip_proto = IPPROTO_TCP;
    ((IPHdr *)s5_pkt->iph)->ip_ttl   = 0xF0;
    ((IPHdr *)s5_pkt->iph)->ip_len = 0x5;
    ((IPHdr *)s5_pkt->iph)->ip_tos = 0x10;

    SET_TCP_OFFSET((TCPHdr *)s5_pkt->tcph,0x5);
    ((TCPHdr *)s5_pkt->tcph)->th_flags = TH_PUSH|TH_ACK;

    s5_pkt->preprocessor_bits = (BITOP *)SnortAlloc(sizeof(BITOP));
    boInitBITOP(s5_pkt->preprocessor_bits, num_preprocs + 1);

    s5_pkt->preproc_reassembly_pkt_bits = (BITOP *)SnortAlloc(sizeof(BITOP));
    boInitBITOP(s5_pkt->preproc_reassembly_pkt_bits, num_preprocs + 1);

#ifdef SUP_IP6    
    sfiph_build(s5_pkt, s5_pkt->iph, AF_INET);

    /* Same thing as above, but for the IPv6-enabled packet */
    s5_pkt_6 = (Packet *) SnortAlloc(sizeof(Packet));
    s5_pkt_6->pkth = SnortAlloc(sizeof(struct pcap_pkthdr)+
            ETHERNET_HEADER_LEN +
            SPARC_TWIDDLE + IP_MAXPACKET);
    
    if (s5_pkt_6->pkth == NULL)
    {
        FatalError("Stream5InitPacket() => Failed to allocate memory\n");
    }

    s5_pkt_6->pkt = ((u_int8_t *)s5_pkt_6->pkth) + sizeof(struct pcap_pkthdr);
    s5_pkt_6->eh = (EtherHdr *)((u_int8_t *)s5_pkt_6->pkt + SPARC_TWIDDLE);
    s5_pkt_6->iph =
        (IPHdr *)((u_int8_t *)s5_pkt_6->eh + ETHERNET_HEADER_LEN);
    s5_pkt_6->tcph = (TCPHdr *)((u_int8_t *)s5_pkt_6->iph + IP6_HDR_LEN);

    s5_pkt_6->data = (u_int8_t *)s5_pkt_6->tcph + TCP_HEADER_LEN;

    /*  s5_pkt->data is now pkt +
     *  IPMAX_PACKET - (IP_HEADER_LEN + TCP_HEADER_LEN + ETHERNET_HEADER_LEN)
     *  in size
     *
     * This is MAX_STREAM_SIZE
     */
    ((EtherHdr *)s5_pkt_6->eh)->ether_type = htons(0x0800);
    SET_IP_VER((IPHdr *)s5_pkt_6->iph, 0x4);
    SET_IP_HLEN((IPHdr *)s5_pkt_6->iph, 0x5);
    ((IPHdr *)s5_pkt_6->iph)->ip_len = 0x5;
    ((IPHdr *)s5_pkt_6->iph)->ip_tos = 0x10;
    s5_pkt_6->ip6h.next = ((IPHdr *)s5_pkt_6->iph)->ip_proto = IPPROTO_TCP;
    s5_pkt_6->ip6h.hop_lmt = ((IPHdr *)s5_pkt_6->iph)->ip_ttl = 0xF0;
    s5_pkt_6->ip6h.len = IP6_HDR_LEN >> 2;
 
    set_callbacks(s5_pkt_6, AF_INET6);

    SET_TCP_OFFSET((TCPHdr *)s5_pkt_6->tcph, 0x5);
    ((TCPHdr *)s5_pkt_6->tcph)->th_flags = TH_PUSH|TH_ACK;

    s5_pkt_6->preprocessor_bits = (BITOP *)SnortAlloc(sizeof(BITOP));
    boInitBITOP(s5_pkt_6->preprocessor_bits, num_preprocs + 1);

    s5_pkt_6->preproc_reassembly_pkt_bits = (BITOP *)SnortAlloc(sizeof(BITOP));
    boInitBITOP(s5_pkt_6->preproc_reassembly_pkt_bits, num_preprocs + 1);
#endif
}

static INLINE void SetupTcpDataBlock(TcpDataBlock *tdb, Packet *p)
{
#ifdef SUP_IP6
    tdb->sip = *GET_SRC_IP(p);
    tdb->dip = *GET_DST_IP(p);
    if(IS_IP4(p))
    {
        *tdb->sip.ip32 = ntohl(*tdb->sip.ip32);
        *tdb->dip.ip32 = ntohl(*tdb->dip.ip32);
    } 
#else
    tdb->sip = ntohl(p->iph->ip_src.s_addr);
    tdb->dip = ntohl(p->iph->ip_dst.s_addr);
#endif
    tdb->seq = ntohl(p->tcph->th_seq);
    tdb->ack = ntohl(p->tcph->th_ack);
    tdb->win = ntohs(p->tcph->th_win);
    tdb->end_seq = tdb->seq + (u_int32_t) p->dsize;
    if(p->tcph->th_flags & TH_SYN) tdb->end_seq++;
    if(p->tcph->th_flags & TH_FIN) tdb->end_seq++;
    return;
}

static void Stream5DropSegment(StreamSegment *seg)
{
    int dropped = 0;

    if(seg != NULL)
    {
        STREAM5_DEBUG_WRAP( DebugMessage(DEBUG_STREAM_STATE,  
                        "Dumping segment at seq %X, size %d, caplen %d\n", 
                        seg->seq, seg->size, seg->caplen););

        if(seg->pktOrig != NULL)
        {
            s5_global_config.mem_in_use -= seg->caplen;
            dropped += seg->caplen;
            free(seg->pktOrig);
            seg->pktOrig = NULL;
        }

        s5_global_config.mem_in_use -= sizeof(StreamSegment);
        dropped += sizeof(StreamSegment);
        free(seg);
        s5stats.tcp_streamsegs_released++;
    }

    STREAM5_DEBUG_WRAP( DebugMessage(DEBUG_STREAM_STATE,  
                "Stream5DropSegment dropped %d bytes\n", dropped););
}

static void DeleteSeglist(StreamSegment *listhead)
{
    StreamSegment *idx = listhead;
    StreamSegment *dump_me;
    int i = 0;

    STREAM5_DEBUG_WRAP( DebugMessage(DEBUG_STREAM_STATE,  
                "In DeleteSeglist\n"););
    while(idx)
    {
        i++;
        dump_me = idx;
        idx = idx->next;
        Stream5DropSegment(dump_me);
    }

    STREAM5_DEBUG_WRAP( DebugMessage(DEBUG_STREAM_STATE,  
                "Dropped %d segments\n", i););
}

INLINE int purge_alerts(StreamTracker *st, u_int32_t flush_seq)
{
    int i;
    int new_count = 0;

    for (i=0;i<st->alert_count;i++)
    {
        u_int32_t alert_seq = ntohl(st->alerts[i].seq);
        if (SEQ_LT(alert_seq,flush_seq) )
        {
            st->alerts[i].sid = 0;
            st->alerts[i].gid = 0;
            st->alerts[i].seq = 0;
        }
        else
        {
            if (new_count != i)
            {
                st->alerts[new_count].sid = st->alerts[i].sid;
                st->alerts[new_count].gid = st->alerts[i].gid;
                st->alerts[new_count].seq = st->alerts[i].seq;
            }
            new_count++;
        }
    }
    st->alert_count = new_count;

    return new_count;
}

INLINE int purge_to_seq(TcpSession *tcpssn, StreamTracker *st, u_int32_t flush_seq)
{
    StreamSegment *ss = NULL;
    StreamSegment *dump_me = NULL;
    int purged_bytes = 0;
    u_int32_t last_ts = 0;

    if(st->seglist == NULL)
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
               "setting st->seglist_base_seq to 0x%X\n", 
               flush_seq););
        st->seglist_base_seq = flush_seq;
        return 0;
    }

    ss = st->seglist;
    
    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                "In purge_to_seq, start seq = 0x%X end seq = 0x%X delta %d\n", 
                ss->seq, flush_seq, flush_seq-ss->seq););
    while(ss)
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "s: %X  sz: %d\n", ss->seq, ss->size););
        dump_me = ss;

        ss = ss->next;
        if(SEQ_LT(dump_me->seq, flush_seq))
        {
            if (dump_me->ts > last_ts)
            {
                last_ts = dump_me->ts;
            }
            purged_bytes += Stream5SeglistDeleteNode(st, dump_me);
        }
        else
            break;
    }

    //st->seglist_base_seq = st->r_win_base;
    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
               "setting st->seglist_base_seq to 0x%X\n", 
               flush_seq););
    st->seglist_base_seq = flush_seq;
    st->r_nxt_ack = flush_seq;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                "st->seglist_base_seq set to 0x%X\n", st->seglist_base_seq););

    purge_alerts(st, flush_seq);

    if (st->seglist == NULL)
    {
        st->seglist_tail = NULL;
    }

    /* Update the "last" time stamp seen from the other side
     * to be the most recent timestamp (largest) that was removed
     * from the queue.  This will ensure that as we go forward,
     * last timestamp is the highest one that we had stored and
     * purged and handle the case when packets arrive out of order,
     * such as:
     * P1: seq 10, length 10, timestamp 10 
     * P3: seq 30, length 10, timestamp 30
     * P2: seq 20, length 10, timestamp 20
     *
     * Without doing it this way, the timestamp would be 20.  With
     * the next packet to arrive (P4, seq 40), the ts_last value
     * wouldn't be updated for the talker in ProcessTcp() since that
     * code specificially looks for the NEXT sequence number.
     */
    if (st == &tcpssn->client)
    {
        int32_t delta = last_ts - tcpssn->server.ts_last;
        if (delta > 0)
            tcpssn->server.ts_last = last_ts;
    }
    else if (st == &tcpssn->server)
    {
        int32_t delta = last_ts - tcpssn->client.ts_last;
        if (delta > 0)
            tcpssn->client.ts_last = last_ts;
    }


    return purged_bytes;
}

/*
 * purge a seglist up the the last ack received
 */
INLINE int purge_ackd(TcpSession *tcpssn, StreamTracker *st)
{
    return purge_to_seq(tcpssn, st, st->r_win_base);
}

#ifdef SUP_IP6
INLINE int _flush_ackd_4(TcpSession *tcpssn, StreamTracker *st, Packet *p, 
        snort_ip_p sip, snort_ip_p dip, u_int16_t sp, u_int16_t dp, u_int32_t dir)
{
    u_int32_t base_seq;
    u_int32_t footprint = 0;
    u_int16_t ip_len;
    u_int32_t bytes_processed = 0;
    int32_t flushed_bytes;
    PROFILE_VARS;

    PREPROC_PROFILE_START(s5TcpFlushPerfStats);

    IP_COPY_VALUE(s5_pkt->ip4h.ip_src, sip);
    IP_COPY_VALUE(s5_pkt->ip4h.ip_dst, dip);
    ((IPHdr *)s5_pkt->iph)->ip_src.s_addr = *sip->ip32;
    ((IPHdr *)s5_pkt->iph)->ip_dst.s_addr = *dip->ip32;
    
    ((TCPHdr *)s5_pkt->tcph)->th_sport = sp;
    ((TCPHdr *)s5_pkt->tcph)->th_dport = dp;
    s5_pkt->sp = htons(sp);
    s5_pkt->dp = htons(dp);

    if(p->eh != NULL)
    {
        if (p->sp == s5_pkt->sp)
        {
            memcpy(((EtherHdr *)s5_pkt->eh)->ether_src, p->eh->ether_src, 6);
            memcpy(((EtherHdr *)s5_pkt->eh)->ether_dst, p->eh->ether_dst, 6);
        }
        else
        {
            memcpy(((EtherHdr *)s5_pkt->eh)->ether_src, p->eh->ether_dst, 6);
            memcpy(((EtherHdr *)s5_pkt->eh)->ether_dst, p->eh->ether_src, 6);
        }
    }

    ((TCPHdr *)s5_pkt->tcph)->th_seq = htonl(st->seglist_base_seq);
    ((TCPHdr *)s5_pkt->tcph)->th_ack = htonl(st->l_unackd);
    ((TCPHdr *)s5_pkt->tcph)->th_win = htons(st->l_window);

    do
    {
        base_seq = st->seglist_base_seq; 

        footprint = st->r_win_base - base_seq;

        if(footprint == 0) 
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "Negative footprint, bailing %d (0x%X - 0x%X)\n", 
                        footprint, st->r_win_base, base_seq););
            PREPROC_PROFILE_END(s5TcpFlushPerfStats);

            return bytes_processed;
        }

        if(footprint < st->seg_bytes_logical)
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "Footprint less than queued bytes, "
                        "win_base: 0x%X base_seq: 0x%X\n", 
                        st->r_win_base, base_seq););
        }

        if(footprint > STREAM_MAX_PACKET)
        {
            /* this is as much as we can pack into a stream buffer */
            footprint = STREAM_MAX_PACKET;
        }

        /* setup the pseudopacket payload */
        flushed_bytes = FlushStream(st, /* p, */ (u_int8_t *)s5_pkt->data, (int) footprint);

        if(flushed_bytes == -1)
        {
            /* couldn't put a stream together for whatever reason
             * should probably clean the seglist and bail...
             */
            if(st->seglist)
            {
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "dumping entire seglist!\n"););

                DeleteSeglist(st->seglist);
                st->seglist_tail = NULL;
            }

            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                       "setting st->seglist_base_seq to 0x%X\n", 
                       st->r_win_base););
            st->seglist_base_seq = st->r_win_base;

            PREPROC_PROFILE_END(s5TcpFlushPerfStats);
            return bytes_processed;
        }

        if (flushed_bytes == 0)
        {
            /* No more ACK'd data... bail */
            break;
        }

        s5_pkt->dsize = (u_int16_t)flushed_bytes;
        
        ((struct pcap_pkthdr *)s5_pkt->pkth)->caplen = s5_pkt->dsize + IP_HEADER_LEN + 
            TCP_HEADER_LEN + ETHERNET_HEADER_LEN;
        ((struct pcap_pkthdr *)s5_pkt->pkth)->len = s5_pkt->pkth->caplen;

        ((struct pcap_pkthdr *)s5_pkt->pkth)->ts.tv_sec = st->seglist->pkth.ts.tv_sec;
        ((struct pcap_pkthdr *)s5_pkt->pkth)->ts.tv_usec = st->seglist->pkth.ts.tv_usec;

        ip_len = (u_int16_t)(s5_pkt->dsize + IP_HEADER_LEN + TCP_HEADER_LEN);
        s5_pkt->ip4h.ip_len = ((IPHdr *)s5_pkt->iph)->ip_len = htons(ip_len);

        sfPerf.sfBase.iStreamFlushes++;

        bytes_processed += s5_pkt->dsize;

        s5_pkt->packet_flags = (PKT_REBUILT_STREAM|PKT_STREAM_EST);
        s5_pkt->packet_flags |= dir;
        s5_pkt->ssnptr = (void *) tcpssn->lwssn;
        //s5_pkt->streamptr = (void *) st;
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                   "setting st->seglist_base_seq to 0x%X\n", 
                   st->r_win_base););

        if (st->flags & TF_MISSING_PKT)
        {
            st->seglist_base_seq = st->gap_seq;
        }
        else
        {
            st->seglist_base_seq = st->r_win_base;
        }

        if(s5_global_config.flags & STREAM5_CONFIG_SHOW_PACKETS)
        {
            //ClearDumpBuf();
            printf("+++++++++++++++++++Stream Packet+++++++++++++++++++++\n");
            PrintIPPkt(stdout, IPPROTO_TCP, s5_pkt);
            printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
            //ClearDumpBuf();
        }

        s5stats.tcp_rebuilt_packets++; 

        PREPROC_PROFILE_TMPEND(s5TcpFlushPerfStats);
        {
            int event, tmp_do_detect, tmp_do_detect_content;
            PROFILE_VARS;
            
            PREPROC_PROFILE_START(s5TcpProcessRebuiltPerfStats);
            tmp_do_detect = do_detect;
            tmp_do_detect_content = do_detect_content;
            event = Preprocess(s5_pkt);
            do_detect = tmp_do_detect;
            do_detect_content = tmp_do_detect_content;
            PREPROC_PROFILE_END(s5TcpProcessRebuiltPerfStats);

            if(event)
            {
                //LogStream(s);
            }
        }
        PREPROC_PROFILE_TMPSTART(s5TcpFlushPerfStats);

        /* Reset alert tracking after flushing rebuilt packet */

        /* Remove the packets & alerts that are beyond the high-end of
         * those packets flushed */
        purge_to_seq(tcpssn, st, st->seglist_base_seq);

    } while (!(st->flags & TF_MISSING_PKT) && (st->seg_count > 1));

    /* Grab the next random flush point */
    //UpdateFlushMgr(&st->flush_mgr);

    /* tell them how many bytes we processed */
    PREPROC_PROFILE_END(s5TcpFlushPerfStats);
    return bytes_processed;
}


INLINE int _flush_ackd_6(TcpSession *tcpssn, StreamTracker *st, Packet *p, 
        snort_ip_p sip, snort_ip_p dip, u_int16_t sp, u_int16_t dp, u_int32_t dir)
{
    u_int32_t base_seq;
    u_int32_t footprint = 0;
    u_int16_t ip_len;
    u_int32_t bytes_processed = 0;
    int32_t flushed_bytes;
    PROFILE_VARS;

    PREPROC_PROFILE_START(s5TcpFlushPerfStats);
    
    IP_COPY_VALUE(s5_pkt_6->ip6h.ip_src, sip);
    IP_COPY_VALUE(s5_pkt_6->ip6h.ip_dst, dip);

    ((TCPHdr *)s5_pkt_6->tcph)->th_sport = sp;
    ((TCPHdr *)s5_pkt_6->tcph)->th_dport = dp;
    s5_pkt_6->sp = htons(sp);
    s5_pkt_6->dp = htons(dp);

    if(p->eh != NULL)
    {
        if (p->sp == s5_pkt_6->sp)
        {
            memcpy(((EtherHdr *)s5_pkt_6->eh)->ether_src, p->eh->ether_src, 6);
            memcpy(((EtherHdr *)s5_pkt_6->eh)->ether_dst, p->eh->ether_dst, 6);
        }
        else
        {
            memcpy(((EtherHdr *)s5_pkt_6->eh)->ether_src, p->eh->ether_dst, 6);
            memcpy(((EtherHdr *)s5_pkt_6->eh)->ether_dst, p->eh->ether_src, 6);
        }
    }

    ((TCPHdr *)s5_pkt_6->tcph)->th_seq = htonl(st->seglist_base_seq);
    ((TCPHdr *)s5_pkt_6->tcph)->th_ack = htonl(st->l_unackd);
    ((TCPHdr *)s5_pkt_6->tcph)->th_win = htons(st->l_window);

    do
    {
        base_seq = st->seglist_base_seq; 

        footprint = st->r_win_base - base_seq;

        if(footprint <= 0) 
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "Negative footprint, bailing %d (0x%X - 0x%X)\n", 
                        footprint, st->r_win_base, base_seq););
            PREPROC_PROFILE_END(s5TcpFlushPerfStats);

            return bytes_processed;
        }

        if(footprint < st->seg_bytes_logical)
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "Footprint less than queued bytes, "
                        "win_base: 0x%X base_seq: 0x%X\n", 
                        st->r_win_base, base_seq););
        }

        if(footprint > STREAM_MAX_PACKET)
        {
            /* this is as much as we can pack into a stream buffer */
            footprint = STREAM_MAX_PACKET;
        }

        /* setup the pseudopacket payload */
        flushed_bytes = FlushStream(st, /* p, */ (u_int8_t *)s5_pkt_6->data, (int) footprint);

        if(flushed_bytes == -1)
        {
            /* couldn't put a stream together for whatever reason
             * should probably clean the seglist and bail...
             */
            if(st->seglist)
            {
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "dumping entire seglist!\n"););

                DeleteSeglist(st->seglist);
                st->seglist_tail = NULL;
            }

            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                       "setting st->seglist_base_seq to 0x%X\n", 
                       st->r_win_base););
            st->seglist_base_seq = st->r_win_base;

            PREPROC_PROFILE_END(s5TcpFlushPerfStats);
            return bytes_processed;
        }

        if (flushed_bytes == 0)
        {
            /* No more ACK'd data... bail */
            break;
        }

        s5_pkt_6->dsize = (u_int16_t)flushed_bytes;

        ((struct pcap_pkthdr *)s5_pkt_6->pkth)->caplen = s5_pkt_6->dsize + IP6_HDR_LEN + 
            TCP_HEADER_LEN + ETHERNET_HEADER_LEN;
        ((struct pcap_pkthdr *)s5_pkt_6->pkth)->len = s5_pkt_6->pkth->caplen;

        ((struct pcap_pkthdr *)s5_pkt_6->pkth)->ts.tv_sec = st->seglist->pkth.ts.tv_sec;
        ((struct pcap_pkthdr *)s5_pkt_6->pkth)->ts.tv_usec = st->seglist->pkth.ts.tv_usec;

        ip_len = (u_int16_t)(s5_pkt_6->dsize + IP6_HDR_LEN + TCP_HEADER_LEN);
        s5_pkt_6->ip6h.len = htons(ip_len);

        sfPerf.sfBase.iStreamFlushes++;

        bytes_processed += s5_pkt_6->dsize;

        s5_pkt_6->packet_flags = (PKT_REBUILT_STREAM|PKT_STREAM_EST);
        s5_pkt_6->packet_flags |= dir;
        s5_pkt_6->ssnptr = (void *) tcpssn->lwssn;
        //s5_pkt->streamptr = (void *) st;
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                   "setting st->seglist_base_seq to 0x%X\n", 
                   st->r_win_base););

        if (st->flags & TF_MISSING_PKT)
        {
            st->seglist_base_seq = st->gap_seq;
        }
        else
        {
            st->seglist_base_seq = st->r_win_base;
        }

        if(s5_global_config.flags & STREAM5_CONFIG_SHOW_PACKETS)
        {
            //ClearDumpBuf();
            printf("+++++++++++++++++++Stream Packet+++++++++++++++++++++\n");
            PrintIPPkt(stdout, IPPROTO_TCP, s5_pkt_6);
            printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
            //ClearDumpBuf();
        }

        s5stats.tcp_rebuilt_packets++; 

        PREPROC_PROFILE_TMPEND(s5TcpFlushPerfStats);
        {
            int event, tmp_do_detect, tmp_do_detect_content;
            PROFILE_VARS;
            
            PREPROC_PROFILE_START(s5TcpProcessRebuiltPerfStats);
            tmp_do_detect = do_detect;
            tmp_do_detect_content = do_detect_content;
            event = Preprocess(s5_pkt_6);
            do_detect = tmp_do_detect;
            do_detect_content = tmp_do_detect_content;
            PREPROC_PROFILE_END(s5TcpProcessRebuiltPerfStats);

            if(event)
            {
                //LogStream(s);
            }
        }
        PREPROC_PROFILE_TMPSTART(s5TcpFlushPerfStats);

        /* Reset alert tracking after flushing rebuilt packet */

        /* Remove the packets & alerts that are beyond the high-end of
         * those packets flushed */
        purge_to_seq(tcpssn, st, st->seglist_base_seq);

    } while (!(st->flags & TF_MISSING_PKT) && (st->seg_count > 1));

    /* Grab the next random flush point */
    //UpdateFlushMgr(&st->flush_mgr);

    /* tell them how many bytes we processed */
    PREPROC_PROFILE_END(s5TcpFlushPerfStats);
    return bytes_processed;
}
#endif /* SUP_IP6 */

/*
 * flush a seglist up to the last ack received, generate the pseudopacket
 * and fire it thru the system
 */
INLINE int flush_ackd(TcpSession *tcpssn, StreamTracker *st, Packet *p, 
        snort_ip_p sip, snort_ip_p dip, u_int16_t sp, u_int16_t dp, u_int32_t dir)
{
#ifndef SUP_IP6
    u_int32_t base_seq;
    u_int32_t footprint = 0;
    u_int16_t ip_len;
    int32_t flushed_bytes;
#endif
    u_int32_t bytes_processed = 0;
#ifndef SUP_IP6
    PROFILE_VARS;
#endif

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "In flush_ackd()\n"););

    if(st->seg_bytes_logical == 0)
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "bailing, no data\n"););
        return bytes_processed;
    }

    if(st->seglist == NULL || st->seglist_tail == NULL)
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "bailing, bad seglist ptr\n"););
        return bytes_processed;
    }

    if ((st->seg_count == 1) && !(st->flags & TF_FORCE_FLUSH))
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "only 1 packet in seglist no need to flush\n"););
        return bytes_processed;
    }

    //PrintSeglist(st);

#ifdef SUP_IP6
    if(sfip_family(sip) == AF_INET) 
    {
        return _flush_ackd_4(tcpssn, st, p, sip, dip, sp, dp, dir);
    }

    return _flush_ackd_6(tcpssn, st, p, sip, dip, sp, dp, dir);
    
#else
    PREPROC_PROFILE_START(s5TcpFlushPerfStats);

    ((IPHdr *)s5_pkt->iph)->ip_src.s_addr = sip;
    ((IPHdr *)s5_pkt->iph)->ip_dst.s_addr = dip;

    ((TCPHdr *)s5_pkt->tcph)->th_sport = sp;
    ((TCPHdr *)s5_pkt->tcph)->th_dport = dp;
    s5_pkt->sp = htons(sp);
    s5_pkt->dp = htons(dp);

    if(p->eh != NULL)
    {
        if (p->sp == s5_pkt->sp)
        {
            memcpy(((EtherHdr *)s5_pkt->eh)->ether_src, p->eh->ether_src, 6);
            memcpy(((EtherHdr *)s5_pkt->eh)->ether_dst, p->eh->ether_dst, 6);
        }
        else
        {
            memcpy(((EtherHdr *)s5_pkt->eh)->ether_src, p->eh->ether_dst, 6);
            memcpy(((EtherHdr *)s5_pkt->eh)->ether_dst, p->eh->ether_src, 6);
        }
    }

    ((TCPHdr *)s5_pkt->tcph)->th_seq = htonl(st->seglist_base_seq);
    ((TCPHdr *)s5_pkt->tcph)->th_ack = htonl(st->l_unackd);
    ((TCPHdr *)s5_pkt->tcph)->th_win = htons(st->l_window);

    do
    {
        base_seq = st->seglist_base_seq; 

        footprint = st->r_win_base - base_seq;

        if(footprint <= 0) 
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "Negative footprint, bailing %d (0x%X - 0x%X)\n", 
                        footprint, st->r_win_base, base_seq););
            PREPROC_PROFILE_END(s5TcpFlushPerfStats);

            return bytes_processed;
        }

        if(footprint < st->seg_bytes_logical)
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "Footprint less than queued bytes, "
                        "win_base: 0x%X base_seq: 0x%X\n", 
                        st->r_win_base, base_seq););
        }

        if(footprint > STREAM_MAX_PACKET)
        {
            /* this is as much as we can pack into a stream buffer */
            footprint = STREAM_MAX_PACKET;
        }

        /* setup the pseudopacket payload */
        flushed_bytes = FlushStream(st, /* p, */ (u_int8_t *)s5_pkt->data, (int) footprint);

        if(flushed_bytes == -1)
        {
            /* couldn't put a stream together for whatever reason
             * should probably clean the seglist and bail...
             */
            if(st->seglist)
            {
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "dumping entire seglist!\n"););

                DeleteSeglist(st->seglist);
                st->seglist_tail = NULL;
            }

            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                       "setting st->seglist_base_seq to 0x%X\n", 
                       st->r_win_base););
            st->seglist_base_seq = st->r_win_base;

            PREPROC_PROFILE_END(s5TcpFlushPerfStats);
            return bytes_processed;
        }

        if (flushed_bytes == 0)
        {
            /* No more ACK'd data... bail */
            break;
        }

        s5_pkt->dsize = (u_int16_t)flushed_bytes;

        ((struct pcap_pkthdr *)s5_pkt->pkth)->caplen = s5_pkt->dsize + IP_HEADER_LEN + 
            TCP_HEADER_LEN + ETHERNET_HEADER_LEN;
        ((struct pcap_pkthdr *)s5_pkt->pkth)->len = s5_pkt->pkth->caplen;

        ((struct pcap_pkthdr *)s5_pkt->pkth)->ts.tv_sec = st->seglist->pkth.ts.tv_sec;
        ((struct pcap_pkthdr *)s5_pkt->pkth)->ts.tv_usec = st->seglist->pkth.ts.tv_usec;

        ip_len = (u_int16_t)(s5_pkt->dsize + IP_HEADER_LEN + TCP_HEADER_LEN);
        ((IPHdr *)s5_pkt->iph)->ip_len = htons(ip_len);

        sfPerf.sfBase.iStreamFlushes++;

        bytes_processed += s5_pkt->dsize;

        s5_pkt->packet_flags = (PKT_REBUILT_STREAM|PKT_STREAM_EST);
        s5_pkt->packet_flags |= dir;
        s5_pkt->ssnptr = (void *) tcpssn->lwssn;
        //s5_pkt->streamptr = (void *) st;
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                   "setting st->seglist_base_seq to 0x%X\n", 
                   st->r_win_base););

        if (st->flags & TF_MISSING_PKT)
        {
            st->seglist_base_seq = st->gap_seq;
        }
        else
        {
            st->seglist_base_seq = st->r_win_base;
        }

        if(s5_global_config.flags & STREAM5_CONFIG_SHOW_PACKETS)
        {
            //ClearDumpBuf();
            printf("+++++++++++++++++++Stream Packet+++++++++++++++++++++\n");
            PrintIPPkt(stdout, IPPROTO_TCP, s5_pkt);
            printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
            //ClearDumpBuf();
        }

        s5stats.tcp_rebuilt_packets++; 

        PREPROC_PROFILE_TMPEND(s5TcpFlushPerfStats);
        {
            int event, tmp_do_detect, tmp_do_detect_content;
            PROFILE_VARS;
            
            PREPROC_PROFILE_START(s5TcpProcessRebuiltPerfStats);
            tmp_do_detect = do_detect;
            tmp_do_detect_content = do_detect_content;
            event = Preprocess(s5_pkt);
            do_detect = tmp_do_detect;
            do_detect_content = tmp_do_detect_content;
            PREPROC_PROFILE_END(s5TcpProcessRebuiltPerfStats);

            if(event)
            {
                //LogStream(s);
            }
        }
        PREPROC_PROFILE_TMPSTART(s5TcpFlushPerfStats);

        /* Reset alert tracking after flushing rebuilt packet */

        /* Remove the packets & alerts that are prior to the high-end of
         * those packets flushed */
        purge_to_seq(tcpssn, st, st->seglist_base_seq);

    } while (!(st->flags & TF_MISSING_PKT) && (st->seg_count > 1));

    /* Grab the next random flush point */
    //UpdateFlushMgr(&st->flush_mgr);

    /* tell them how many bytes we processed */
    PREPROC_PROFILE_END(s5TcpFlushPerfStats);
    return bytes_processed;
#endif
}

/*
 * flush the client seglist up to the most recently acked segment
 */
static int FlushStream(StreamTracker *st, /* Packet *p, */ u_int8_t *flushbuf, 
        int size)
{
    StreamSegment *ss = NULL;
    u_int32_t base_seq = st->seglist->seq;
    u_int16_t bytes_flushed = 0;
    u_int32_t bytes_queued = st->seg_bytes_logical;
    u_int32_t last = 0;
    u_int32_t last_seq = 0;
    u_int32_t segs = 0;
    const u_int8_t *flushbuf_end;
    int ret;
    PROFILE_VARS;

    if(st->seg_count == 0 || st->seglist == NULL || st->seglist_tail == NULL)
        return -1;

    /*
     * since this is going into a pseudopacket the size can't ever be more than 
     * 65495 (MAXPACKET - IP_HDRLEN - TCP_HDRLEN), bail if it is
     */
    if(size > STREAM_MAX_PACKET)
        return -1;

    PREPROC_PROFILE_START(s5TcpBuildPacketPerfStats);


    flushbuf_end = flushbuf + STREAM_MAX_PACKET;

#ifdef DEBUG_STREAM5
    for(ss = st->seglist; ss; ss = ss->next)
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "seq: 0x%X  offset: %d  size: %d delta: %d\n", ss->seq, 
                    ss->seq-base_seq, ss->size, (ss->seq-base_seq) - last););
        last = ss->seq-base_seq;
        segs++;
    }
    /* Uh, need to reset these here */
    segs = 0;
    last = 0;
#endif

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "flushing %lu bytes\n", size););

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Flushing stream, starting seq %X, r_win_base: %X "
                "base_seq: %X st->seglist: %p st->seglist->seq: %X\n", 
                base_seq, st->r_win_base, base_seq, st->seglist, st->seglist->seq););

    st->flags &= ~TF_MISSING_PKT;
    st->flags &= ~TF_MISSING_PREV_PKT;
    st->gap_seq = 0;

    if (st->seglist_base_seq < st->seglist->seq)
        st->flags |= TF_MISSING_PREV_PKT;

    for(ss = st->seglist; ss && SEQ_LT(ss->seq,  st->r_win_base); ss = ss->next)
    {
        u_int16_t bytes_to_copy = ss->size;

        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "seq: 0x%X  offset: %d  size: %d\n", ss->seq, 
                    ss->seq-base_seq, ss->size););

        /* Check for a gap/missing packet */
        if ((ss->next && (ss->seq + ss->size != ss->next->seq)) ||
            (!ss->next && (ss->seq + ss->size < st->r_win_base)))
        {
            st->flags |= TF_MISSING_PKT;
            st->flags |= TF_PKT_MISSED;

            if (ss->next)
                st->gap_seq = ss->next->seq;
            else
                st->gap_seq = st->r_win_base;
        }

        if(ss->urg_offset)
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "s: %p e: %p dlt: %lu off: %d d: %p sz: %d\n", 
                        flushbuf, flushbuf_end, flushbuf_end - flushbuf, 
                        ss->seq-base_seq, ss->payload, ss->size););

            /*
             * have to hop over the byte pointed to by the urg ptr
             *
             * TODO fix this to not copy in the URG pointer data.  Need
             * a few PCAPs to test with.  Need to track urg_pointer
             * offsets to adjust true seq to correct value, sans UrgP
             * data.
             */
            ret = SafeMemcpy(flushbuf+(ss->seq-base_seq), ss->payload, 
                             ss->urg_offset-1, flushbuf, flushbuf_end);

            if (ret == SAFEMEM_ERROR)
            {
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "ERROR writing flushbuf attempting to "
                        "write flushbuf out of range!\n"););
            }

            ret = SafeMemcpy(flushbuf+(ss->seq-base_seq+(u_int32_t)ss->urg_offset),
                             ss->payload+ss->urg_offset+1, ss->size-ss->urg_offset, 
                             flushbuf, flushbuf_end);

            if (ret == SAFEMEM_ERROR)
            {
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "ERROR writing flushbuf attempting to "
                        "write flushbuf out of range!\n"););
            }

            last = ss->size - 1;
        }
        else
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "s: %p e: %p dlt: %lu off: %d d: %p sz: %d\n", 
                        flushbuf, flushbuf_end, flushbuf_end - flushbuf, 
                        ss->seq-base_seq, ss->payload, ss->size););

            if (SEQ_GT(ss->seq + bytes_to_copy, st->r_win_base))
                bytes_to_copy = st->r_win_base - ss->seq;

            ret = SafeMemcpy(flushbuf+(ss->seq-base_seq), ss->payload, 
                             bytes_to_copy, flushbuf, flushbuf_end);

            if (ret == SAFEMEM_ERROR)
            {
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "ERROR writing flushbuf attempting to "
                            "write flushbuf out of range!\n"););
            }

            last = bytes_to_copy;
        }

        last_seq = ss->seq;
        if (bytes_to_copy < ss->size) 
        {
            bytes_flushed += bytes_to_copy;
            ss->seq = st->r_win_base;
            ss->size -= bytes_to_copy;
            ss->payload += bytes_to_copy;
        }
        else
        {
            bytes_flushed += ss->size;
            ss->buffered = 1;
        }
        segs++;

        /* Was there a gap following this segment? */
        if (st->flags & TF_MISSING_PKT)
            break;

        if(((ss->seq - base_seq) + ss->size) > (u_int32_t)(flushbuf_end - flushbuf))
            break;
    }

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "flushed %d bytes on session (%lu)!\n", bytes_flushed,
                last_seq - base_seq + last););

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"););

#ifdef DEBUG
//    PrintHexDump(flushbuf, (last_seq - base_seq) + last, stdout);
#endif

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"););

    bytes_queued -= bytes_flushed;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "flushed %d bytes on stream, %d still queued, "
                "%d segs flushed\n", 
                bytes_flushed, bytes_queued, segs););

    //return (last_seq - base_seq) + last;
    PREPROC_PROFILE_END(s5TcpBuildPacketPerfStats);
    return bytes_flushed;
}

int Stream5FlushServer(Packet *p, Stream5LWSession *lwssn)
{
    int flushed;
    TcpSession *tcpssn = NULL;
    StreamTracker *flushTracker = NULL;

    if (lwssn->proto_specific_data)
        tcpssn = (TcpSession *)lwssn->proto_specific_data->data;

    if (!tcpssn)
        return 0;

    flushTracker = &tcpssn->server;

    flushTracker->flags |= TF_FORCE_FLUSH;

    /* If this is a rebuilt packet, don't flush now because we'll
     * overwrite the packet being processed.
     */
    if (p->packet_flags & PKT_REBUILT_STREAM)
    {
        /* We'll check & clear the TF_FORCE_FLUSH next time through */
        return 0;
    }

    /* Need to convert the addresses to network order */
    flushed = flush_ackd(tcpssn, flushTracker, p,
#ifdef SUP_IP6
                            &tcpssn->tcp_server_ip,
                            &tcpssn->tcp_client_ip,
#else
                            tcpssn->tcp_server_ip,
                            tcpssn->tcp_client_ip,
#endif
                            tcpssn->tcp_server_port,
                            tcpssn->tcp_client_port,
                            PKT_FROM_SERVER);
    if (flushed)
        purge_ackd(tcpssn, flushTracker);

    flushTracker->flags &= ~TF_FORCE_FLUSH;

    return flushed;
}

int Stream5FlushClient(Packet *p, Stream5LWSession *lwssn)
{
    int flushed;
    TcpSession *tcpssn = NULL;
    StreamTracker *flushTracker = NULL;
   
    if (lwssn->proto_specific_data)
        tcpssn = (TcpSession *)lwssn->proto_specific_data->data;

    if (!tcpssn)
        return 0;

    flushTracker = &tcpssn->client;

    flushTracker->flags |= TF_FORCE_FLUSH;

    /* If this is a rebuilt packet, don't flush now because we'll
     * overwrite the packet being processed.
     */
    if (p->packet_flags & PKT_REBUILT_STREAM)
    {
        /* We'll check & clear the TF_FORCE_FLUSH next time through */
        return 0;
    }

    /* Need to convert the addresses to network order */
    flushed = flush_ackd(tcpssn, flushTracker, p,
#ifdef SUP_IP6
                            &tcpssn->tcp_client_ip,
                            &tcpssn->tcp_server_ip,
#else
                            tcpssn->tcp_client_ip,
                            tcpssn->tcp_server_ip,
#endif
                            tcpssn->tcp_client_port,
                            tcpssn->tcp_server_port,
                            PKT_FROM_CLIENT);
    if (flushed)
        purge_ackd(tcpssn, flushTracker);

    flushTracker->flags &= ~TF_FORCE_FLUSH;

    return flushed;
}

int Stream5FlushListener(Packet *p, Stream5LWSession *lwssn)
{
    TcpSession *tcpssn = NULL;
    StreamTracker *listener = NULL;
    int dir = 0;
    int flushed = 0;

    if (lwssn->proto_specific_data)
        tcpssn = (TcpSession *)lwssn->proto_specific_data->data;

    if (!tcpssn)
        return 0;

    /* figure out direction of this packet -- we should've already
     * looked at it, so the packet_flags are already set. */
    if(p->packet_flags & PKT_FROM_SERVER)
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Flushing listener on packet from server\n"););
        listener = &tcpssn->client;
        /* dir of flush is the data from the opposite side */
        dir = PKT_FROM_SERVER;
    }
    else if (p->packet_flags & PKT_FROM_CLIENT)
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Flushing listener on packet from client\n"););
        listener = &tcpssn->server;
        /* dir of flush is the data from the opposite side */
        dir = PKT_FROM_CLIENT;
    }

    if (dir != 0)
    {
        listener->flags |= TF_FORCE_FLUSH;
        flushed = flush_ackd(tcpssn, listener, p,
                            GET_SRC_IP(p), GET_DST_IP(p),
                            p->tcph->th_sport, p->tcph->th_dport, dir);
        if (flushed)
            purge_ackd(tcpssn, listener);
        listener->flags &= ~TF_FORCE_FLUSH;
    }

    return flushed;
}

int Stream5FlushTalker(Packet *p, Stream5LWSession *lwssn)
{
    TcpSession *tcpssn = NULL;
    StreamTracker *talker = NULL;
    int dir = 0;
    int flushed = 0;

    if (lwssn->proto_specific_data)
        tcpssn = (TcpSession *)lwssn->proto_specific_data->data;

    if (!tcpssn)
    {
        return 0;
    }

    /* figure out direction of this packet -- we should've already
     * looked at it, so the packet_flags are already set. */
    if(p->packet_flags & PKT_FROM_SERVER)
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Flushing talker on packet from server\n"););
        talker = &tcpssn->server;
        /* dir of flush is the data from the opposite side */
        dir = PKT_FROM_CLIENT;
    }
    else if (p->packet_flags & PKT_FROM_CLIENT)
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Flushing talker on packet from client\n"););
        talker = &tcpssn->client;
        /* dir of flush is the data from the opposite side */
        dir = PKT_FROM_SERVER;
    }

    if (dir != 0)
    {
        talker->flags |= TF_FORCE_FLUSH;
        flushed = flush_ackd(tcpssn, talker, p,
                            GET_DST_IP(p), GET_SRC_IP(p),
                            p->tcph->th_dport, p->tcph->th_sport, dir);
        if (flushed)
            purge_ackd(tcpssn, talker);

        talker->flags &= ~TF_FORCE_FLUSH;
    }

    return flushed;
}

Stream5LWSession *GetLWTcpSession(SessionKey *key)
{
    return GetLWSessionFromKey(tcp_lws_cache, key);
}

void TcpSessionCleanup(Stream5LWSession *lwssn)
{
    struct pcap_pkthdr tmp_pcap_hdr;
    TcpSession *tcpssn = NULL;
    if (lwssn->proto_specific_data)
        tcpssn = (TcpSession *)lwssn->proto_specific_data->data;

    if (!tcpssn)
    {
        /* Huh? */
        Stream5UpdatePerfBaseState(&sfPerf.sfBase, lwssn, TCP_STATE_CLOSED);
        return;
    }

    /* Flush ack'd data on both sides as necessary */
    {
        Packet p;
        int flushed;
        DecoderFlags decoder_flags;

        if (!s5_tcp_cleanup)
        {
            /* Turn off decoder alerts since we're decoding stored
             * packets that we already alerted on.
             */
            memcpy(&decoder_flags, &pv.decoder_flags, sizeof(DecoderFlags));
            memset(&pv.decoder_flags, 0, sizeof(DecoderFlags));
        }

        /* Flush the client */
        if (tcpssn->client.seglist)
        {
            pc.s5tcp1++;
            /* Do each field individually because of size differences on 64bit OS */
            tmp_pcap_hdr.ts.tv_sec = tcpssn->client.seglist->pkth.ts.tv_sec;
            tmp_pcap_hdr.ts.tv_usec = tcpssn->client.seglist->pkth.ts.tv_usec;
            tmp_pcap_hdr.caplen = tcpssn->client.seglist->pkth.caplen;
            tmp_pcap_hdr.len = tcpssn->client.seglist->pkth.len;
            (*grinder)(&p, &tmp_pcap_hdr,
                       tcpssn->client.seglist->pktOrig + SPARC_TWIDDLE);
            p.ssnptr = lwssn;

            tcpssn->client.flags |= TF_FORCE_FLUSH;

#ifdef SUP_IP6
            if(p.family == AF_INET) 
            {
                pc.tcp--;
            } 
            else
            {
                pc.tcp6--;
            }
            flushed = flush_ackd(tcpssn, &tcpssn->client, &p,
                            p.iph_api.iph_ret_src(&p), p.iph_api.iph_ret_dst(&p), 
                            p.tcph->th_sport, p.tcph->th_dport,
                            PKT_FROM_SERVER);
#else
            pc.tcp--;
            flushed = flush_ackd(tcpssn, &tcpssn->client, &p,
                            p.iph->ip_src.s_addr, p.iph->ip_dst.s_addr,
                            p.tcph->th_sport, p.tcph->th_dport,
                            PKT_FROM_SERVER);
#endif
            if (flushed)
                purge_ackd(tcpssn, &tcpssn->client);

            tcpssn->client.flags &= ~TF_FORCE_FLUSH;
        }

        /* Flush the server */
        if (tcpssn->server.seglist)
        {
            pc.s5tcp2++;
            /* Do each field individually because of size differences on 64bit OS */
            tmp_pcap_hdr.ts.tv_sec = tcpssn->server.seglist->pkth.ts.tv_sec;
            tmp_pcap_hdr.ts.tv_usec = tcpssn->server.seglist->pkth.ts.tv_usec;
            tmp_pcap_hdr.caplen = tcpssn->server.seglist->pkth.caplen;
            tmp_pcap_hdr.len = tcpssn->server.seglist->pkth.len;
            (*grinder)(&p, &tmp_pcap_hdr,
                       tcpssn->server.seglist->pktOrig + SPARC_TWIDDLE);
            p.ssnptr = lwssn;

            tcpssn->server.flags |= TF_FORCE_FLUSH;
#ifdef SUP_IP6
            if(p.family == AF_INET) 
            {
                pc.tcp--;
            } 
            else
            {
                pc.tcp6--;
            }

            flushed = flush_ackd(tcpssn, &tcpssn->server, &p,
                            p.iph_api.iph_ret_src(&p), p.iph_api.iph_ret_dst(&p), 
                            p.tcph->th_sport, p.tcph->th_dport,
                            PKT_FROM_CLIENT);
#else
            pc.tcp--;
            flushed = flush_ackd(tcpssn, &tcpssn->server, &p,
                            p.iph->ip_src.s_addr, p.iph->ip_dst.s_addr,
                            p.tcph->th_sport, p.tcph->th_dport,
                            PKT_FROM_CLIENT);
#endif
            if (flushed)
                purge_ackd(tcpssn, &tcpssn->server);

            tcpssn->server.flags &= ~TF_FORCE_FLUSH;
        }

        if (!s5_tcp_cleanup)
        {
            /* And turn decoder alerts back on (or whatever they were set to) */
            memcpy(&pv.decoder_flags, &decoder_flags, sizeof(DecoderFlags));
        }
    }

    /* Purge the sequence lists */
    STREAM5_DEBUG_WRAP( DebugMessage(DEBUG_STREAM_STATE,  
                "In TcpSessionCleanup, %lu bytes in use\n", s5_global_config.mem_in_use););
    STREAM5_DEBUG_WRAP( DebugMessage(DEBUG_STREAM_STATE,  
                "client has %d segs queued\n", tcpssn->client.seg_count););
    DeleteSeglist(tcpssn->client.seglist);
    tcpssn->client.seglist_tail = NULL;
    STREAM5_DEBUG_WRAP( DebugMessage(DEBUG_STREAM_STATE,  
                "server has %d segs queued\n", tcpssn->server.seg_count););
    DeleteSeglist(tcpssn->server.seglist);
    tcpssn->server.seglist_tail = NULL;

    STREAM5_DEBUG_WRAP( DebugMessage(DEBUG_STREAM_STATE,  
                "After cleaning, %lu bytes in use\n", s5_global_config.mem_in_use););

    Stream5UpdatePerfBaseState(&sfPerf.sfBase, tcpssn->lwssn, TCP_STATE_CLOSED);
    if (lwssn->session_flags & SSNFLAG_PRUNED)
    {
        CloseStreamSession(&sfPerf.sfBase, SESSION_CLOSED_PRUNED);
    }
    else if (lwssn->session_flags & SSNFLAG_TIMEDOUT)
    {
        CloseStreamSession(&sfPerf.sfBase, SESSION_CLOSED_TIMEDOUT);
    }
    else
    {
        CloseStreamSession(&sfPerf.sfBase, SESSION_CLOSED_NORMALLY);
    }

    /* Cleanup the proto specific data */
    mempool_free(&tcp_session_mempool, lwssn->proto_specific_data);
    lwssn->proto_specific_data = NULL;
    lwssn->session_flags = SSNFLAG_NONE;
    lwssn->session_state = STREAM5_STATE_NONE;
    lwssn->expire_time = 0;
    lwssn->ignore_direction = 0;

    FreeLWApplicationData(lwssn);

    s5stats.tcp_streamtrackers_released++;
    RemoveStreamSession(&sfPerf.sfBase);
}

#ifdef SUP_IP6
Stream5TcpPolicy *Stream5PolicyLookup(sfip_t *ip)
#else
Stream5TcpPolicy *Stream5PolicyLookup(struct in_addr ip)
#endif
{
    int policyIndex;
    Stream5TcpPolicy *policy = NULL;

    for (policyIndex = 0; policyIndex < numTcpPolicies; policyIndex++)
    {
        policy = tcpPolicyList[policyIndex];

        /*
         * Does this policy handle packets to this IP address?
         */
#ifdef SUP_IP6
        if(sfvar_ip_in(policy->bound_addrs, ip))
#else
        if(IpAddrSetContains(policy->bound_addrs, ip))
#endif
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                "[Stream5] Found tcp policy in IpAddrSet\n"););
            break;
        }
        else
        {
            policy = NULL;
        }
    }

    return policy;
}

/*
 * Main entry point for TCP
 */
int Stream5ProcessTcp(Packet *p)
{
    Stream5TcpPolicy *s5TcpPolicy = NULL;
    SessionKey skey;
    TcpDataBlock tdb;
    Stream5LWSession *lwssn = NULL;
    PROFILE_VARS;

    STREAM5_DEBUG_WRAP(
            char flagbuf[9];
            CreateTCPFlagString(p, flagbuf);
            DebugMessage((DEBUG_STREAM|DEBUG_STREAM_STATE),
                "Got TCP Packet 0x%X:%d ->  0x%X:%d %s\nseq: 0x%X   ack:0x%X  "
                "dsize: %lu\n"
                "active sessions: %lu\n",
                GET_SRC_IP(p),
                p->sp,
                GET_DST_IP(p),
                p->dp,
                flagbuf,
                ntohl(p->tcph->th_seq), ntohl(p->tcph->th_ack), p->dsize,
                sfxhash_count(tcp_lws_cache->hashTable));
            );

    PREPROC_PROFILE_START(s5TcpPerfStats);

    memset(&tdb, 0, sizeof(TcpDataBlock));
    SetupTcpDataBlock(&tdb, p);

#ifdef DEBUG_STREAM5
    PrintTcpDataBlock(&tdb);
#endif

    /* Find an Tcp policy for this packet */
#ifdef SUP_IP6
    s5TcpPolicy = Stream5PolicyLookup(GET_DST_IP(p));
#else
    s5TcpPolicy = Stream5PolicyLookup(p->iph->ip_dst);
#endif

    if (!s5TcpPolicy)
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM, 
                    "[Stream5] Could not find Tcp Policy context "
                    "for IP %s\n", inet_ntoa(GET_DST_ADDR(p))););
        PREPROC_PROFILE_END(s5TcpPerfStats);
        return 0;
    }

    if ((lwssn = GetLWSession(tcp_lws_cache, p, &skey)) == NULL)
    {
        /* if require 3WHS, create Lightweight Session on SYN */
        if (s5TcpPolicy->flags & STREAM5_CONFIG_REQUIRE_3WHS)
        {
            if (p->tcph->th_flags == TH_SYN)
            {
                /* SYN only */
                lwssn = NewLWSession(tcp_lws_cache, p, &skey);
                lwssn->session_state = STREAM5_STATE_SYN;
                s5stats.total_tcp_sessions++;
            }
            else
            {
                /* If we're within the "startup" window, try to handle
                 * this packet as midstream pickup -- allows for
                 * connections that already existed before snort started.
                 */
                if (p->pkth->ts.tv_sec - firstPacketTime < s5TcpPolicy->hs_timeout)
                {
                    midstream_allowed = 1;
                    goto midstream_pickup_allowed;
                }
                else
                {
                    midstream_allowed = 0;
                }

                /* TODO: maybe look at drop stats before printing this
                 * warning -- or make this a configurable alert when
                 * requiring 3WAY. */
                DEBUG_WRAP(
                    DebugMessage(DEBUG_STREAM_STATE, "Stream5: Requiring 3-way "
                        "Handshake, but failed to retrieve session object "
                        "for non SYN packet.  Dropped SYN or hacker?\n"););

                /* 
                 * Do nothing with this packet since we require a 3-way.
                 * Wow that just sounds cool... Require a 3-way.  Hehe.
                 */
                return 0;
            }
        }
        else
        {
midstream_pickup_allowed:
            if (p->tcph->th_flags == (TH_SYN|TH_ACK))
            {
                /* If we have a SYN/ACK */
                lwssn = NewLWSession(tcp_lws_cache, p, &skey);
                s5stats.total_tcp_sessions++;
            }
            else if (p->dsize > 0)
            {
                /* If we have data -- missed the SYN/ACK
                 * somehow -- maybe just an incomplete PCAP.  */
                /* This handles data on SYN situations */
                lwssn = NewLWSession(tcp_lws_cache, p, &skey);
                s5stats.total_tcp_sessions++;
            }
            else if ((Stream5PacketHasWscale(p) & TF_WSCALE) &&
                     (p->tcph->th_flags == TH_SYN))
            {
                /* If we have a wscale option, need to save the
                 * option if its the first SYN from client. */
                lwssn = NewLWSession(tcp_lws_cache, p, &skey);
                s5stats.total_tcp_sessions++;
            }
            else
            {
                /* No data, no need to create session yet */
                /* This is done to handle SYN flood DoS attacks */
#ifdef DEBUG
                    if (p->tcph->th_flags == TH_SYN)
                    {
                        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "Stream5: no data in packet (SYN only), no need to"
                            "create lightweight session.\n"););
                    }
                    else
                    {
                        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "Stream5: no data in packet (non SYN/keep alive "
                            "ACK?), no need to create lightweight session.\n"););
                    }
#endif

                PREPROC_PROFILE_END(s5TcpPerfStats);
                return 0;
            }
        }
    }
    else
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Stream5: Retrieved existing session object.\n"););
    }

    if (!lwssn)
    {
        LogMessage("Stream5: Failed to retrieve session object.  Out of memory?\n");
        PREPROC_PROFILE_END(s5TcpPerfStats);
        return -1;
    }

    p->ssnptr = lwssn;

    /*
     * Check if the session is expired.
     * Should be done before we do something with the packet...
     * ie, Insert a packet, or handle state change SYN, FIN, RST, etc.
     */
    if ((lwssn->session_state & STREAM5_STATE_TIMEDOUT) ||
        Stream5Expire(p, lwssn))
    {
        lwssn->session_flags |= SSNFLAG_TIMEDOUT;
        /* Session is timed out */
        if (lwssn->session_flags & SSNFLAG_RESET)
        {
            /* If this one has been reset, delete the TCP
             * portion, and start a new. */
            TcpSessionCleanup(lwssn);

            ProcessTcp(lwssn, p, &tdb, s5TcpPolicy);

            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Finished Stream5 TCP cleanly!\n"
                    "---------------------------------------------------\n"););
        }
        else
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Stream5 TCP session timedout!\n"););

            /* Not reset, simply time'd out.  Clean it up */
            TcpSessionCleanup(lwssn);

            ProcessTcp(lwssn, p, &tdb, s5TcpPolicy);
        }
    }
    else
    {
        ProcessTcp(lwssn, p, &tdb, s5TcpPolicy);
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Finished Stream5 TCP cleanly!\n"
                    "---------------------------------------------------\n"););
    }
    MarkupPacketFlags(p, lwssn);
    Stream5SetExpire(p, lwssn, s5TcpPolicy->session_timeout);

    PREPROC_PROFILE_END(s5TcpPerfStats);
    return 0;
}

static u_int32_t Stream5GetTcpTimestamp(Packet *p, u_int32_t *ts)
{
    unsigned int i = 0;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Getting timestamp...\n"););
    while(i < p->tcp_option_count && i < TCP_OPTLENMAX)
    {
        if(p->tcp_options[i].code == TCPOPT_TIMESTAMP)
        {
            *ts = EXTRACT_32BITS(p->tcp_options[i].data);
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "Found timestamp %lu\n", *ts););
            return TF_TSTAMP;
        }

        i++;
    }

    *ts = 0;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "No timestamp...\n"););

    return TF_NONE;
}

static u_int32_t Stream5GetMss(Packet *p, u_int16_t *value)
{
    unsigned int i = 0;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Getting MSS...\n"););
    while(i < p->tcp_option_count && i < TCP_OPTLENMAX)
    {
        if(p->tcp_options[i].code == TCPOPT_MAXSEG)
        {
            *value = EXTRACT_16BITS(p->tcp_options[i].data);
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "Found MSS %u\n", *value););
            return TF_MSS;
        }

        i++;
    }

    *value = 0;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "No MSS...\n"););
    return TF_NONE;
}

static u_int32_t Stream5GetWscale(Packet *p, u_int16_t *value)
{
    unsigned int i = 0;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Getting wscale...\n"););
    while(i < p->tcp_option_count && i < TCP_OPTLENMAX)
    {
        if(p->tcp_options[i].code == TCPOPT_WSCALE)
        {
            *value = (u_int16_t) p->tcp_options[i].data[0];
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "Found wscale %d\n", *value););

            /* If scale specified in option is larger than 14,
             * use 14 because of limitation in the math of
             * shifting a 32bit value (max scaled window is 2^30th).
             *
             * See RFC 1323 for details.
             */
            if (*value > 14)
            {
                *value = 14;
            }

            return TF_WSCALE;
        }

        i++;
    }

    *value = 0;
    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "No wscale...\n"););
    return TF_NONE;
}

static u_int32_t Stream5PacketHasWscale(Packet *p)
{
    u_int16_t wscale;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Checking for wscale...\n"););
    return Stream5GetWscale(p, &wscale);
}

static INLINE int IsWellFormed(Packet *p, StreamTracker *ts)
{
    if(GET_IPH_TTL(p) == ts->ttl && p->dsize <= ts->mss)
        return 1;

    return 0;
}

static void FinishServerInit(Packet *p, TcpDataBlock *tdb, TcpSession *ssn)
{
    StreamTracker *server;
    StreamTracker *client;

    if (!ssn)
    {
        return;
    }

    server = &ssn->server;
    client = &ssn->client;

    server->l_window = tdb->win;              /* set initial server window */
    server->l_unackd = tdb->seq + 1;
    server->l_nxt_seq = server->l_unackd + 1;
    server->isn = tdb->seq;
    server->ttl = GET_IPH_TTL(p);

    client->r_nxt_ack = tdb->end_seq;
    client->r_win_base = tdb->end_seq;
    client->seglist_base_seq = server->l_unackd;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
               "seglist_base_seq = %X\n", client->seglist_base_seq););
    if (!(ssn->lwssn->session_state & STREAM5_STATE_MIDSTREAM))
        server->s_mgr.state = TCP_STATE_SYN_RCVD;

    server->flags |= Stream5GetTcpTimestamp(p, &server->ts_last);
    if (server->ts_last == 0)
        server->flags |= TF_TSTAMP_ZERO;
    else
        server->ts_last_pkt = p->pkth->ts.tv_sec;
    server->flags |= Stream5GetMss(p, &server->mss);
    server->flags |= Stream5GetWscale(p, &server->wscale);

#ifdef DEBUG_STREAM5
    PrintTcpSession(ssn);
#endif
}

#ifdef OLD_CODE_NOLONGER_USED_DEPENDS_ON_CURRENT_STATE
static INLINE void QueueState(u_int8_t transition, StreamTracker *st,
        u_int8_t expected_flags, u_int32_t seq_num, u_int8_t get_seq)
{
    StateMgr *smgr = &st->s_mgr;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "[^^] Queing transition to %s, flag 0x%X, seq: 0x%X\n",
                state_names[transition], expected_flags, seq_num););

    smgr->state_queue = transition;
    smgr->expected_flags = expected_flags;
    smgr->stq_get_seq = get_seq;
    smgr->transition_seq = seq_num;

#ifdef DEBUG_STREAM5
    PrintStateMgr(smgr);
#endif
    return;
}

static INLINE int EvalStateQueue(StreamTracker *sptr, u_int8_t flags, 
        u_int32_t ack)
{
    StateMgr *smgr = &sptr->s_mgr;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                "Evaluating state queue!\n"););
    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                "StreamTracker %p, flags 0x%X ack: 0x%X\n", sptr, flags, ack);
            PrintStateMgr(smgr););

    if(smgr->expected_flags != 0)
    {
        if((flags & smgr->expected_flags) != 0)
        {
            if(smgr->stq_get_seq && (SEQ_GEQ(ack, smgr->transition_seq)))
            {

                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "[^^] Accepting %s state transition\n",
                            state_names[smgr->state_queue]););
                smgr->state = smgr->state_queue;
                smgr->expected_flags = 0;
                smgr->transition_seq = 0;
                return 1;
            }
            else if(!smgr->stq_get_seq)
            {
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "[^^] Accepting %s state transition\n",
                            state_names[smgr->state_queue]););
                smgr->state = smgr->state_queue;
                smgr->expected_flags = 0;
                smgr->transition_seq = 0;
                return 1;

            }
            else
            {
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "[!!] sptr->stq_get_seq: %d  "
                            "[ack: 0x%X expected: 0x%X]\n", smgr->stq_get_seq,
                            ack, smgr->transition_seq););
            }
        }
        else
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "[!!] flags: 0x%X  expected: 0x%X, bitwise: 0x%X\n",
                        flags, smgr->expected_flags,
                        (flags & smgr->expected_flags)););
        }
    }
    else
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "No transition queued, returning\n"););
    }

    return 0;
}
#endif

/*
 * get the footprint for the current seglist, the difference
 * between our base sequence and the last ack'd sequence we
 * received
 */
INLINE u_int32_t get_q_footprint(StreamTracker *st)
{
    u_int32_t fp;

    if (st == NULL)
    {
        return 0;
    }

    fp = st->r_win_base - st->seglist_base_seq;

    if(fp <= 0)
        return 0;

    return fp;
}

static INLINE int IgnoreLargePkt(StreamTracker *st, Packet *p, TcpDataBlock *tdb)
{
    if((st->flush_mgr.flush_policy == STREAM_FLPOLICY_FOOTPRINT) &&
       (st->tcp_policy->flags & STREAM5_CONFIG_PERFORMANCE))
    {
        if ((p->dsize > st->flush_mgr.flush_pt * 2) &&
            (st->seg_count == 0))
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "WARNING: Data larger than twice flushpoint.  Not "
                "inserting for reassembly: seq: %d, size %d!\n"
                "This is a tradeoff of performance versus the remote "
                "possibility of catching an exploit that spans two or "
                "more consecuvitve large packets.\n",
                tdb->seq, p->dsize););
            return 1;
        }
    }
    return 0;
}

static void NewQueue(StreamTracker *st, Packet *p, TcpDataBlock *tdb, TcpSession *tcpssn)
{
    StreamSegment *ss = NULL;
    u_int32_t overlap = 0;
    PROFILE_VARS;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "In NewQueue\n"););
    
    PREPROC_PROFILE_START(s5TcpInsertPerfStats);

    if(st->flush_mgr.flush_policy != STREAM_FLPOLICY_IGNORE)
    {
        /* Check if we should not insert a large packet */
        if (IgnoreLargePkt(st, p, tdb))
        {
            return;
        }

        /* new packet seq is below the last ack... */
        if(SEQ_GT(st->seglist_base_seq, tdb->seq))
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "segment overlaps ack'd data...\n"););
            overlap = st->seglist_base_seq - tdb->seq;
            if(overlap >= p->dsize) 
            {
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "full overlap on ack'd data, dropping segment\n"););
                PREPROC_PROFILE_END(s5TcpInsertPerfStats);
                return;
            }
        }

        AddStreamNode(st, p, tdb->ts, tcpssn, p->dsize, 0, 0, tdb->seq, NULL, &ss);

        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Attached new queue to seglist, %d bytes queued, "
                    "base_seq 0x%X\n", 
                    ss->size, st->seglist_base_seq););
    }

    PREPROC_PROFILE_END(s5TcpInsertPerfStats);
    return;
}

static INLINE StreamSegment *FindSegment(StreamTracker *st, u_int32_t pkt_seq)
{
    int32_t dist_head;
    int32_t dist_tail;
    StreamSegment *ss;

    if (!st->seglist)
        return NULL;

    dist_head = pkt_seq - st->seglist->seq;
    dist_tail = pkt_seq - st->seglist_tail->seq;

    if (dist_head <= dist_tail)
    {
        /* Start iterating at the head (left) */
        for (ss = st->seglist; ss; ss = ss->next)
        {
            if (SEQ_EQ(ss->seq, pkt_seq))
                return ss;

            if (SEQ_GEQ(ss->seq, pkt_seq))
                break;
        }
    }
    else
    {
        /* Start iterating at the tail (right) */
        for (ss = st->seglist_tail; ss; ss = ss->prev)
        {
            if (SEQ_EQ(ss->seq, pkt_seq))
                return ss;

            if (SEQ_LT(ss->seq, pkt_seq))
                break;
        }
    }
    return NULL;
}

void Stream5TcpBlockPacket(Packet *p)
{
    StreamSegment *ss;
    StreamTracker *tracker;
    Stream5LWSession *lwssn;
    TcpSession *ssn;
    u_int32_t seq;

    if ((!p) || (!p->ssnptr))
        return;

    if (p->packet_flags & PKT_REBUILT_STREAM)
        return;

    if (!(p->packet_flags & PKT_STREAM_INSERT))
        return;

    lwssn = (Stream5LWSession *)p->ssnptr;

    ssn = (TcpSession *)lwssn->proto_specific_data->data;

    if (!ssn)
        return;

    seq = ntohl(p->tcph->th_seq);

    if (p->packet_flags & PKT_FROM_SERVER)
    {
        tracker = &ssn->client;
    }
    else
    {
        tracker = &ssn->server;
    }
    
    ss = FindSegment(tracker, seq);

    if (ss)
    {
        ss->blocked = 1;
    }
}

static INLINE int SegmentFastTrack(StreamSegment *tail, TcpDataBlock *tdb)
{
    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Checking seq for fast track: %X > %X\n", tdb->seq, 
                tail->seq + tail->size););

    if(SEQ_EQ(tdb->seq, tail->seq + tail->size))
        return 1;

    return 0;
}

static void *SegmentAlloc(u_int32_t size, Packet *p)
{
    void *tmp;

    s5_global_config.mem_in_use += size;

    if (s5_global_config.mem_in_use > s5_global_config.memcap)
    {
        pc.str_mem_faults++;
        sfPerf.sfBase.iStreamFaults++;

        /* Smack the older time'd out sessions */
        if (!PruneLWSessionCache(tcp_lws_cache, p->pkth->ts.tv_sec,
                    (Stream5LWSession*)p->ssnptr, 0))
        {
            /* Try the memcap - last parameter (1) specifies check
             * based on memory cap. */
            PruneLWSessionCache(tcp_lws_cache, 0,
                    (Stream5LWSession*)p->ssnptr, 1);
        }
    }

    tmp = SnortAlloc(size);

    return tmp;
}

static int AddStreamNode(StreamTracker *st, Packet *p,
                  u_int32_t ts,
                  TcpSession *tcpssn,
                  int16_t len,
                  u_int32_t slide,
                  u_int32_t trunc,
                  u_int32_t seq,
                  StreamSegment *left,
                  StreamSegment **retSeg)
{
    StreamSegment *ss = NULL;
    int32_t newSize = len - slide - trunc;

    if (newSize <= 0)
    {
        /*
         * zero size data because of trimming.  Don't
         * insert it
         */
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "zero size TCP data after left & right trimming "
                    "(len: %d slide: %d trunc: %d)\n",
                    len, slide, trunc););
        s5stats.tcp_discards++;

#ifdef DEBUG_STREAM
        {
            StreamSegment *idx = st->seglist;
            unsigned long i = 0;
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Dumping seglist, %d segments\n", st->seg_count););
            while (idx)
            {
                i++;
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "%d  ptr: %p  seq: 0x%X  size: %d nxt: %p prv: %p\n", 
                        i, idx, idx->seq, idx->size, idx->next, idx->prev););

                if(st->seg_count < i)
                    FatalError("Circular list, WTF?\n");

                idx = idx->next;
            }
        }
#endif
        return STREAM_INSERT_ANOMALY;
    }
    
    ss = (StreamSegment *) SegmentAlloc(sizeof(StreamSegment), p);
    ss->pktOrig = ss->pkt = (u_int8_t *) SegmentAlloc(p->pkth->caplen + SPARC_TWIDDLE, p);
    ss->caplen = p->pkth->caplen + SPARC_TWIDDLE;
    ss->pkt += SPARC_TWIDDLE;

    memcpy(ss->pkt, p->pkt, p->pkth->caplen);
    //memcpy(&ss->pkth, p->pkth, sizeof(struct pcap_pkthdr));
    /* Do each field individually because of size differences on 64bit OS */
    ss->pkth.ts.tv_sec = p->pkth->ts.tv_sec;
    ss->pkth.ts.tv_usec = p->pkth->ts.tv_usec;
    ss->pkth.caplen = p->pkth->caplen;
    ss->pkth.len = p->pkth->len;

    ss->data = ss->pkt + (p->data - p->pkt);

    ss->payload = ss->data + slide;
    ss->size = (u_int16_t)newSize;
    ss->seq = seq;
    ss->ts = ts;
    ss->cksum = p->tcph->th_sum;

    /* handle the urg ptr */
    if(p->tcph->th_flags & TH_URG) 
    {
        if(ntohs(p->tcph->th_urp) < p->dsize)
        {
            switch(st->os_policy)
            {
            case STREAM_POLICY_LINUX:
            case STREAM_POLICY_OLD_LINUX:
                /* Linux, Old linux discard data from urgent pointer */
                /* If urg poitner is 0, its treated as a 1 */
                ss->urg_offset = ntohs(p->tcph->th_urp);
                if (ss->urg_offset == 0)
                {
                    ss->urg_offset = 1;
                }
                break;
            case STREAM_POLICY_FIRST:
            case STREAM_POLICY_LAST:
                /* Uh, who knows */
            case STREAM_POLICY_BSD:
            case STREAM_POLICY_MACOS:
            case STREAM_POLICY_SOLARIS:
            case STREAM_POLICY_WINDOWS:
            case STREAM_POLICY_WINDOWS2K3:
            case STREAM_POLICY_VISTA:
            case STREAM_POLICY_HPUX11:
            case STREAM_POLICY_HPUX10:
            case STREAM_POLICY_IRIX:
                /* Others discard data from urgent pointer */
                /* If urg pointer is beyond this packet, its treated as a 0 */
                ss->urg_offset = ntohs(p->tcph->th_urp);
                if (ss->urg_offset > p->dsize)
                {
                    ss->urg_offset = 0;
                }
                break;
            }
        }
    }

    Stream5SeglistAddNode(st, left, ss);
    st->seg_bytes_logical += ss->size;
    st->seg_bytes_total += p->dsize;
    st->total_segs_queued++;
    st->total_bytes_queued += ss->size;

    p->packet_flags |= PKT_STREAM_INSERT;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "added %d bytes on segment list @ seq: 0x%X, total %lu, "
                "%d segments queued\n", ss->size, ss->seq,
                st->seg_bytes_logical, st->seg_count););

    *retSeg = ss;
    return STREAM_INSERT_OK;
}

static int DupStreamNode(Packet *p,
        StreamTracker *st,
        StreamSegment *left,
        StreamSegment **retSeg)
{
    StreamSegment *ss = NULL;

    /*
     * get a new node
     */
    ss = (StreamSegment *) SegmentAlloc(sizeof(StreamSegment), p);
    /* caplen includes SPARC_TWIDDLE HERE */
    ss->pktOrig = ss->pkt = (u_int8_t *) SegmentAlloc(left->caplen, p);

    /* caplen includes SPARC_TWIDDLE HERE */
    ss->caplen = left->caplen;
    memcpy(ss->pktOrig, left->pktOrig, left->caplen);
    memcpy(&ss->pkth, &left->pkth, sizeof(struct pcap_pkthdr));

    ss->pkt += SPARC_TWIDDLE;
    ss->data = ss->pkt + (left->data - left->pkt);
    /*
     * twiddle the values for overlaps
     */
    ss->payload = ss->data;
    ss->size = left->size;
    ss->seq = left->seq;
    ss->cksum = left->cksum;

    Stream5SeglistAddNode(st, left, ss);
    //st->seg_bytes_logical += ss->size;
    //st->seg_bytes_total += p->dsize;
    st->total_segs_queued++;
    //st->total_bytes_queued += ss->size;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "added %d bytes on segment list @ seq: 0x%X, total %lu, "
                "%d segments queued\n", ss->size, ss->seq,
                st->seg_bytes_logical, st->seg_count););

    *retSeg = ss;
    return STREAM_INSERT_OK;

}

static int StreamQueue(StreamTracker *st, Packet *p, TcpDataBlock *tdb, 
        TcpSession *tcpssn)
{
    StreamSegment *ss = NULL;
    StreamSegment *left = NULL;
    StreamSegment *right = NULL;
    StreamSegment *dump_me = NULL;
    u_int32_t orig_seq, seq = tdb->seq;
    u_int32_t seq_end = tdb->end_seq;
    u_int16_t len = p->dsize;
    int trunc = 0;
    int overlap = 0;
    int slide = 0;
    int ret = STREAM_INSERT_OK;
    char done = 0;
    char addthis = 1;
    int32_t dist_head;
    int32_t dist_tail;
#ifdef DEBUG_STREAM5
    StreamSegment *lastptr = NULL;
    u_int32_t base_seq = st->seglist_base_seq;
    int last = 0;
#endif
    PROFILE_VARS;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "Queuing %d bytes on stream!\n"
                "base_seq: %X seq: %X  seq_end: %X\n", 
                seq_end - seq, base_seq, seq, seq_end););

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "%d segments on seglist\n", st->seg_count););
    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+\n"););
    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+\n"););

    orig_seq = seq;

    PREPROC_PROFILE_START(s5TcpInsertPerfStats);

    /* Check if we should not insert a large packet */
    if (IgnoreLargePkt(st, p, tdb))
    {
        return ret;
    }

    if(SegmentFastTrack(st->seglist_tail, tdb))
    {
        /* segment fit cleanly at the end of the segment list */
        left = st->seglist_tail;
        right = NULL;

        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
            "Fast tracking segment! (tail_seq %X size %d)\n", 
            st->seglist_tail->seq, st->seglist_tail->size););

        ret = AddStreamNode(st, p, tdb->ts, tcpssn, len,
                slide /* 0 */, trunc /* 0 */, seq, left /* tail */,
                &ss);

        PREPROC_PROFILE_END(s5TcpInsertPerfStats);
        return ret;
    }

    if (st->seglist && st->seglist_tail)
    {
        if (tdb->seq > st->seglist->seq)
        {
            dist_head = tdb->seq - st->seglist->seq;
        }
        else
        {
            dist_head = st->seglist->seq - tdb->seq;
        }

        if (tdb->seq > st->seglist_tail->seq)
        {
            dist_tail = tdb->seq - st->seglist_tail->seq;
        }
        else
        {
            dist_tail = st->seglist_tail->seq - tdb->seq;
        }
    }
    else
    {
        dist_head = dist_tail = 0;
    }
    
    if (dist_head <= dist_tail)
    {
        /* Start iterating at the head (left) */
        for(ss = st->seglist; ss; ss = ss->next)
        {
            STREAM5_DEBUG_WRAP(
                DebugMessage(DEBUG_STREAM_STATE,
                    "ss: %p  seq: 0x%X  size: %lu delta: %d\n", 
                    ss, ss->seq, ss->size, (ss->seq-base_seq) - last);
                last = ss->seq-base_seq;
                lastptr = ss;

                DebugMessage(DEBUG_STREAM_STATE,
                    "   lastptr: %p ss->next: %p ss->prev: %p\n", 
                    lastptr, ss->next, ss->prev);
                );

            right = ss;

            if(SEQ_GEQ(right->seq, seq))
                break;

            left = right;
        }

        if(ss == NULL)
            right = NULL;
    }
    else
    {
        /* Start iterating at the tail (right) */
        for(ss = st->seglist_tail; ss; ss = ss->prev)
        {
            STREAM5_DEBUG_WRAP(
                DebugMessage(DEBUG_STREAM_STATE,
                    "ss: %p  seq: 0x%X  size: %lu delta: %d\n", 
                    ss, ss->seq, ss->size, (ss->seq-base_seq) - last);
                last = ss->seq-base_seq;
                lastptr = ss;

                DebugMessage(DEBUG_STREAM_STATE,
                    "   lastptr: %p ss->next: %p ss->prev: %p\n", 
                    lastptr, ss->next, ss->prev);
                );

            left = ss;

            if(SEQ_LT(left->seq, seq))
                break;

            right = left;
        }

        if(ss == NULL)
            left = NULL;
    }

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+\n"););
    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+!+\n"););

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "left: %p:0x%X  right: %p:0x%X\n", left, 
                left?left->seq:0, right, right?right->seq:0););

    /*
     * handle left overlaps
     */
    if(left)
    {
        /* 
         * check if the new segment overlaps on the left side
         */
        overlap = left->seq + left->size - seq;

        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "left overlap %d\n", overlap););

        if(overlap > 0)
        {
            s5stats.tcp_overlaps++;
            st->overlap_count++;
            switch(st->reassembly_policy)
            {
                case REASSEMBLY_POLICY_FIRST:
                case REASSEMBLY_POLICY_LINUX:
                case REASSEMBLY_POLICY_BSD:
                case REASSEMBLY_POLICY_WINDOWS:
                case REASSEMBLY_POLICY_WINDOWS2K3:
                case REASSEMBLY_POLICY_VISTA:
                case REASSEMBLY_POLICY_HPUX10:
                case REASSEMBLY_POLICY_IRIX:
                case REASSEMBLY_POLICY_OLD_LINUX:
                case REASSEMBLY_POLICY_MACOS:
                    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                                "left overlap, honoring old data\n"););
                    seq += overlap;
                    slide = overlap;
                    if(SEQ_LEQ(seq_end, seq))
                    {
                        /*
                         * houston, we have a problem
                         */
                        /* flag an anomaly */
                        EventBadSegment(st->tcp_policy);
                        s5stats.tcp_discards++;
                        PREPROC_PROFILE_END(s5TcpInsertPerfStats);
                        return STREAM_INSERT_ANOMALY;
                    }
                    break;

                case REASSEMBLY_POLICY_SOLARIS:
                case REASSEMBLY_POLICY_HPUX11:
                    if ((left->seq < seq) && (left->seq + left->size >= seq + len))
                    {
                        /* New packet is entirely overlapped by an
                         * existing packet on both sides.  Drop the
                         * new data. */
                        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                                    "left overlap, honoring old data\n"););
                        seq += overlap;
                        slide = overlap;
                        if(SEQ_LEQ(seq_end, seq))
                        {
                            /*
                             * houston, we have a problem
                             */
                            /* flag an anomaly */
                            EventBadSegment(st->tcp_policy);
                            s5stats.tcp_discards++;
                            PREPROC_PROFILE_END(s5TcpInsertPerfStats);
                            return STREAM_INSERT_ANOMALY;
                        }
                    }
                    /* Otherwise, trim the old data accordingly */
                    left->size -= (int16_t)overlap;
                    st->seg_bytes_logical -= overlap;
                    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                                "left overlap, honoring new data\n"););
                    if (left->size <= 0)
                    {
                        dump_me = left;

                        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                                "retrans, dumping old TCP data (seq: %d "
                                "overlap: %d)\n", dump_me->seq, overlap););

                        left = left->prev;
                        Stream5SeglistDeleteNode(st, dump_me);
                    }
                    break;
                case REASSEMBLY_POLICY_LAST:
                    /* True "Last" policy" */
                    if ((left->seq < seq) && (left->seq + left->size > seq + len))
                    {
                        /* New data is overlapped on both sides by
                         * existing data.  Existing data needs to be
                         * split and the new data inserted in the
                         * middle.
                         *
                         * Need to duplicate left.  Adjust that
                         * seq by + (seq + len) and
                         * size by - (seq + len - left->seq).
                         */
                        ret = DupStreamNode(p, st, left, &right);
                        if (ret != STREAM_INSERT_OK)
                        {
                            /* No warning,
                             * its done in StreamSeglistAddNode */
                            PREPROC_PROFILE_END(s5TcpInsertPerfStats);
                            return ret;
                        }
                        left->size -= (int16_t)overlap;
                        st->seg_bytes_logical -= overlap;
                        st->seg_bytes_total -= overlap;
                        
                        right->seq = seq + len;
                        right->size -= (int16_t)(seq + len - left->seq);
                        right->payload += (seq + len - left->seq);
                        st->seg_bytes_logical -= (seq + len - left->seq);
                        st->seg_bytes_total -= (seq + len - left->seq);
                    }
                    else
                    {
                        left->size -= (int16_t)overlap;
                        st->seg_bytes_logical -= overlap;
                    }
                    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                                "left overlap, honoring new data\n"););
                    if (left->size <= 0)
                    {
                        dump_me = left;

                        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                                "retrans, dumping old TCP data (seq: %d "
                                "overlap: %d)\n", dump_me->seq, overlap););

                        left = left->prev;
                        Stream5SeglistDeleteNode(st, dump_me);
                    }
                    break;
            }

            if(SEQ_LEQ(seq_end, seq))
            {
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "seq_end < seq"););
                /*
                 * houston, we have a problem
                 */
                /* flag an anomaly */
                EventBadSegment(st->tcp_policy);
                s5stats.tcp_discards++;
                PREPROC_PROFILE_END(s5TcpInsertPerfStats);
                return STREAM_INSERT_ANOMALY;
            }
        }
        else
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "No left overlap\n"););
        }
    }

    //(seq_end > right->seq) && (seq_end <= (right->seq+right->size))))
    while(right && !done && SEQ_LT(right->seq, seq_end))
    {
        trunc = 0;
        overlap = (int)(seq_end - right->seq);
        //overlap = right->size - (right->seq - seq);
        //right->seq + right->size - seq_end;

        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "right overlap(%d): len: %d right->seq: 0x%X seq: 0x%X\n",
                    overlap, len, right->seq, seq););

        if(overlap < right->size)
        {
            s5stats.tcp_overlaps++;
            st->overlap_count++;

            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "Got partial right overlap\n"););

            switch(st->reassembly_policy)
            {
                /* truncate existing data */
                case REASSEMBLY_POLICY_LAST:
                case REASSEMBLY_POLICY_LINUX:
                case REASSEMBLY_POLICY_OLD_LINUX:
                case REASSEMBLY_POLICY_BSD:
                case REASSEMBLY_POLICY_WINDOWS:
                case REASSEMBLY_POLICY_WINDOWS2K3:
                case REASSEMBLY_POLICY_IRIX:
                case REASSEMBLY_POLICY_HPUX10:
                case REASSEMBLY_POLICY_MACOS:
                    if ((right->seq == seq) &&
                        (st->reassembly_policy != REASSEMBLY_POLICY_LAST))
                    {
                        slide = (right->seq + right->size - seq);
                        seq += slide;
                    }
                    else
                    {
                        /* partial overlap */
                        right->seq += overlap;
                        right->payload += overlap;
                        right->size -= (int16_t)overlap;
                        st->seg_bytes_logical -= overlap;
                        st->total_bytes_queued -= overlap;
                    }

                    if (right->size <= 0)
                    {
                        dump_me = right;

                        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_FRAG, "retrans, "
                                "dumping old data (seq: %d overlap: %d)\n", 
                                dump_me->seq, overlap););

                        right = right->next;

                        Stream5SeglistDeleteNode(st, dump_me);
 
                    }
                    break;

                case REASSEMBLY_POLICY_FIRST:
                case REASSEMBLY_POLICY_VISTA:
                case REASSEMBLY_POLICY_SOLARIS:
                case REASSEMBLY_POLICY_HPUX11:
                    trunc = overlap;
                    break;
            }

            /* all done, keep me out of the loop */
            done = 1;
        }
        else
        {
            s5stats.tcp_overlaps++;
            st->overlap_count++;

            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "Got full right overlap\n"););

            if ((right->seq == seq) && (right->cksum == p->tcph->th_sum))
            {
                /* RETRANSMISSION */
                /* Packet was analyzed the first time.
                 * Don't bother looking at it again.
                 */
                DisableDetect(p);

                /* Still want to cound this in Perfmon */
                SetPreprocBit(p, PP_PERFMONITOR);

                if (InlineMode())
                {
                    /* Examined previously, was it blocked? */
                    if (right->blocked)
                    {
                        /* Previously blocked, block it again */
                        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                                    "Dropping retransmitted packet -- "
                                    "blocked previously\n"););
                        InlineDrop(p);
                    }
                    else
                    {
                        /* Previously not blocked, let it through */
                        DEBUG_WRAP(DebugMessage(DEBUG_STREAM,
                                    "Allowing retransmitted packet -- "
                                    "not blocked previously\n"););
                    }
                }
                addthis = 0;
                done = 1;
                break;
            }
            else if ((right->seq == seq) &&
                     (right->size >= p->dsize))
            {
                /* Strange -- different size data.  New is same or smaller.  */
                /* Log Evasion attempt -- NO because this is handled by
                 * the policy-based code below. */
            }

            switch(st->reassembly_policy)
            {
                case REASSEMBLY_POLICY_BSD:
                case REASSEMBLY_POLICY_LINUX:
                case REASSEMBLY_POLICY_WINDOWS:
                case REASSEMBLY_POLICY_WINDOWS2K3:
                case REASSEMBLY_POLICY_HPUX10:
                case REASSEMBLY_POLICY_IRIX:
                case REASSEMBLY_POLICY_MACOS:
                    if ((seq_end >= right->seq + right->size) &&
                       (seq < right->seq))
                    {
                        dump_me = right;
                        st->seg_bytes_logical -= right->size;
                        st->seg_bytes_total -= right->size;

                        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                                    "retrans, dropping old data at seq %d, size %d\n",
                                    right->seq, right->size););
                        right = right->next;
                        Stream5SeglistDeleteNode(st, dump_me);
                        break;
                    }
                    else
                    {
                        switch (st->reassembly_policy)
                        {
                        case REASSEMBLY_POLICY_WINDOWS:
                        case REASSEMBLY_POLICY_WINDOWS2K3:
                        case REASSEMBLY_POLICY_BSD:
                        case REASSEMBLY_POLICY_MACOS:
                            /* BSD/MacOS & Windows follow a FIRST policy in the
                             * case below... */
                             break;
                        default:
                            /* All others follow a LAST policy */
                            if ((seq_end > right->seq + right->size) &&
                                (seq == right->seq))
                            {
                                /* When existing data is fully overlapped by new
                                 * and sequence numbers are the same, most OSs
                                 * follow a LAST policy.
                                 */
                                goto right_overlap_last;
                            }
                            break;
                        }
                    }
                    /* Fall through */
                case REASSEMBLY_POLICY_FIRST:
                case REASSEMBLY_POLICY_VISTA:
                    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                                "Got full right overlap, truncating new\n"););
                    /* full overlap */
                    if (right->seq == seq)
                    {
                        slide = (int32_t)(right->seq + right->size - seq);
                        seq += slide;
                        left = right;
                        right = right->next;

                        if (right && (SEQ_EQ(seq,right->seq)))
                        {
                            /* same seq as next packet don't insert yet...
                             * keep going.
                             */
                            continue;
                        }
                    }
                    else
                    {
                        trunc += overlap;
                    }
                    if(SEQ_LEQ((int)(seq_end - trunc), seq))
                    {
                        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                                    "StreamQueue got full right overlap with "
                                    "resulting seq too high, bad segment "
                                    "(seq: %X  seq_end: %X overlap: %lu\n", 
                                    seq, seq_end, overlap););
                        EventBadSegment(st->tcp_policy);
                        s5stats.tcp_discards++;
                        PREPROC_PROFILE_END(s5TcpInsertPerfStats);
                        return STREAM_INSERT_ANOMALY;
                    }

                    /* insert this one, and see if we need to chunk it up */
                    /* Adjust slide so that is correct relative to orig_seq */
                    slide = seq - orig_seq;
                    ret = AddStreamNode(st, p, tdb->ts, tcpssn, len, slide, trunc, seq, left, &ss);
                    if (ret != STREAM_INSERT_OK)
                    {
                        /* no warning, already done above */
                        PREPROC_PROFILE_END(s5TcpInsertPerfStats);
                        return ret;
                    }

                    {
                        u_int32_t curr_end = ss->seq + ss->size;

                        while (right &&
                             (curr_end <= right->seq) &&
                             (right->seq < seq_end))
                        {
                            curr_end = right->seq + right->size;
                            left = right;
                            right = right->next;
                        }

                        if (right && (right->seq < seq_end))
                        {
                            /* Adjust seq to end of 'right' */
                            seq = right->seq + right->size;

                            /* Not overlapping on the left any more */
                            slide = 0;

                            left = right;

                            /*
                             * Reset trunc, in case the next one kicks us
                             * out of the loop.  This packet will become the
                             * right-most entry so far.  Don't truncate any
                             * further.
                             */
                            trunc = 0;
                            if (right->next)
                                continue;
                        }

                        if (curr_end < seq_end)
                        {
                            /* Insert this guy in his proper spot,
                             * adjust offset to the right-most endpoint
                             * we saw.
                             */
                            slide = left->seq + left->size - seq;
                            seq = curr_end;
                            trunc = 0;
                        }
                        else
                        {
                            addthis = 0;
                        }
                    }

                    break;

                case REASSEMBLY_POLICY_HPUX11:
                case REASSEMBLY_POLICY_SOLARIS:
                    /* If this packet is wholly overlapping and the same size
                     * as a previous one and we have not received the one
                     * immediately preceeding, we take the FIRST. */
                    if (SEQ_EQ(right->seq, seq) && (right->size == len) &&
                        (left && !SEQ_EQ(left->seq + left->size, seq)))
                    {
                        trunc += overlap;
                        if(SEQ_LEQ((int)(seq_end - trunc), seq))
                        {
                            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                                "StreamQueue got full right overlap with "
                                "resulting seq too high, bad segment "
                                "(seq: %X  seq_end: %X overlap: %lu\n", 
                                seq, seq_end, overlap););
                            EventBadSegment(st->tcp_policy);
                            s5stats.tcp_discards++;
                            PREPROC_PROFILE_END(s5TcpInsertPerfStats);
                            return STREAM_INSERT_ANOMALY;
                        }
                        break;
                    }
                /* Fall through */
                case REASSEMBLY_POLICY_OLD_LINUX:
                case REASSEMBLY_POLICY_LAST:
right_overlap_last:
                    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                                "Got full right overlap of old, dropping old\n"););
                    dump_me = right;
                    right = right->next;
                    Stream5SeglistDeleteNode(st, dump_me);
                    break;
            }
        }
    }

    if (addthis)
    {
        /* Adjust slide so that is correct relative to orig_seq */
        slide = seq - orig_seq;
        ret = AddStreamNode(st, p, tdb->ts, tcpssn, len,
                slide, trunc, seq, left, &ss);
    }
    else
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Fully truncated right overlap\n"););
    }

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "StreamQueue returning normally\n"););

    PREPROC_PROFILE_END(s5TcpInsertPerfStats);
    return ret;
}


static void ProcessTcpStream(StreamTracker *rcv, TcpSession *tcpssn,
                             Packet *p, TcpDataBlock *tdb,
                             Stream5TcpPolicy *s5TcpPolicy)
{

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "In ProcessTcpStream(), %d bytes to queue\n", p->dsize););

    if(rcv->seg_count != 0)
    {
        if(rcv->flush_mgr.flush_policy == STREAM_FLPOLICY_IGNORE)
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Ignoring segment due to IGNORE flush_policy\n"););
            return;
        }
        else
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "queuing segment\n"););
            StreamQueue(rcv, p, tdb, tcpssn);

            if ((rcv->tcp_policy->overlap_limit) && 
                (rcv->overlap_count > rcv->tcp_policy->overlap_limit))
            {
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "Reached the overlap limit.  Flush the data "
                        "and kill the session if configured\n"););
                if (p->packet_flags & PKT_FROM_CLIENT)
                {
                    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "Flushing data on packet from the client\n"););
                    flush_ackd(tcpssn, rcv, p,
                            GET_SRC_IP(p), GET_DST_IP(p),
                            p->tcph->th_sport, p->tcph->th_dport,
                            PKT_FROM_CLIENT);

                    flush_ackd(tcpssn, &tcpssn->server, p,
                            GET_DST_IP(p), GET_SRC_IP(p),
                            p->tcph->th_dport, p->tcph->th_sport,
                            PKT_FROM_SERVER);
                }
                else
                {
                    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "Flushing data on packet from the server\n"););
                    flush_ackd(tcpssn, rcv, p,
                            GET_SRC_IP(p), GET_DST_IP(p),
                            p->tcph->th_sport, p->tcph->th_dport,
                            PKT_FROM_SERVER);

                    flush_ackd(tcpssn, &tcpssn->client, p,
                            GET_DST_IP(p), GET_SRC_IP(p),
                            p->tcph->th_dport, p->tcph->th_sport,
                            PKT_FROM_CLIENT);
                }

                /* Alert on overlap limit */
                /* TODO: Alert should cause drop of packet & reset of session */
                /* FYI: Mark session as dead/drop remaining packets */
                /* FYI: Issue Drop/Reset packets for this session */
                EventExcessiveOverlap(rcv->tcp_policy);
            }
        }
    }
    else
    {
        if(rcv->flush_mgr.flush_policy == STREAM_FLPOLICY_IGNORE)
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                            "Ignoring segment due to IGNORE flush_policy\n"););
            return;
        }
        else
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                                "queuing segment\n"););
            NewQueue(rcv, p, tdb, tcpssn);
        }
    }

    return;
}

static int ProcessTcpData(Packet *p, StreamTracker *listener, TcpSession *tcpssn,
        TcpDataBlock *tdb, Stream5TcpPolicy *s5TcpPolicy)
{
    PROFILE_VARS;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "In ProcessTcpData()\n"););

    PREPROC_PROFILE_START(s5TcpDataPerfStats);
    if ((p->tcph->th_flags & TH_SYN) && (listener->os_policy != STREAM_POLICY_MACOS))
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Bailing, data on SYN, not MAC Policy!\n"););
        PREPROC_PROFILE_END(s5TcpDataPerfStats);
        return S5_UNALIGNED;
    }

    /* we're aligned, so that's nice anyway */
    if(tdb->seq == listener->r_nxt_ack)
    {
        /* check if we're in the window */
        if(Stream5GetWindow(listener) == 0)
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "Bailing, we're out of the window!\n"););
            PREPROC_PROFILE_END(s5TcpDataPerfStats);
            return S5_UNALIGNED;
        }

        /* move the ack boundry up, this is the only way we'll accept data */
        if (listener->s_mgr.state_queue == TCP_STATE_NONE)
            listener->r_nxt_ack = tdb->end_seq;

        if(p->dsize != 0)
        {
            ProcessTcpStream(listener, tcpssn, p, tdb, s5TcpPolicy);
            /* set flags to session flags */

            PREPROC_PROFILE_END(s5TcpDataPerfStats);
            return S5_ALIGNED;
        }
    }
    else
    {
        /* pkt is out of order, do some target-based shizzle here */

        /* NO, we don't want to simply bail.  Some platforms
         * favor unack'd dup data over the original data.
         * Let the reassembly policy decide how to handle
         * the overlapping data.
         *
         * See HP, Solaris, et al. for those that favor
         * duplicate data over the original in some cases.
         */
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "out of order segment (tdb->seq: 0x%X "
                    "l->r_nxt_ack: 0x%X!\n", tdb->seq, listener->r_nxt_ack);); 

        if(p->dsize != 0)
        {
            ProcessTcpStream(listener, tcpssn, p, tdb, s5TcpPolicy);
        }
    }

    PREPROC_PROFILE_END(s5TcpDataPerfStats);
    return S5_UNALIGNED;
}

u_int16_t StreamGetPolicy(Stream5LWSession *lwssn, Stream5TcpPolicy *s5TcpPolicy,
              int direction)
{
#ifdef TARGET_BASED
#ifndef SUP_IP6
    u_int16_t policy_id;
    /* Not caching this host_entry in the frag tracker so we can
     * swap the table out after processing this packet if we need
     * to.  */
    HostAttributeEntry *host_entry = NULL;
    int ssn_dir;

    if (direction == FROM_CLIENT)
    {
        host_entry = SFAT_LookupHostEntryByIp4Addr(ntohl(lwssn->server_ip));
        ssn_dir = SSN_DIR_SERVER;
    }
    else
    {
        host_entry = SFAT_LookupHostEntryByIp4Addr(ntohl(lwssn->client_ip));
        ssn_dir = SSN_DIR_CLIENT;
    }

    if (host_entry && (isStreamPolicySet(host_entry) == POLICY_SET))
    {
        policy_id = getStreamPolicy(host_entry);

        if (policy_id != SFAT_UNKNOWN_STREAM_POLICY)
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "StreamGetPolicy: Policy Map Entry: %s %s %s %d(%s)\n",
                host_entry->hostInfo.vendor.value.s_value,
                host_entry->hostInfo.operatingSystem.value.s_value,
                host_entry->hostInfo.version.value.s_value,
                policy_id, reassembly_policy_names[policy_id]););

            /* Since we've already done the lookup, try to get the
             * application protocol id with that host_entry. */
            Stream5SetApplicationProtocolIdFromHostEntry(lwssn, host_entry, ssn_dir);
            return policy_id;
        }
    }
#endif
#endif

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
        "StreamGetPolicy: Using configured default %d(%s)\n",
        s5TcpPolicy->policy, reassembly_policy_names[s5TcpPolicy->policy]););

    return s5TcpPolicy->policy;
}

void SetTcpReassemblyPolicy(StreamTracker *st)
{
    st->reassembly_policy = GetTcpReassemblyPolicy(st->os_policy);
}

void SetOSPolicy(TcpSession *tcpssn)
{
    if (tcpssn->client.os_policy == 0)
    {
        tcpssn->client.os_policy = StreamGetPolicy(tcpssn->lwssn, tcpssn->client.tcp_policy, FROM_SERVER);
        SetTcpReassemblyPolicy(&tcpssn->client);
    }

    if (tcpssn->server.os_policy == 0)
    {
        tcpssn->server.os_policy = StreamGetPolicy(tcpssn->lwssn, tcpssn->server.tcp_policy, FROM_CLIENT);
        SetTcpReassemblyPolicy(&tcpssn->server);
    }
}

static INLINE int ValidMacAddress(StreamTracker *talker,
                                  StreamTracker *listener,
                                  Packet *p)
{
    int i;
    int ret = 0;

    if (p->eh == NULL)
        return 0;

    /* Use a for loop and byte comparison, which has proven to be
     * faster on pipelined architectures compared to a memcmp (setup
     * for memcmp is slow).  Not using a 4 byte and 2 byte long because
     * there is no guaranttee of memory alignment (and thus performance
     * issues similar to memcmp). */
    for (i=0;i<6;i++)
    {
        if ((talker->mac_addr[i] != p->eh->ether_src[i]))
        {
            if (p->packet_flags & PKT_FROM_CLIENT)
                ret |= EVENT_SESSION_HIJACK_CLIENT;
            else
                ret |= EVENT_SESSION_HIJACK_SERVER;
        }

        if (listener->mac_addr[i] != p->eh->ether_dst[i])
        {
            if (p->packet_flags & PKT_FROM_CLIENT)
                ret |= EVENT_SESSION_HIJACK_SERVER;
            else
                ret |= EVENT_SESSION_HIJACK_CLIENT;
        }
    }

    return ret;
}

static INLINE void CopyMacAddr(Packet *p,
                                 TcpSession *tcpssn,
                                 int dir)
{
    int i;

    /* Not ethernet based, nothing to do */
    if (p->eh == NULL)
        return;

    if (dir == FROM_CLIENT)
    {
        /* Client is SRC */
        for (i=0;i<6;i++)
        {
            tcpssn->client.mac_addr[i] = p->eh->ether_src[i];
            tcpssn->server.mac_addr[i] = p->eh->ether_dst[i];
        }
    }
    else
    {
        /* Server is SRC */
        for (i=0;i<6;i++)
        {
            tcpssn->server.mac_addr[i] = p->eh->ether_src[i];
            tcpssn->client.mac_addr[i] = p->eh->ether_dst[i];
        }
    }
}

static int NewTcpSession(Packet *p,
                         Stream5LWSession *lwssn,
                         TcpDataBlock *tdb,
                         Stream5TcpPolicy *dstPolicy)
{
    MemBucket *tmpBucket = NULL;
    TcpSession *tmp = NULL;
    u_int16_t client_port = 0, server_port = 0;
    PROFILE_VARS;

    PREPROC_PROFILE_START(s5TcpNewSessPerfStats);

    if(p->tcph->th_flags == TH_SYN)
    {
        /******************************************************************
         * start new sessions on proper SYN packets
         *****************************************************************/
        tmpBucket = mempool_alloc(&tcp_session_mempool);
        tmp = tmpBucket->data;
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Creating new session tracker on SYN!\n"););

#ifdef DEBUG
        tmp->ssn_time.tv_sec = p->pkth->ts.tv_sec;
        tmp->ssn_time.tv_usec = p->pkth->ts.tv_usec;
#endif
        lwssn->session_flags |= SSNFLAG_SEEN_CLIENT;

        if((p->tcph->th_flags & (TH_CWR|TH_ECE)) == (TH_CWR|TH_ECE))
        {
            lwssn->session_flags |= SSNFLAG_ECN_CLIENT_QUERY;
        }

        /* setup the stream trackers */
        tmp->client.ttl = GET_IPH_TTL(p);
        tmp->client.s_mgr.state = TCP_STATE_SYN_SENT;
        tmp->client.isn = tdb->seq;
        tmp->client.l_unackd = tdb->seq + 1;
        tmp->client.l_nxt_seq = tmp->client.l_unackd + 1; /* reset later */
        tmp->client.l_window = tdb->win;

        tmp->client.ts_last_pkt = p->pkth->ts.tv_sec;

        tmp->server.seglist_base_seq = tmp->client.l_unackd;
        tmp->server.r_nxt_ack = tmp->client.l_unackd;
        tmp->server.r_win_base = tdb->seq+1;

        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "seglist_base_seq = %X\n", tmp->server.seglist_base_seq););
        tmp->server.s_mgr.state = TCP_STATE_LISTEN;

        tmp->client.flags |= Stream5GetTcpTimestamp(p, &tmp->client.ts_last);
        if (tmp->client.ts_last == 0)
            tmp->client.flags |= TF_TSTAMP_ZERO;
        tmp->client.flags |= Stream5GetMss(p, &tmp->client.mss);
        tmp->client.flags |= Stream5GetWscale(p, &tmp->client.wscale);


        /* Set the Stream5TcpPolicy for each direction (pkt from client) */
#ifdef SUP_IP6
        tmp->client.tcp_policy = Stream5PolicyLookup(GET_SRC_IP(p));
#else
        tmp->client.tcp_policy = Stream5PolicyLookup(p->iph->ip_src);
#endif
        tmp->server.tcp_policy = dstPolicy;

        /* Server is destination */
        server_port = p->dp;
        client_port = p->sp;

        CopyMacAddr(p, tmp, FROM_CLIENT);
    }
    else if (TCP_ISFLAGSET(p->tcph, TH_SYN|TH_ACK))
    {
        /******************************************************************
         * start new sessions on SYN/ACK from server
         *****************************************************************/
        tmpBucket = mempool_alloc(&tcp_session_mempool);
        tmp = tmpBucket->data;
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Creating new session tracker on SYN_ACK!\n"););

#ifdef DEBUG
        tmp->ssn_time.tv_sec = p->pkth->ts.tv_sec;
        tmp->ssn_time.tv_usec = p->pkth->ts.tv_usec;
#endif
        lwssn->session_flags |= SSNFLAG_SEEN_SERVER;

        if((p->tcph->th_flags & (TH_CWR|TH_ECE)) == (TH_CWR|TH_ECE))
        {
            lwssn->session_flags |= SSNFLAG_ECN_SERVER_REPLY;
        }

        /* setup the stream trackers */
        tmp->server.ttl = GET_IPH_TTL(p);
        tmp->server.s_mgr.state = TCP_STATE_SYN_RCVD;
        tmp->server.isn = tdb->seq;
        tmp->server.l_unackd = tdb->seq + 1;
        tmp->server.l_nxt_seq = tmp->server.l_unackd + 1; /* reset later */
        tmp->server.l_window = tdb->win;

        /* Double check these two -- should be ACK -1? */
        tmp->server.seglist_base_seq = tdb->ack;
        tmp->server.r_win_base = tdb->ack;
        tmp->server.r_nxt_ack = tdb->ack;

        tmp->server.ts_last_pkt = p->pkth->ts.tv_sec;

        tmp->client.seglist_base_seq = tmp->server.l_unackd;
        tmp->client.r_nxt_ack = tmp->server.l_unackd;
        tmp->client.r_win_base = tdb->seq+1;

        /* Double check this -- should be ACK -1? */
        tmp->client.isn = tdb->ack-1;

        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "seglist_base_seq = %X\n", tmp->client.seglist_base_seq););
        tmp->client.s_mgr.state = TCP_STATE_SYN_SENT;

        tmp->server.flags |= Stream5GetTcpTimestamp(p, &tmp->server.ts_last);
        if (tmp->server.ts_last == 0)
            tmp->server.flags |= TF_TSTAMP_ZERO;
        tmp->server.flags |= Stream5GetMss(p, &tmp->server.mss);
        tmp->server.flags |= Stream5GetWscale(p, &tmp->server.wscale);

        /* Set the Stream5TcpPolicy for each direction (pkt from server) */
#ifdef SUP_IP6
        tmp->server.tcp_policy = Stream5PolicyLookup(GET_SRC_IP(p));
#else
        tmp->server.tcp_policy = Stream5PolicyLookup(p->iph->ip_src);
#endif
        tmp->client.tcp_policy = dstPolicy;

        /* Client is destination */
        server_port = p->sp;
        client_port = p->dp;

        CopyMacAddr(p, tmp, FROM_SERVER);
    }
    else if ((p->tcph->th_flags & TH_ACK) &&
             !(p->tcph->th_flags & TH_RST) &&
             (lwssn->session_state & STREAM5_STATE_ESTABLISHED))
    {
        /******************************************************************
         * start new sessions on completion of 3-way (ACK only, no data)
         *****************************************************************/
        tmpBucket = mempool_alloc(&tcp_session_mempool);
        tmp = tmpBucket->data;
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Creating new session tracker on ACK!\n"););

#ifdef DEBUG
        tmp->ssn_time.tv_sec = p->pkth->ts.tv_sec;
        tmp->ssn_time.tv_usec = p->pkth->ts.tv_usec;
#endif
        lwssn->session_flags |= SSNFLAG_SEEN_CLIENT;

        if((p->tcph->th_flags & (TH_CWR|TH_ECE)) == (TH_CWR|TH_ECE))
        {
            lwssn->session_flags |= SSNFLAG_ECN_CLIENT_QUERY;
        }

        /* setup the stream trackers */
        tmp->client.ttl = GET_IPH_TTL(p);
        tmp->client.s_mgr.state = TCP_STATE_ESTABLISHED;
        tmp->client.isn = tdb->seq;
        tmp->client.l_unackd = tdb->seq + 1;
        tmp->client.l_nxt_seq = tmp->client.l_unackd + 1; /* reset later */
        tmp->client.l_window = tdb->win;

        tmp->client.ts_last_pkt = p->pkth->ts.tv_sec;

        tmp->server.seglist_base_seq = tmp->client.l_unackd;
        tmp->server.r_nxt_ack = tmp->client.l_unackd;
        tmp->server.r_win_base = tdb->seq+1;

        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "seglist_base_seq = %X\n", tmp->server.seglist_base_seq););
        tmp->server.s_mgr.state = TCP_STATE_ESTABLISHED;

        tmp->client.flags |= Stream5GetTcpTimestamp(p, &tmp->client.ts_last);
        if (tmp->client.ts_last == 0)
            tmp->client.flags |= TF_TSTAMP_ZERO;
        tmp->client.flags |= Stream5GetMss(p, &tmp->client.mss);
        tmp->client.flags |= Stream5GetWscale(p, &tmp->client.wscale);

        /* Set the Stream5TcpPolicy for each direction (pkt from client) */
#ifdef SUP_IP6
        tmp->client.tcp_policy = Stream5PolicyLookup(GET_SRC_IP(p));
#else
        tmp->client.tcp_policy = Stream5PolicyLookup(p->iph->ip_src);
#endif

        tmp->server.tcp_policy = dstPolicy;

        /* Server is destination */
        server_port = p->dp;
        client_port = p->sp;

        CopyMacAddr(p, tmp, FROM_CLIENT);
    }
    else if (p->dsize != 0)
    {
        /******************************************************************
         * start new sessions on data in packet
         *****************************************************************/
        tmpBucket = mempool_alloc(&tcp_session_mempool);
        tmp = tmpBucket->data;
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Creating new session tracker on data packet (ACK|PSH)!\n"););

#ifdef DEBUG
        tmp->ssn_time.tv_sec = p->pkth->ts.tv_sec;
        tmp->ssn_time.tv_usec = p->pkth->ts.tv_usec;
#endif

        if (lwssn->direction == FROM_CLIENT)
        {
            /* Sender is client (src port is higher) */
            lwssn->session_flags |= SSNFLAG_SEEN_CLIENT;

            if((p->tcph->th_flags & (TH_CWR|TH_ECE)) == (TH_CWR|TH_ECE))
            {
                lwssn->session_flags |= SSNFLAG_ECN_CLIENT_QUERY;
            }

            /* setup the stream trackers */
            tmp->client.ttl = GET_IPH_TTL(p);
            tmp->client.s_mgr.state = TCP_STATE_ESTABLISHED;
            tmp->client.isn = tdb->seq;
            tmp->client.l_unackd = tdb->seq;
            tmp->client.l_nxt_seq = tmp->client.l_unackd + 1; /* reset later */
            tmp->client.l_window = tdb->win;

            tmp->client.ts_last_pkt = p->pkth->ts.tv_sec;

            tmp->server.seglist_base_seq = tmp->client.l_unackd;
            tmp->server.r_nxt_ack = tmp->client.l_unackd;
            tmp->server.r_win_base = tdb->seq;
            tmp->server.l_window = 0; /* reset later */

            /* Next server packet is what was ACKd */
            //tmp->server.l_nxt_seq = tdb->ack + 1;
            tmp->server.l_unackd = tdb->ack - 1;

            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                        "seglist_base_seq = %X\n", tmp->server.seglist_base_seq););
            tmp->server.s_mgr.state = TCP_STATE_ESTABLISHED;

            tmp->client.flags |= Stream5GetTcpTimestamp(p, &tmp->client.ts_last);
            if (tmp->client.ts_last == 0)
                tmp->client.flags |= TF_TSTAMP_ZERO;
            tmp->client.flags |= Stream5GetMss(p, &tmp->client.mss);
            tmp->client.flags |= Stream5GetWscale(p, &tmp->client.wscale);

            /* Set the Stream5TcpPolicy for each direction (pkt from client) */
#ifdef SUP_IP6
            tmp->client.tcp_policy = Stream5PolicyLookup(GET_SRC_IP(p));
#else
            tmp->client.tcp_policy = Stream5PolicyLookup(p->iph->ip_src);
#endif
            tmp->server.tcp_policy = dstPolicy;

            /* Server is destination */
            server_port = p->dp;
            client_port = p->sp;

            CopyMacAddr(p, tmp, FROM_CLIENT);
        }
        else
        {
            /* Sender is server (src port is lower) */
            lwssn->session_flags |= SSNFLAG_SEEN_SERVER;

            /* setup the stream trackers */
            tmp->server.ttl = GET_IPH_TTL(p);
            tmp->server.s_mgr.state = TCP_STATE_ESTABLISHED;
            tmp->server.isn = tdb->seq;
            tmp->server.l_unackd = tdb->seq;
            tmp->server.l_nxt_seq = tmp->server.l_unackd + 1; /* reset later */
            tmp->server.l_window = tdb->win;

            /* Double check these two -- should be ACK -1? */
            tmp->server.seglist_base_seq = tdb->ack -1;
            tmp->server.r_win_base = tdb->ack;
            tmp->server.r_nxt_ack = tdb->ack;

            tmp->server.ts_last_pkt = p->pkth->ts.tv_sec;

            tmp->client.seglist_base_seq = tmp->server.l_unackd;
            tmp->client.r_nxt_ack = tmp->server.l_unackd;
            tmp->client.r_win_base = tdb->seq;
            tmp->client.l_window = 0; /* reset later */

            /* Double check this -- should be ACK -1? */
            tmp->client.isn = tdb->ack-1;

            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                        "seglist_base_seq = %X\n", tmp->client.seglist_base_seq););
            tmp->client.s_mgr.state = TCP_STATE_ESTABLISHED;

            tmp->server.flags |= Stream5GetTcpTimestamp(p, &tmp->server.ts_last);
            if (tmp->server.ts_last == 0)
                tmp->server.flags |= TF_TSTAMP_ZERO;
            tmp->server.flags |= Stream5GetMss(p, &tmp->server.mss);
            tmp->server.flags |= Stream5GetWscale(p, &tmp->server.wscale);

            /* Set the Stream5TcpPolicy for each direction (pkt from server) */
#ifdef SUP_IP6
            tmp->server.tcp_policy = Stream5PolicyLookup(GET_SRC_IP(p));
#else
            tmp->server.tcp_policy = Stream5PolicyLookup(p->iph->ip_src);
#endif
            tmp->client.tcp_policy = dstPolicy;

            /* Client is destination */
            server_port = p->sp;
            client_port = p->dp;

            CopyMacAddr(p, tmp, FROM_SERVER);
        }
    }

    if (tmp)
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "adding TcpSession to lightweight session\n"););
        lwssn->proto_specific_data = tmpBucket;
        lwssn->protocol = GET_IPH_PROTO(p);
        tmp->lwssn = lwssn;

        /* New session, previous was marked as reset.  Clear the
         * reset flag. */
        if (lwssn->session_flags & SSNFLAG_RESET)
            lwssn->session_flags &= ~SSNFLAG_RESET;

        SetOSPolicy(tmp);
        /* Set up the flush behaviour, based on the configured info
         * for the server and client ports.
         */
        /* Yes, the server flush manager gets the info from the
         * policy's server port's the flush policy from the client
         * and visa-versa.
         *
         * For example, when policy said 'ports client 80', that means
         * reassemble packets from the client side (stored in the server's
         * flush buffer in the session) destined for port 80.  Port 80 is
         * the server port and we're reassembling the client side.
         * That should make this almost as clear as opaque mud!
         */
#ifdef TARGET_BASED
        if (tmp->server.tcp_policy->flush_config_protocol[lwssn->application_protocol].configured == 1)
        {
            InitFlushMgr(&tmp->server.flush_mgr,
                     &tmp->server.tcp_policy->flush_point_list,
                     tmp->server.tcp_policy->flush_config_protocol[lwssn->application_protocol].client.flush_policy);
        }
        else
        {
#endif
            InitFlushMgr(&tmp->server.flush_mgr,
                     &tmp->server.tcp_policy->flush_point_list,
                     tmp->server.tcp_policy->flush_config[server_port].client.flush_policy);
#ifdef TARGET_BASED
        }
#endif

#ifdef TARGET_BASED
        if (tmp->client.tcp_policy->flush_config_protocol[lwssn->application_protocol].configured == 1)
        {
            InitFlushMgr(&tmp->client.flush_mgr,
                     &tmp->client.tcp_policy->flush_point_list,
                     tmp->client.tcp_policy->flush_config_protocol[lwssn->application_protocol].client.flush_policy);
        }
        else
        {
#endif
            InitFlushMgr(&tmp->client.flush_mgr,
                     &tmp->client.tcp_policy->flush_point_list,
                     tmp->client.tcp_policy->flush_config[server_port].server.flush_policy);
#ifdef TARGET_BASED
        }
#endif

#ifdef DEBUG_STREAM5
        PrintTcpSession(tmp);
#endif
        Stream5SetExpire(p, lwssn, dstPolicy->session_timeout);

        s5stats.tcp_streamtrackers_created++;

        AddStreamSession(&sfPerf.sfBase, lwssn->session_state & STREAM5_STATE_MIDSTREAM ? SSNFLAG_MIDSTREAM : 0);

        Stream5UpdatePerfBaseState(&sfPerf.sfBase, tmp->lwssn, TCP_STATE_SYN_SENT);

        PREPROC_PROFILE_END(s5TcpNewSessPerfStats);
        return 1;
    }

    PREPROC_PROFILE_END(s5TcpNewSessPerfStats);
    return 0;
}

static int RepeatedSyn(StreamTracker *listener,
                       StreamTracker *talker,
                       TcpDataBlock *tdb,
                       TcpSession *tcpssn)
{
    switch (listener->os_policy)
    {
    case STREAM_POLICY_WINDOWS:
    case STREAM_POLICY_WINDOWS2K3:
    case STREAM_POLICY_VISTA:
        /* Windows has some strange behaviour here.  If the
         * sequence of the reset is the next expected sequence,
         * it Resets.  Otherwise it ignores the 2nd SYN.
         */
        if (SEQ_EQ(tdb->seq, listener->r_nxt_ack))
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                "Got syn on established windows ssn, which causes Reset,"
                "bailing\n"););
            tcpssn->lwssn->session_flags |= SSNFLAG_RESET;
            talker->s_mgr.state = TCP_STATE_CLOSED;
            return ACTION_RST;
        }
        else
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                "Got syn on established windows ssn, not causing Reset,"
                "bailing\n"););
            s5stats.tcp_discards++;
            return ACTION_NOTHING;
        }
        break;
    case STREAM_POLICY_MACOS:
        /* MACOS ignores a 2nd SYN, regardless of the sequence number. */
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
            "Got syn on established macos ssn, not causing Reset,"
            "bailing\n"););
        s5stats.tcp_discards++;
        return ACTION_NOTHING;
        break;
    case STREAM_POLICY_FIRST:
    case STREAM_POLICY_LAST:
    /* Uh, who knows */
    case STREAM_POLICY_LINUX:
    case STREAM_POLICY_OLD_LINUX:
    case STREAM_POLICY_BSD:
    case STREAM_POLICY_SOLARIS:
    case STREAM_POLICY_HPUX11:
    case STREAM_POLICY_HPUX10:
    case STREAM_POLICY_IRIX:
        /* If its not a retransmission of the actual SYN... RESET */
        if(!SEQ_EQ(tdb->seq,talker->isn))
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                "Got syn on established ssn, which causes Reset, bailing\n"););
            tcpssn->lwssn->session_flags |= SSNFLAG_RESET;
            talker->s_mgr.state = TCP_STATE_CLOSED;
            return ACTION_RST;
        }
        else
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                "Got syn on established ssn, not causing Reset,"
                "bailing\n"););
            s5stats.tcp_discards++;
            return ACTION_NOTHING;
        }
        break;
    }
    return ACTION_NOTHING;
}

static void LogTcpEvents(Stream5TcpPolicy *s5TcpPolicy, int eventcode)
{
    if (eventcode & EVENT_SYN_ON_EST)
        EventSynOnEst(s5TcpPolicy);

    if (eventcode & EVENT_DATA_ON_SYN)
        EventDataOnSyn(s5TcpPolicy);

    if (eventcode & EVENT_DATA_ON_CLOSED)
        EventDataOnClosed(s5TcpPolicy);

    if (eventcode & EVENT_BAD_TIMESTAMP)
        EventBadTimestamp(s5TcpPolicy);

    if (eventcode & EVENT_BAD_SEGMENT)
        EventBadSegment(s5TcpPolicy);

    if (eventcode & EVENT_WINDOW_TOO_LARGE)
        EventWindowTooLarge(s5TcpPolicy);

    if (eventcode & EVENT_EXCESSIVE_TCP_OVERLAPS)
        EventExcessiveOverlap(s5TcpPolicy);

    if (eventcode & EVENT_DATA_AFTER_RESET)
        EventDataAfterReset(s5TcpPolicy);

    if (eventcode & EVENT_SESSION_HIJACK_CLIENT)
        EventSessionHijackedClient(s5TcpPolicy);

    if (eventcode & EVENT_SESSION_HIJACK_SERVER)
        EventSessionHijackedServer(s5TcpPolicy);

    if (eventcode & EVENT_DATA_WITHOUT_FLAGS)
        EventDataWithoutFlags(s5TcpPolicy);
}

static int ProcessTcp(Stream5LWSession *lwssn, Packet *p, TcpDataBlock *tdb, 
        Stream5TcpPolicy *s5TcpPolicy)
{
    int retcode = 0;
    int eventcode = 0;
    char ignore = 0;
    int got_ts = 0;
    int ts_action = ACTION_NOTHING;
    int aligned = S5_UNALIGNED;
    TcpSession *tcpssn = NULL;
    StreamTracker *talker = NULL;
    StreamTracker *listener = NULL;
    u_int32_t require3Way = (s5TcpPolicy->flags & STREAM5_CONFIG_REQUIRE_3WHS);
#ifdef DEBUG_STREAM5
    char *t = NULL;
    char *l = NULL;
#endif
    PROFILE_VARS;

    if (lwssn->protocol != IPPROTO_TCP)
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Lightweight session not TCP on TCP packet\n"););
        return ACTION_NOTHING;
    }

    if (InlineMode() &&
        (lwssn->session_flags & (SSNFLAG_DROP_CLIENT|SSNFLAG_DROP_SERVER)))
    {
        /* figure out direction of this packet */
        GetLWPacketDirection(p, lwssn);
        /* Got a packet on a session that was dropped (by a rule). */

        /* TODO: Send reset to other side if not already done for inline mode */
        //if (!(lwssn->session_flags & SSNFLAG_SERVER_RESET)
        //{
        //    Send Server Reset
        //    lwssn->session_state |= STREAM5_STATE_SERVER_RESET;
        //}
        //if (!(lwssn->session_flags & SSNFLAG_CLIENT_RESET)
        //{
        //    Send Client Reset
        //    lwssn->session_state |= STREAM5_STATE_CLIENT_RESET;
        //}
        /* Drop this packet */
        if (((p->packet_flags & PKT_FROM_SERVER) &&
             (lwssn->session_flags & SSNFLAG_DROP_SERVER)) ||
            ((p->packet_flags & PKT_FROM_CLIENT) &&
             (lwssn->session_flags & SSNFLAG_DROP_CLIENT)))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                        "Blocking %s packet as session was blocked\n",
                        p->packet_flags & PKT_FROM_SERVER ?
                        "server" : "client"););
            DisableDetect(p);
            /* Still want to add this number of bytes to totals */
            SetPreprocBit(p, PP_PERFMONITOR);
            InlineDrop(p);
            return ACTION_NOTHING;
        }
    }

    if (lwssn->proto_specific_data)
        tcpssn = (TcpSession *)lwssn->proto_specific_data->data;

    PREPROC_PROFILE_START(s5TcpStatePerfStats);

    if (tcpssn == NULL)
    {
        if (p->tcph->th_flags == TH_SYN)
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Stream5 SYN PACKET, establishing lightweight"
                    "session direction.\n"););
            /* SYN packet from client */
            lwssn->direction = FROM_CLIENT;
            IP_COPY_VALUE(lwssn->client_ip, GET_SRC_IP(p));
            lwssn->client_port = p->tcph->th_sport;
            IP_COPY_VALUE(lwssn->server_ip, GET_DST_IP(p));
            lwssn->server_port = p->tcph->th_dport;
            lwssn->session_state |= STREAM5_STATE_SYN;
            if (require3Way || (Stream5PacketHasWscale(p) & TF_WSCALE) ||
                ((p->dsize > 0) &&
                 (StreamGetPolicy(lwssn, s5TcpPolicy, FROM_CLIENT) ==
                     STREAM_POLICY_MACOS)))
            {
                /* Create TCP session if we 
                 * 1) require 3-WAY HS, OR
                 * 2) client sent wscale option, OR
                 * 3) have data and its a MAC OS policy -- MAC
                 *    is the only one that accepts data on SYN
                 *    (and thus requires a TCP session at this point)
                 */
                NewTcpSession(p, lwssn, tdb, s5TcpPolicy);
                tcpssn = (TcpSession *)lwssn->proto_specific_data->data;
            }

            /* Nothing left todo here */
        }
        else if (TCP_ISFLAGSET(p->tcph, TH_SYN|TH_ACK))
        {
            /* SYN-ACK from server */
            if ((lwssn->session_state == STREAM5_STATE_NONE) ||
                (lwssn->session_flags & SSNFLAG_RESET))
            {
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                        "Stream5 SYN|ACK PACKET, establishing lightweight"
                        "session direction.\n"););
                lwssn->direction = FROM_SERVER;
                IP_COPY_VALUE(lwssn->client_ip, GET_DST_IP(p));
                lwssn->client_port = p->tcph->th_dport;
                IP_COPY_VALUE(lwssn->server_ip, GET_SRC_IP(p));
                lwssn->server_port = p->tcph->th_sport;
            }
            lwssn->session_state |= STREAM5_STATE_SYN_ACK;
            if (!require3Way)
            {
                NewTcpSession(p, lwssn, tdb, s5TcpPolicy);
                tcpssn = (TcpSession *)lwssn->proto_specific_data->data;
            }

            /* Nothing left todo here */
        }
        else if ((p->tcph->th_flags == TH_ACK) &&
                 (lwssn->session_state & STREAM5_STATE_SYN_ACK))
        {
            /* TODO: do we need to verify the ACK field is >= the seq of the SYN-ACK? */

            /* 3-way Handshake complete, create TCP session */
            lwssn->session_state |= STREAM5_STATE_ACK | STREAM5_STATE_ESTABLISHED;
            NewTcpSession(p, lwssn, tdb, s5TcpPolicy);
            tcpssn = (TcpSession *)lwssn->proto_specific_data->data;
            Stream5UpdatePerfBaseState(&sfPerf.sfBase, tcpssn->lwssn, TCP_STATE_ESTABLISHED);
        }
        else if ((p->dsize > 0) && (!require3Way || midstream_allowed))
        {
            /* create session on data, need to figure out direction, etc */
            /* Assume from client, can update later */
            if (p->sp > p->dp)
            {
                lwssn->direction = FROM_CLIENT;
                IP_COPY_VALUE(lwssn->client_ip, GET_SRC_IP(p));
                lwssn->client_port = p->tcph->th_sport;
                IP_COPY_VALUE(lwssn->server_ip, GET_DST_IP(p));
                lwssn->server_port = p->tcph->th_dport;
            }
            else
            {
                lwssn->direction = FROM_SERVER;
                IP_COPY_VALUE(lwssn->client_ip, GET_DST_IP(p));
                lwssn->client_port = p->tcph->th_dport;
                IP_COPY_VALUE(lwssn->server_ip, GET_SRC_IP(p));
                lwssn->server_port = p->tcph->th_sport;
            }
            lwssn->session_state |= STREAM5_STATE_MIDSTREAM;
            lwssn->session_flags |= SSNFLAG_MIDSTREAM;

#ifdef DEBUG
            if (pv.readmode_flag)
            {
                /* If we're in readback mode... may only have one packet.
                 * That being packet with the exploit being tested, so
                 * mark this session as established, so rule option
                 * 'flow:established' works correctly.
                 */
                STREAM5_DEBUG_WRAP(
                    char timestamp[TIMEBUF_SIZE];
                    char src_addr[17];
                    char dst_addr[17];
                    bzero((char *)timestamp, TIMEBUF_SIZE);
                    ts_print((struct timeval *) &p->pkth->ts, timestamp);
                    SnortSnprintf(src_addr, 17, "%s",
                        inet_ntoa(GET_SRC_ADDR(p)));
                    SnortSnprintf(dst_addr, 17, "%s",
                        inet_ntoa(GET_DST_ADDR(p)));
                    DebugMessage(DEBUG_STREAM_STATE, "Session not established"
                        "on midstream-pickup of data packet.  Will be marked"
                        "as established when other side is seen. Packet Info:"
                        "Time: %s\tSrc: %s:%d\tDst: %s:%d\n",
                        timestamp, src_addr, p->sp, dst_addr, p->dp);

                    );
#ifdef MIMIC_STREAM4_MIDSTREAM_BEHAVIOUR
                lwssn->session_state |= STREAM5_STATE_ESTABLISHED;
                lwssn->session_flags |= SSNFLAG_ESTABLISHED;
#endif
            }
#endif

            NewTcpSession(p, lwssn, tdb, s5TcpPolicy);
            tcpssn = (TcpSession *)lwssn->proto_specific_data->data;
            if (lwssn->session_state & STREAM5_STATE_ESTABLISHED)
                Stream5UpdatePerfBaseState(&sfPerf.sfBase, tcpssn->lwssn, TCP_STATE_ESTABLISHED);
        }
        else if (p->dsize == 0)
        {
            /* Already have a lwssn, but no tcp session.
             * Probably just an ACK of already sent data (that
             * we missed).
             */
            /* Do nothing. */
            PREPROC_PROFILE_END(s5TcpStatePerfStats);
            return ACTION_NOTHING | retcode;
        }
    }
    else
    {
        /* If session is already marked as established */
        if (!(lwssn->session_state & STREAM5_STATE_ESTABLISHED) && !require3Way)
        {
            /* If not requiring 3-way Handshake... */
    
            /* TCP session created on TH_SYN above,
             * or maybe on SYN-ACK, or anything else */
    
            /* Need to update Lightweight session state */
            if (TCP_ISFLAGSET(p->tcph, TH_SYN|TH_ACK))
            {
                /* SYN-ACK from server */
                if (lwssn->session_state != STREAM5_STATE_NONE)
                {
                    lwssn->session_state |= STREAM5_STATE_SYN_ACK;
                }
            }
            else if ((p->tcph->th_flags == TH_ACK) &&
                     (lwssn->session_state & STREAM5_STATE_SYN_ACK))
            {
                lwssn->session_state |= STREAM5_STATE_ACK | STREAM5_STATE_ESTABLISHED;
                Stream5UpdatePerfBaseState(&sfPerf.sfBase, tcpssn->lwssn, TCP_STATE_ESTABLISHED);
            }
        }
    }

    /* figure out direction of this packet */
    GetLWPacketDirection(p, lwssn);

    if(p->packet_flags & PKT_FROM_SERVER)
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Stream5: Updating on packet from server\n"););
        lwssn->session_flags |= SSNFLAG_SEEN_SERVER;
        if (tcpssn)
        {
            talker = &tcpssn->server;
            listener = &tcpssn->client;
        }

        STREAM5_DEBUG_WRAP(
                t = "Server";
                l = "Client");

        /* If we picked this guy up midstream, finish the initialization */
        if ((lwssn->session_state & STREAM5_STATE_MIDSTREAM) &&
            !(lwssn->session_state & STREAM5_STATE_ESTABLISHED))
        {
            FinishServerInit(p, tdb, tcpssn);
            if((p->tcph->th_flags & TH_ECE) && 
                lwssn->session_flags & SSNFLAG_ECN_CLIENT_QUERY)
            {
                lwssn->session_flags |= SSNFLAG_ECN_SERVER_REPLY;
            }
            
            if (lwssn->session_flags & SSNFLAG_SEEN_CLIENT)
            {
                lwssn->session_state |= STREAM5_STATE_ESTABLISHED;
                lwssn->session_flags |= SSNFLAG_ESTABLISHED;
                Stream5UpdatePerfBaseState(&sfPerf.sfBase, tcpssn->lwssn, TCP_STATE_ESTABLISHED);
            }
        }
    }
    else
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Stream5: Updating on packet from client\n"););
        /* if we got here we had to see the SYN already... */
        lwssn->session_flags |= SSNFLAG_SEEN_CLIENT;
        if (tcpssn)
        {
            talker = &tcpssn->client;
            listener = &tcpssn->server;
        }

        STREAM5_DEBUG_WRAP(
                t = "Client";
                l = "Server";);

        if ((lwssn->session_state & STREAM5_STATE_MIDSTREAM) &&
            !(lwssn->session_state & STREAM5_STATE_ESTABLISHED))
        {
            /* Midstream and seen server. */
            if (lwssn->session_flags & SSNFLAG_SEEN_SERVER)
            {
                lwssn->session_state |= STREAM5_STATE_ESTABLISHED;
                lwssn->session_flags |= SSNFLAG_ESTABLISHED;
            }
        }
    }

    /*
     * check for SYN on reset session
     */
    if ((lwssn->session_flags & SSNFLAG_RESET) &&
        (p->tcph->th_flags & TH_SYN))
    {
        if ((!tcpssn) ||
            ((listener->s_mgr.state == TCP_STATE_CLOSED) ||
             (talker->s_mgr.state == TCP_STATE_CLOSED)))
        {
            /* Listener previously issued a reset */
            /* Talker is re-SYN-ing */

            TcpSessionCleanup(lwssn);

            if (p->tcph->th_flags & TH_RST)
            {
                /* Got SYN/RST.  We're done. */
                tcpssn = NULL;
                PREPROC_PROFILE_END(s5TcpStatePerfStats);
                return ACTION_RST;
            }
            else if (p->tcph->th_flags == TH_SYN)
            {
                lwssn->direction = FROM_CLIENT;
                IP_COPY_VALUE(lwssn->client_ip, GET_SRC_IP(p));
                lwssn->client_port = p->tcph->th_sport;
                IP_COPY_VALUE(lwssn->server_ip, GET_DST_IP(p));
                lwssn->server_port = p->tcph->th_dport;
                lwssn->session_state = STREAM5_STATE_SYN;
                NewTcpSession(p, lwssn, tdb, s5TcpPolicy);

                tcpssn = (TcpSession *)lwssn->proto_specific_data->data;

                if (tcpssn)
                {
                    listener = &tcpssn->server;
                    talker = &tcpssn->client;
                }
                lwssn->session_flags = SSNFLAG_SEEN_CLIENT;
            }
            else if (p->tcph->th_flags == (TH_SYN|TH_ACK))
            {
                lwssn->direction = FROM_SERVER;
                IP_COPY_VALUE(lwssn->client_ip, GET_DST_IP(p));
                lwssn->client_port = p->tcph->th_dport;
                IP_COPY_VALUE(lwssn->server_ip, GET_SRC_IP(p));
                lwssn->server_port = p->tcph->th_sport;
                lwssn->session_state = STREAM5_STATE_SYN_ACK;
                NewTcpSession(p, lwssn, tdb, s5TcpPolicy);

                tcpssn = (TcpSession *)lwssn->proto_specific_data->data;

                if (tcpssn)
                {
                    listener = &tcpssn->client;
                    talker = &tcpssn->server;
                }
                lwssn->session_flags = SSNFLAG_SEEN_SERVER;
            }
        }
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Got SYN pkt on reset ssn, re-SYN-ing\n"););
    }

    if (((p->packet_flags & PKT_FROM_SERVER) && (lwssn->ignore_direction & SSN_DIR_CLIENT)) ||
        ((p->packet_flags & PKT_FROM_CLIENT) && (lwssn->ignore_direction & SSN_DIR_SERVER)))
    {
        if (talker && (talker->flags & TF_FORCE_FLUSH))
        {
            Stream5FlushTalker(p, lwssn);
            talker->flags &= ~TF_FORCE_FLUSH;
        }

        if (listener && (listener->flags & TF_FORCE_FLUSH))
        {
            Stream5FlushListener(p, lwssn);
            listener->flags &= ~TF_FORCE_FLUSH;
        }

        Stream5DisableInspection(lwssn, p);
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Stream5 Ignoring packet from %d. "
                    "Session marked as ignore\n",
                    p->packet_flags & PKT_FROM_SERVER? "server" : "client"););
        PREPROC_PROFILE_END(s5TcpStatePerfStats);
        return ACTION_NOTHING;
    }

    /* Check if the session is to be ignored */
    ignore = CheckIgnoreChannel(p);
    if (ignore)
    {
        /* Set the directions to ignore... */
        lwssn->ignore_direction = ignore;
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Stream5: Ignoring packet from %d. "
                    "Marking session marked as ignore.\n",
                    p->packet_flags & PKT_FROM_SERVER? "server" : "client"););
        Stream5DisableInspection(lwssn, p);
        PREPROC_PROFILE_END(s5TcpStatePerfStats);
        return ACTION_NOTHING;
    }


    /* Handle data on SYN */
    if ((p->dsize) && TCP_ISFLAGSET(p->tcph, TH_SYN))
    {
        /* MacOS accepts data on SYN, so don't alert if policy is MACOS */
        if (StreamGetPolicy(lwssn, s5TcpPolicy, FROM_CLIENT) !=
            STREAM_POLICY_MACOS)
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                "Got data on SYN packet, not processing it\n"););
            //EventDataOnSyn(s5TcpPolicy);
            eventcode |= EVENT_DATA_ON_SYN;
            retcode |= ACTION_BAD_PKT;
        }
    }

    if (!tcpssn)
    {
        LogTcpEvents(s5TcpPolicy, eventcode);
        PREPROC_PROFILE_END(s5TcpStatePerfStats);
        return ACTION_NOTHING | retcode;
    }

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                "   %s [talker] state: %s\n", t, 
                state_names[talker->s_mgr.state]););
    STREAM5_DEBUG_WRAP(PrintFlushMgr(&talker->flush_mgr););
    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                "   %s state: %s(%d)\n", l, 
                state_names[listener->s_mgr.state], 
                listener->s_mgr.state););
    STREAM5_DEBUG_WRAP(PrintFlushMgr(&listener->flush_mgr););

    /*
     * process SYN ACK on unestablished sessions
     */
    if(TCP_STATE_SYN_SENT == listener->s_mgr.state)
    {
        if(p->tcph->th_flags & TH_ACK)
        {
            /* 
             * make sure we've got a valid segment 
             */
            if(!IsBetween(listener->l_unackd, listener->l_nxt_seq, tdb->ack))
            {
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                            "Pkt ack is out of bounds, bailing!\n"););
                s5stats.tcp_discards++;
                LogTcpEvents(listener->tcp_policy, eventcode);
                PREPROC_PROFILE_END(s5TcpStatePerfStats);
                return ACTION_BAD_PKT;
            }
        }

        talker->flags |= Stream5GetTcpTimestamp(p, &tdb->ts);
        if (tdb->ts == 0)
            talker->flags |= TF_TSTAMP_ZERO;

        /*
         * catch resets sent by server 
         */
        if(p->tcph->th_flags & TH_RST)
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                        "got RST\n"););
            /* Reset is valid when in SYN_SENT if the
             * ack field ACKs the SYN.
             */
            if(ValidRst(listener, tdb))
            {
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                            "got RST, closing talker\n"););
                /* Reset is valid */
                /* Mark session as reset... Leave it around so that any
                 * additional data sent from one side or the other isn't
                 * processed (and is dropped in inline mode).
                 */
                lwssn->session_flags |= SSNFLAG_RESET;
                talker->s_mgr.state = TCP_STATE_CLOSED;
                Stream5UpdatePerfBaseState(&sfPerf.sfBase, tcpssn->lwssn, TCP_STATE_CLOSING);
                /* Leave listener open, data may be in transit */
                LogTcpEvents(listener->tcp_policy, eventcode);
                PREPROC_PROFILE_END(s5TcpStatePerfStats);
                return ACTION_RST;
            }
            /* Reset not valid. */
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                        "bad sequence number, bailing\n"););
            s5stats.tcp_discards++;
            LogTcpEvents(listener->tcp_policy, eventcode);
            PREPROC_PROFILE_END(s5TcpStatePerfStats);
            return ACTION_NOTHING;
        }

        /*
         * finish up server init
         */
        if(p->tcph->th_flags & TH_SYN)
        {
            FinishServerInit(p, tdb, tcpssn);
            if (talker->flags & TF_TSTAMP)
            {
                talker->ts_last_pkt = p->pkth->ts.tv_sec;
                talker->ts_last = tdb->ts;
            }
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                        "Finish server init got called!\n"););
        }
        else
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                        "Finish server init didn't get called!\n"););
        }

        if((p->tcph->th_flags & TH_ECE) && 
            lwssn->session_flags & SSNFLAG_ECN_CLIENT_QUERY)
        {
            lwssn->session_flags |= SSNFLAG_ECN_SERVER_REPLY;
        }

        /*
         * explicitly set the state
         */
        listener->s_mgr.state = TCP_STATE_SYN_SENT;
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Accepted SYN ACK\n"););
        LogTcpEvents(listener->tcp_policy, eventcode);
        PREPROC_PROFILE_END(s5TcpStatePerfStats);
        return ACTION_NOTHING;
    }

    /*
     * scale the window.  Only if BOTH client and server specified
     * wscale option as part of 3-way handshake.
     * This is per RFC 1323.
     */
    if ((talker->flags & TF_WSCALE) && (listener->flags & TF_WSCALE))
    {
        tdb->win <<= talker->wscale;
    }

    /* Check for session hijacking -- compare mac address to the ones
     * that were recorded at session startup.
     */
    if (listener->tcp_policy->flags & STREAM5_CONFIG_CHECK_SESSION_HIJACKING)
    {
        eventcode |= ValidMacAddress(talker, listener, p);
    }

    /* Check timestamps */
    ts_action = ValidTimestamp(talker, listener, tdb, p, &eventcode, &got_ts);

    /*
     * check RST validity
     */
    if(p->tcph->th_flags & TH_RST)
    {
        if(ValidRst(listener, tdb) && (ts_action == ACTION_NOTHING))
        {
            /* RST only valid if Timestamp is valid */
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Got RST, bailing\n"););
            lwssn->session_flags |= SSNFLAG_RESET;
            talker->s_mgr.state = TCP_STATE_CLOSED;
            Stream5UpdatePerfBaseState(&sfPerf.sfBase, tcpssn->lwssn, TCP_STATE_CLOSING);
            /* Leave listener open, data may be in transit */
            LogTcpEvents(listener->tcp_policy, eventcode);
            PREPROC_PROFILE_END(s5TcpStatePerfStats);
            return ACTION_RST;
        }
        /* Reset not valid. */
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "bad sequence number, bailing\n"););
        s5stats.tcp_discards++;
        LogTcpEvents(listener->tcp_policy, eventcode);
        PREPROC_PROFILE_END(s5TcpStatePerfStats);
        return ACTION_NOTHING | ts_action;
    }
    else
    {
        /* check for valid seqeuence/retrans */
        if(!ValidSeq(listener, tdb))
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                        "bad sequence number, bailing\n"););
            s5stats.tcp_discards++;
            LogTcpEvents(listener->tcp_policy, eventcode);
            PREPROC_PROFILE_END(s5TcpStatePerfStats);
            return ACTION_NOTHING | ts_action;
        }
    }

    if (ts_action != ACTION_NOTHING)
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "bad timestamp, bailing\n"););
        s5stats.tcp_discards++;
        LogTcpEvents(listener->tcp_policy, eventcode);
        PREPROC_PROFILE_END(s5TcpStatePerfStats);
        return ts_action;
    }

    /*
     * update PAWS timestamps
     */
    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                "PAWS update tdb->seq %lu > listener->r_win_base %lu\n",
                tdb->seq, listener->r_win_base););
    if(got_ts && SEQ_EQ(listener->r_nxt_ack, tdb->seq))
    {
        if((int32_t)(tdb->ts - talker->ts_last) >= 0 ||
           (u_int32_t)p->pkth->ts.tv_sec >= talker->ts_last_pkt+PAWS_24DAYS)
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                        "updating timestamps...\n"););
            talker->ts_last = tdb->ts;
            talker->ts_last_pkt = p->pkth->ts.tv_sec;
        }
    }
    else
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "not updating timestamps...\n"););
    }

    /*
     * check for repeat SYNs 
     */
    if(p->tcph->th_flags & TH_SYN)
    {
        int action = RepeatedSyn(listener, talker, tdb, tcpssn);

        if (action != ACTION_NOTHING)
        {
            /* got a bad SYN on the session, alert! */
            eventcode |= EVENT_SYN_ON_EST;
            LogTcpEvents(listener->tcp_policy, eventcode);
            PREPROC_PROFILE_END(s5TcpStatePerfStats);
            return action;
        }
    }

    /*
     * Check that the window is within the limits
     */
    if (listener->tcp_policy->max_window && (tdb->win > listener->tcp_policy->max_window))
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Got window that was beyond the allowed policy value, bailing\n"););
        /* got a window too large, alert! */
        eventcode |= EVENT_WINDOW_TOO_LARGE;
        s5stats.tcp_discards++;
        LogTcpEvents(listener->tcp_policy, eventcode);
        PREPROC_PROFILE_END(s5TcpStatePerfStats);
        return ACTION_NOTHING | ACTION_BAD_PKT;
    }

    if(talker->s_mgr.state_queue != TCP_STATE_NONE)
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Found queued state transition on ack 0x%X, "
                    "current 0x%X!\n", talker->s_mgr.transition_seq, 
                    tdb->ack););
        if(tdb->ack == talker->s_mgr.transition_seq)
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                        "accepting transition!\n"););
            talker->s_mgr.state = talker->s_mgr.state_queue;
            talker->s_mgr.state_queue = TCP_STATE_NONE;
        }
    }
    
    /* 
     * process ACK flags
     */
    if(p->tcph->th_flags & TH_ACK)
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Got an ACK...\n"););
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "   %s [listener] state: %s\n", l, 
                    state_names[listener->s_mgr.state]););
        switch(listener->s_mgr.state)
        {
            case TCP_STATE_SYN_RCVD:
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                            "listener state is SYN_SENT...\n"););
                if(IsBetween(listener->l_unackd, listener->l_nxt_seq, tdb->ack))
                {
                    UpdateSsn(listener, talker, tdb);
                    lwssn->session_flags |= SSNFLAG_ESTABLISHED;
                    lwssn->session_state |= STREAM5_STATE_ESTABLISHED;
                    listener->s_mgr.state = TCP_STATE_ESTABLISHED;
                    talker->s_mgr.state = TCP_STATE_ESTABLISHED;
                    Stream5UpdatePerfBaseState(&sfPerf.sfBase, tcpssn->lwssn, TCP_STATE_ESTABLISHED);
                    //ssn_rate.est_rate++;

                    /* Indicate this packet completes 3-way handshake */
                    p->packet_flags |= PKT_STREAM_TWH;
                }

                talker->flags |= got_ts;
                if(got_ts && SEQ_EQ(listener->r_nxt_ack, tdb->seq))
                {
                    talker->ts_last_pkt = p->pkth->ts.tv_sec;
                    talker->ts_last = tdb->ts;
                }

                break;

            case TCP_STATE_ESTABLISHED:
                /* If we picked this guy up after the initial SYN,
                 * set the client ttl */
                if ((talker == &tcpssn->client) && 
                    (talker->ttl == 0))
                    talker->ttl = GET_IPH_TTL(p);
                /* Fall through */

            case TCP_STATE_CLOSE_WAIT:
                UpdateSsn(listener, talker, tdb);
                break;

            case TCP_STATE_FIN_WAIT_1:
                UpdateSsn(listener, talker, tdb);

                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                            "tdb->ack %X >= talker->r_nxt_ack %X\n",
                            tdb->ack, talker->r_nxt_ack););
                if(SEQ_GEQ(tdb->ack, talker->r_nxt_ack) &&
                    (p->tcph->th_flags & TH_FIN))
                {
                    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                                "seq ok, setting state!\n"););

                    if (talker->s_mgr.state_queue == TCP_STATE_NONE)
                    {
                        talker->s_mgr.state = TCP_STATE_LAST_ACK;
                        if (listener->s_mgr.state_queue == TCP_STATE_NONE)
                        {
                            listener->s_mgr.state = TCP_STATE_FIN_WAIT_2;
                        }
                    }                  
                }
                else
                {
                    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                                "seq bad!\n"););
                }
                break;

            case TCP_STATE_FIN_WAIT_2:
                if(SEQ_GEQ(tdb->end_seq, listener->r_nxt_ack))
                {
                    if (listener->s_mgr.state_queue == TCP_STATE_NONE)
                    {
                        listener->s_mgr.state = TCP_STATE_TIME_WAIT;
                    }
                }
                break;

            case TCP_STATE_CLOSING:
                UpdateSsn(listener, talker, tdb);
                if(SEQ_GEQ(tdb->end_seq, listener->r_nxt_ack))
                {
                    listener->s_mgr.state = TCP_STATE_TIME_WAIT;
                }
                break;

            case TCP_STATE_LAST_ACK:
                if(SEQ_GEQ(tdb->end_seq, listener->r_nxt_ack))
                {
                    listener->s_mgr.state = TCP_STATE_CLOSED;
                }
                break;

            default:
                break;
        }
    }

    /*
     * handle data in the segment
     */
    if(p->dsize)
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "   %s state: %s(%d) getting data\n", l, 
                    state_names[listener->s_mgr.state], 
                    listener->s_mgr.state););

        if(TCP_STATE_CLOSE_WAIT == listener->s_mgr.state || 
           TCP_STATE_LAST_ACK == listener->s_mgr.state   || 
           TCP_STATE_CLOSING == listener->s_mgr.state    || 
           TCP_STATE_TIME_WAIT == listener->s_mgr.state)
        {
            /* data on a segment when we're not accepting data any more */
            /* alert! */
            //EventDataOnClosed(listener->tcp_policy);
            eventcode |= EVENT_DATA_ON_CLOSED;
            retcode |= ACTION_BAD_PKT;
        }
        else if (TCP_STATE_CLOSED == talker->s_mgr.state)
        {
            /* data on a segment when we're not accepting data any more */
            /* alert! */
            if (lwssn->session_flags & SSNFLAG_RESET)
            {
                //EventDataAfterReset(listener->tcp_policy);
                eventcode |= EVENT_DATA_AFTER_RESET;
            }
            else
            {
                //EventDataOnClosed(listener->tcp_policy);
                eventcode |= EVENT_DATA_ON_CLOSED;
            }
            retcode |= ACTION_BAD_PKT;
        }
        else
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                        "Queuing data on listener, t %s, l %s...\n",
                        flush_policy_names[talker->flush_mgr.flush_policy],
                        flush_policy_names[listener->flush_mgr.flush_policy]););
            /* 
             * dunno if this is RFC but fragroute testing expects it
             * for the record, I've seen FTP data sessions that send
             * data packets with no tcp flags set
             */
            if ((p->tcph->th_flags != 0) || (s5TcpPolicy->policy == STREAM_POLICY_LINUX))
            {
                aligned = ProcessTcpData(p, listener, tcpssn, tdb, s5TcpPolicy);
            }
            else
            {
                eventcode |= EVENT_DATA_WITHOUT_FLAGS;
            }
        }
    }

    if(p->tcph->th_flags & TH_FIN)
    {
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Got an FIN...\n"););
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "   %s state: %s(%d)\n", l, 
                    state_names[talker->s_mgr.state], 
                    talker->s_mgr.state););

        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "checking ack (0x%X) vs nxt_ack (0x%X)\n",
                    tdb->seq, listener->r_nxt_ack););
        if(SEQ_LT(tdb->seq,listener->r_nxt_ack))
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                        "FIN inside r_last_ack, bailing\n"););
            goto dupfin;
        }
        else
        {
            listener->r_nxt_ack++;

            switch(talker->s_mgr.state)
            {
                case TCP_STATE_SYN_RCVD:
                case TCP_STATE_ESTABLISHED:

                    if (talker->s_mgr.state_queue == TCP_STATE_CLOSE_WAIT)
                    {
                        /* Talker sent a FIN.  Move him to transition
                         * to closed when he receives the ACK of this FIN.
                         * CLOSED */
                        talker->s_mgr.state_queue = TCP_STATE_CLOSED;
                        talker->s_mgr.transition_seq = tdb->ack + 1;
                        talker->s_mgr.expected_flags = TH_ACK;
                    }
                    else
                    {
                        talker->s_mgr.state = TCP_STATE_FIN_WAIT_1;
                    }
                    Stream5UpdatePerfBaseState(&sfPerf.sfBase, tcpssn->lwssn, TCP_STATE_CLOSING);

                    /* this transition should be queued! */
                    //QueueState(CLOSE_WAIT, listener, TH_ACK, tdb->seq, 1);

                    //listener->s_mgr.state = TCP_STATE_CLOSE_WAIT;
                    if (listener->s_mgr.state == TCP_STATE_FIN_WAIT_1)
                    {
                        /* Simultaneous Close */
                        listener->s_mgr.state_queue = TCP_STATE_TIME_WAIT;
                        listener->s_mgr.transition_seq = tdb->seq + 1;
                        listener->s_mgr.expected_flags = TH_ACK;
                    }
                    else if ((listener->s_mgr.state != TCP_STATE_CLOSED) &&
                             (listener->s_mgr.state != TCP_STATE_TIME_WAIT))
                    {
                        listener->s_mgr.state_queue = TCP_STATE_CLOSE_WAIT;
                        listener->s_mgr.transition_seq = tdb->seq + 1;
                        listener->s_mgr.expected_flags = TH_ACK;
                    }
                    break;

                case TCP_STATE_FIN_WAIT_1:
                    listener->s_mgr.state = TCP_STATE_TIME_WAIT;
                    break;

                case TCP_STATE_FIN_WAIT_2:
                    listener->s_mgr.state = TCP_STATE_TIME_WAIT;
                    break;

                case TCP_STATE_LAST_ACK:
                    listener->s_mgr.state = TCP_STATE_TIME_WAIT;
                    break;

                    /* all other states stay where they are */
                default:
                    break;
            }
        }
    }

dupfin:

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                "   %s [talker] state: %s\n", t, 
                state_names[talker->s_mgr.state]););
    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                "   %s state: %s(%d)\n", l, 
                state_names[listener->s_mgr.state], 
                listener->s_mgr.state););

    /*
     * handle TIME_WAIT timer stuff
     */
    if((talker->s_mgr.state == TCP_STATE_TIME_WAIT && listener->s_mgr.state == TCP_STATE_CLOSED) ||
       (listener->s_mgr.state == TCP_STATE_TIME_WAIT && talker->s_mgr.state == TCP_STATE_CLOSED))
    {
//dropssn:
        STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                    "Session terminating, flushing session buffers\n"););

        if(p->packet_flags & PKT_FROM_SERVER)
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                        "flushing FROM_SERVER\n"););
            if(talker->seg_bytes_logical)
                flush_ackd(tcpssn, talker, p,
                        GET_DST_IP(p), GET_SRC_IP(p),
                        p->tcph->th_dport, p->tcph->th_sport,
                        PKT_FROM_CLIENT);

            if(listener->seg_bytes_logical)
                flush_ackd(tcpssn, listener, p,
                        GET_SRC_IP(p), GET_DST_IP(p),
                        p->tcph->th_sport, p->tcph->th_dport,
                        PKT_FROM_SERVER);
        }
        else
        {
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                        "flushing FROM_CLIENT\n"););
            if(listener->seg_bytes_logical)
            {
                flush_ackd(tcpssn, listener, p,
                        GET_SRC_IP(p), GET_DST_IP(p),
                        p->tcph->th_sport, p->tcph->th_dport,
                        PKT_FROM_CLIENT);
            }
            if(talker->seg_bytes_logical)
            {
                flush_ackd(tcpssn, talker, p,
                        GET_DST_IP(p), GET_SRC_IP(p),
                        p->tcph->th_dport, p->tcph->th_sport,
                        PKT_FROM_SERVER);
            }
        }

        /* yoink that shit */
        LogTcpEvents(listener->tcp_policy, eventcode);
        DeleteLWSession(tcp_lws_cache, lwssn);
        p->ssnptr = NULL;
        PREPROC_PROFILE_END(s5TcpStatePerfStats);
        return ACTION_NOTHING;
    }     
    else if(listener->s_mgr.state == TCP_STATE_CLOSED && talker->s_mgr.state == TCP_STATE_SYN_SENT)
    {
        if(p->tcph->th_flags & TH_SYN &&
           !(p->tcph->th_flags & TH_ACK) &&
           !(p->tcph->th_flags & TH_RST))
        {
            Stream5SetExpire(p, lwssn, s5TcpPolicy->session_timeout);
        }
    }

    CheckFlushPolicy(tcpssn, talker, listener, tdb, p);

    LogTcpEvents(listener->tcp_policy, eventcode);
    PREPROC_PROFILE_END(s5TcpStatePerfStats);
    return ACTION_NOTHING;
}

int CheckFlushPolicy(TcpSession *tcpssn, StreamTracker *talker, 
        StreamTracker *listener, TcpDataBlock *tdb, Packet *p)
{
    u_int32_t flushed = 0;
    u_int32_t dir = 0;

    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                "In CheckFlushPolicy\n"););
    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                "Talker flush policy: %s\n", 
                flush_policy_names[talker->flush_mgr.flush_policy]););
    STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                "Listener flush policy: %s\n", 
                flush_policy_names[listener->flush_mgr.flush_policy]););

    /* Remember, one side's packets are stored in the
     * other side's queue.  So when talker ACKs data,
     * we need to check if we're ready to flush.
     *
     * If we do decide to flush, the flush IP & port info
     * is the opposite of the packet -- again because this
     * is the ACK from the talker and we're flushing packets
     * that actually came from the listener.
     */
    if(p->packet_flags & PKT_FROM_SERVER)
        dir = PKT_FROM_CLIENT;
    else if(p->packet_flags & PKT_FROM_CLIENT)
        dir = PKT_FROM_SERVER;

    switch(talker->flush_mgr.flush_policy)
    {
        case STREAM_FLPOLICY_IGNORE:
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                        "STREAM_FLPOLICY_IGNORE\n"););
            return 0;
            break;

        case STREAM_FLPOLICY_FOOTPRINT:
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                        "STREAM_FLPOLICY_FOOTPRINT\n"););
            if(get_q_footprint(talker) >= talker->flush_mgr.flush_pt)
            {
                flushed = flush_ackd(tcpssn, talker, p,
                        GET_DST_IP(p), GET_SRC_IP(p),
                        p->tcph->th_dport, p->tcph->th_sport, dir);
                if(flushed)
                    purge_ackd(tcpssn, talker);
            }
            break;

        case STREAM_FLPOLICY_LOGICAL:
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                        "STREAM_FLPOLICY_LOGICAL\n"););
            if(talker->seg_bytes_logical > talker->flush_mgr.flush_pt)
            {
                flushed = flush_ackd(tcpssn, talker, p,
                        GET_DST_IP(p), GET_SRC_IP(p),
                        p->tcph->th_dport, p->tcph->th_sport, dir);
                if(flushed)
                    purge_ackd(tcpssn, talker);
            }
            break;

        case STREAM_FLPOLICY_RESPONSE:
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                        "Running FLPOLICY_RESPONSE\n"););
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                        "checking l.r_win_base (0x%X) > "
                        "t.seglist_base_seq (0x%X)\n", 
                        talker->r_win_base, talker->seglist_base_seq););

            if(SEQ_GT(talker->r_win_base, talker->seglist_base_seq) && 
                    IsWellFormed(p, talker))
            {
                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                            "flushing talker, t->sbl: %d\n",
                            talker->seg_bytes_logical););
                //PrintStreamTracker(talker);
                //PrintStreamTracker(talker);

                flushed = flush_ackd(tcpssn, talker, p,
                        GET_DST_IP(p), GET_SRC_IP(p),
                        p->tcph->th_dport, p->tcph->th_sport, dir);

                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                            "bye bye data...\n"););
                if(flushed)
                    purge_ackd(tcpssn, talker);
            }
            break;

        case STREAM_FLPOLICY_SLIDING_WINDOW:
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                        "STREAM_FLPOLICY_SLIDING_WINDOW\n"););
            if(get_q_footprint(talker) >= talker->flush_mgr.flush_pt)
            {
                flushed = flush_ackd(tcpssn, talker, p,
                        GET_DST_IP(p), GET_SRC_IP(p),
                        p->tcph->th_dport, p->tcph->th_sport, dir);

                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                            "Deleting head node for sliding window...\n"););

                /* Base sequence for next window'd flush is the end
                 * of the first packet. */
                talker->seglist_base_seq = talker->seglist->seq + talker->seglist->size;
                Stream5SeglistDeleteNode(talker, talker->seglist);

                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                            "setting talker->seglist_base_seq to 0x%X\n", 
                            talker->seglist->seq););

            }
            break;

#if 0
        case STREAM_FLPOLICY_CONSUMED:
            STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                        "STREAM_FLPOLICY_CONSUMED\n"););
            if(get_q_footprint(talker) >= talker->flush_mgr.flush_pt)
            {
                flushed = flush_ackd(tcpssn, talker, p,
                        p->iph->ip_dst.s_addr, p->iph->ip_src.s_addr,
                        p->tcph->th_dport, p->tcph->th_sport, dir);

                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                            "Deleting head node for sliding window...\n"););

                talker->seglist_base_seq = talker->seglist->seq + talker->seglist->size;
                /* TODO: Delete up to the consumed bytes */
                Stream5SeglistDeleteNode(talker, talker->seglist);

                STREAM5_DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, 
                            "setting talker->seglist_base_seq to 0x%X\n", 
                            talker->seglist->seq););

            }
            break;
#endif

    }
    
    return flushed;
}

static void Stream5SeglistAddNode(StreamTracker *st, StreamSegment *prev,
        StreamSegment *new)
{
    s5stats.tcp_streamsegs_created++;

    if(prev)
    {
        new->next = prev->next;
        new->prev = prev;
        prev->next = new;
        if (new->next)
            new->next->prev = new;
        else
            st->seglist_tail = new;
    }
    else
    {
        new->next = st->seglist;
        if(new->next)
            new->next->prev = new;
        else
            st->seglist_tail = new;
        st->seglist = new;
    }
    st->seg_count++;
#ifdef DEBUG
    new->ordinal = st->segment_ordinal++;
    if (new->next && (new->next->seq == new->seq))
    {
        LogMessage("Same seq to right, check me\n");
    }
#endif
    return;
}

static int Stream5SeglistDeleteNode(StreamTracker *st, StreamSegment *seg)
{
    int ret;

    if(st == NULL || seg == NULL)
        return 0;

    STREAM5_DEBUG_WRAP( DebugMessage(DEBUG_STREAM_STATE,  
                    "Dropping segment at seq %X, len %d\n", 
                    seg->seq, seg->size););
    
    if(seg->prev)
        seg->prev->next = seg->next;
    else
        st->seglist = seg->next;

    if(seg->next)
        seg->next->prev = seg->prev;
    else
        st->seglist_tail = seg->prev;

    st->seg_bytes_logical -= seg->size;
    st->seg_bytes_total -= seg->caplen;

    ret = seg->caplen;

    if (seg->buffered)
    {
        s5stats.tcp_rebuilt_seqs_used++;
    }

    Stream5DropSegment(seg);
    st->seg_count--;

    return ret;
}

void TcpUpdateDirection(Stream5LWSession *ssn, char dir,
                        snort_ip_p ip, u_int16_t port)
{
    TcpSession *tcpssn = (TcpSession *)ssn->proto_specific_data->data;
    snort_ip tmpIp;
    u_int16_t tmpPort;
    StreamTracker tmpTracker;

#ifdef SUP_IP6
    if (IP_EQUALITY(&tcpssn->tcp_client_ip, ip) && (tcpssn->tcp_client_port == port))
    {
        if ((dir == SSN_DIR_CLIENT) && (ssn->direction == SSN_DIR_CLIENT))
        {
            /* Direction already set as client */
            return;
        }
    }
    else if (IP_EQUALITY(&tcpssn->tcp_server_ip, ip) && (tcpssn->tcp_server_port == port))
    {
        if ((dir == SSN_DIR_SERVER) && (ssn->direction == SSN_DIR_SERVER))
        {
            /* Direction already set as server */
            return;
        }
    }
#else
    if (IP_EQUALITY(tcpssn->tcp_client_ip, ip) && (tcpssn->tcp_client_port == port))
    {
        if ((dir == SSN_DIR_CLIENT) && (ssn->direction == SSN_DIR_CLIENT))
        {
            /* Direction already set as client */
            return;
        }
    }
    else if (IP_EQUALITY(tcpssn->tcp_server_ip, ip) && (tcpssn->tcp_server_port == port))
    {
        if ((dir == SSN_DIR_SERVER) && (ssn->direction == SSN_DIR_SERVER))
        {
            /* Direction already set as server */
            return;
        }
    }
#endif

    /* Swap them -- leave ssn->direction the same */

    /* XXX: Gotta be a more efficient way to do this without the memcpy */
    tmpIp = tcpssn->tcp_client_ip;
    tmpPort = tcpssn->tcp_client_port;
    tcpssn->tcp_client_ip = tcpssn->tcp_server_ip;
    tcpssn->tcp_client_port = tcpssn->tcp_server_port;
    tcpssn->tcp_server_ip = tmpIp;
    tcpssn->tcp_server_port = tmpPort;
    memcpy(&tmpTracker, &tcpssn->client, sizeof(StreamTracker));
    memcpy(&tcpssn->client, &tcpssn->server, sizeof(StreamTracker));
    memcpy(&tcpssn->server, &tmpTracker, sizeof(StreamTracker));

}

/* Iterates through the packets that were reassembled for
 * logging of tagged packets.
 */
int GetTcpRebuiltPackets(Packet *p, Stream5LWSession *ssn,
        PacketIterator callback, void *userdata)
{
    int packets = 0;
    TcpSession *tcpssn = (TcpSession *)ssn->proto_specific_data->data;
    StreamTracker *st;
    StreamSegment *ss;

    if (!tcpssn)
    {
        return packets;
    }

    /* StreamTracker is the opposite of the ip of the reassembled
     * packet --> it came out the queue for the other side */
#ifdef SUP_IP6
    if (IP_EQUALITY(GET_SRC_IP(p), &tcpssn->tcp_client_ip))
#else
    if (IP_EQUALITY(GET_SRC_IP(p), tcpssn->tcp_client_ip))
#endif
    {
        st = &tcpssn->server;
    }
    else
    {
        st = &tcpssn->client;
    }

    /* Can stop when we hit a packet that wasn't "buffered"
     * since the segments should be in seq number order */
    for (ss = st->seglist; ss && ss->buffered; ss = ss->next)
    {
        callback(&ss->pkth, ss->pkt, userdata);
        packets++;
    }

    return packets;
}

int Stream5AddSessionAlertTcp(Stream5LWSession *lwssn, Packet *p, u_int32_t gid, u_int32_t sid)
{
    TcpSession *tcpssn = NULL;
    StreamTracker *st;

    if (lwssn->proto_specific_data)
        tcpssn = (TcpSession *)lwssn->proto_specific_data->data;

    if (!tcpssn)
    {
        return 0;
    }

#ifdef SUP_IP6
    if (IP_EQUALITY(GET_SRC_IP(p),&tcpssn->tcp_client_ip))
#else
    if (IP_EQUALITY(GET_SRC_IP(p),tcpssn->tcp_client_ip))
#endif
    {
        st = &tcpssn->server;
    }
    else
    {
        st = &tcpssn->client;
    }

    if (st->alert_count >= MAX_SESSION_ALERTS)
        return 0;

    st->alerts[st->alert_count].gid = gid;
    st->alerts[st->alert_count].sid = sid;
    st->alerts[st->alert_count].seq = p->tcph->th_seq;
    st->alert_count++;

    return 0;
}

int Stream5CheckSessionAlertTcp(Stream5LWSession *lwssn, Packet *p, u_int32_t gid, u_int32_t sid)
{
    TcpSession *tcpssn = NULL;
    StreamTracker *st;
    int i;

    if (lwssn->proto_specific_data)
        tcpssn = (TcpSession *)lwssn->proto_specific_data->data;

    if (!tcpssn)
    {
        return 0;
    }

    /* If this is not a rebuilt packet, no need to check further */
    if (!(p->packet_flags & PKT_REBUILT_STREAM))
    {
        return 0;
    }

#ifdef SUP_IP6
    if (IP_EQUALITY(GET_SRC_IP(p), &tcpssn->tcp_client_ip))
#else
    if (p->iph->ip_src.s_addr == tcpssn->tcp_client_ip)
#endif
    {
        st = &tcpssn->server;
    }
    else
    {
        st = &tcpssn->client;
    }

    for (i=0;i<st->alert_count;i++)
    {
        /*  This is a rebuilt packet and if we've seen this alert before,
         *  return that we have previously alerted on original packet.
         */
        if ( st->alerts[i].gid == gid &&
             st->alerts[i].sid == sid )
        {
            return -1;
        }
    }

    return 0;
}

char Stream5GetReassemblyDirectionTcp(Stream5LWSession *lwssn)
{
    TcpSession *tcpssn = NULL;
    char dir = SSN_DIR_NONE;

    if (!lwssn)
        return SSN_DIR_NONE;

    if (lwssn->proto_specific_data)
        tcpssn = (TcpSession *)lwssn->proto_specific_data->data;

    if (!tcpssn)
        return SSN_DIR_NONE;

    if ((tcpssn->server.flush_mgr.flush_policy != STREAM_FLPOLICY_NONE) &&
        (tcpssn->server.flush_mgr.flush_policy != STREAM_FLPOLICY_IGNORE))
    {
        dir |= SSN_DIR_SERVER;
    }

    if ((tcpssn->client.flush_mgr.flush_policy != STREAM_FLPOLICY_NONE) &&
        (tcpssn->client.flush_mgr.flush_policy != STREAM_FLPOLICY_IGNORE))
    {
        dir |= SSN_DIR_CLIENT;
    }

    return dir;
}

char Stream5SetReassemblyTcp(Stream5LWSession *lwssn,
                                   u_int8_t flush_policy,
                                   char dir,
                                   char flags)
{
    TcpSession *tcpssn = NULL;

    if (!lwssn)
        return SSN_DIR_NONE;

    if (lwssn->proto_specific_data)
        tcpssn = (TcpSession *)lwssn->proto_specific_data->data;

    if (!tcpssn)
        return SSN_DIR_NONE;

    if (flags & STREAM_FLPOLICY_SET_APPEND)
    {
        if (dir & SSN_DIR_CLIENT)
        {
            if (tcpssn->client.flush_mgr.flush_policy != STREAM_FLPOLICY_NONE)
            {
                /* Changing policy with APPEND, Bad */
                DEBUG_WRAP(
                    LogMessage("Stream: Changing client flush policy using "
                            "append is asking for trouble.  Ignored\n"););
            }
            else
            {
                tcpssn->client.flush_mgr.flush_policy = flush_policy;
                /* And Initialize the Flush Mgr */
                InitFlushMgr(&tcpssn->client.flush_mgr,
                    &tcpssn->client.tcp_policy->flush_point_list,
                    flush_policy);
            }
        }

        if (dir & SSN_DIR_SERVER)
        {
            if (tcpssn->server.flush_mgr.flush_policy != STREAM_FLPOLICY_NONE)
            {
                /* Changing policy with APPEND, Bad */
                DEBUG_WRAP(
                    LogMessage("Stream: Changing server flush policy using "
                            "append is asking for trouble.  Ignored\n"););
            }
            else
            {
                tcpssn->server.flush_mgr.flush_policy = flush_policy;
                /* And Initialize the Flush Mgr */
                InitFlushMgr(&tcpssn->server.flush_mgr,
                    &tcpssn->server.tcp_policy->flush_point_list,
                    flush_policy);
            }
        }

    }
    else if (flags & STREAM_FLPOLICY_SET_ABSOLUTE)
    {
        if (dir & SSN_DIR_CLIENT)
        {
            tcpssn->client.flush_mgr.flush_policy = flush_policy;
            /* And Initialize the Flush Mgr */
            InitFlushMgr(&tcpssn->client.flush_mgr,
                &tcpssn->client.tcp_policy->flush_point_list,
                flush_policy);
        }

        if (dir & SSN_DIR_SERVER)
        {
            tcpssn->server.flush_mgr.flush_policy = flush_policy;
            /* And Initialize the Flush Mgr */
            InitFlushMgr(&tcpssn->server.flush_mgr, 
                &tcpssn->server.tcp_policy->flush_point_list,
                flush_policy);
        }
    }

    return Stream5GetReassemblyDirectionTcp(lwssn);
}

char Stream5GetReassemblyFlushPolicyTcp(Stream5LWSession *lwssn, char dir)
{
    TcpSession *tcpssn = NULL;

    if (!lwssn)
        return STREAM_FLPOLICY_NONE;

    if (lwssn->proto_specific_data)
        tcpssn = (TcpSession *)lwssn->proto_specific_data->data;

    if (!tcpssn)
        return STREAM_FLPOLICY_NONE;

    if (dir & SSN_DIR_CLIENT)
    {
        return (char)tcpssn->client.flush_mgr.flush_policy;
    }

    if (dir & SSN_DIR_SERVER)
    {
        return (char)tcpssn->server.flush_mgr.flush_policy;
    }
    return STREAM_FLPOLICY_NONE;
}

char Stream5IsStreamSequencedTcp(Stream5LWSession *lwssn, char dir)
{
    TcpSession *tcpssn = NULL;

    if (!lwssn)
        return 1;

    if (lwssn->proto_specific_data)
        tcpssn = (TcpSession *)lwssn->proto_specific_data->data;

    if (!tcpssn)
        return 1;

    if (dir & SSN_DIR_CLIENT)
    {
        if (tcpssn->server.flags & TF_MISSING_PKT)
            return 0;
    }

    if (dir & SSN_DIR_SERVER)
    {
        if (tcpssn->client.flags & TF_MISSING_PKT)
            return 0;
    }

    return 1;
}

char Stream5MissingInReassembledTcp(Stream5LWSession *lwssn, char dir)
{
    TcpSession *tcpssn = NULL;

    if (!lwssn)
        return 0;

    if (lwssn->proto_specific_data)
        tcpssn = (TcpSession *)lwssn->proto_specific_data->data;

    if (!tcpssn)
        return 0;

    if (dir & SSN_DIR_CLIENT)
    {
        if ((tcpssn->server.flags & TF_MISSING_PKT) &&
            (tcpssn->server.flags & TF_MISSING_PREV_PKT))
            return 3;
        else if (tcpssn->server.flags & TF_MISSING_PREV_PKT)
            return 2;
        else if (tcpssn->server.flags & TF_MISSING_PKT)
            return 1;
    }
    else if (dir & SSN_DIR_SERVER)
    {
        if ((tcpssn->client.flags & TF_MISSING_PKT) &&
            (tcpssn->client.flags & TF_MISSING_PREV_PKT))
            return 3;
        else if (tcpssn->client.flags & TF_MISSING_PREV_PKT)
            return 2;
        else if (tcpssn->client.flags & TF_MISSING_PKT)
            return 1;
    }

    return 0;
}

char Stream5PacketsMissingTcp(Stream5LWSession *lwssn, char dir)
{
    TcpSession *tcpssn = NULL;

    if (!lwssn)
        return 0;

    if (lwssn->proto_specific_data)
        tcpssn = (TcpSession *)lwssn->proto_specific_data->data;

    if (!tcpssn)
        return 0;

    if (dir & SSN_DIR_CLIENT)
    {
        if (tcpssn->server.flags & TF_PKT_MISSED)
            return 1;
    }

    if (dir & SSN_DIR_SERVER)
    {
        if (tcpssn->client.flags & TF_PKT_MISSED)
            return 1;
    }

    return 0;
}

#define SSOD_LESS_THAN 1
#define SSOD_GREATER_THAN 2
#define SSOD_EQUALS 3
#define SSOD_LESS_THAN_OR_EQUALS 4
#define SSOD_GREATER_THAN_OR_EQUALS 5
#define SSOD_NOT_EQUALS 6

#define SSOD_MATCH 1
#define SSOD_NOMATCH 0
typedef struct _StreamSizeOptionData
{
    char operator;
    u_int32_t size;
    char direction;
} StreamSizeOptionData;

int s5TcpStreamSizeInit(char *name, char *parameters, void **dataPtr)
{
    char **toks;
    int num_toks;
    char *endp;
    StreamSizeOptionData *ssod = NULL;
    toks = mSplit(parameters, ",", 4, &num_toks, 0);

    if (num_toks != 3)
    {
        FatalError("%s(%d): Invalid parameters for %s option\n",
            file_name, file_line, name);
        mSplitFree(&toks, num_toks);
    }

    ssod = SnortAlloc(sizeof(StreamSizeOptionData));

    if (!ssod)
    {
        FatalError("%s(%d): Failed to allocate data for %s option\n",
            file_name, file_line, name);
        mSplitFree(&toks, num_toks);
    }

    /* Parse the direction.
     * Can be: client, server, both, either
     */
    if (!strcasecmp(toks[0], "client"))
    {
        ssod->direction = SSN_DIR_CLIENT;
    }
    else if (!strcasecmp(toks[0], "server"))
    {
        ssod->direction = SSN_DIR_SERVER;
    }
    else if (!strcasecmp(toks[0], "both"))
    {
        ssod->direction = SSN_DIR_BOTH;
    }
    else if (!strcasecmp(toks[0], "either"))
    {
        ssod->direction = SSN_DIR_NONE;
    }
    else
    {
        FatalError("%s(%d): Invalid direction: %s for option %s\n", 
            file_name, file_line, toks[0], name);
        free(ssod);
        mSplitFree(&toks, num_toks);
    }

    /* Parse the operator.
     * Can be: =, <, > , !=, <=, >=
     */
    if (!strcasecmp(toks[1], "="))
    {
        ssod->operator = SSOD_EQUALS;
    }
    else if (!strcasecmp(toks[1], "<"))
    {
        ssod->operator = SSOD_LESS_THAN;
    }
    else if (!strcasecmp(toks[1], ">"))
    {
        ssod->operator = SSOD_GREATER_THAN;
    }
    else if (!strcasecmp(toks[1], "!="))
    {
        ssod->operator = SSOD_NOT_EQUALS;
    }
    else if (!strcasecmp(toks[1], "<="))
    {
        ssod->operator = SSOD_LESS_THAN_OR_EQUALS;
    }
    else if (!strcasecmp(toks[1], ">="))
    {
        ssod->operator = SSOD_GREATER_THAN_OR_EQUALS;
    }
    else
    {
        FatalError("%s(%d): Invalid operator: %s for option %s\n", 
            file_name, file_line, toks[1], name);
        free(ssod);
        mSplitFree(&toks, num_toks);
    }

    ssod->size = strtoul(toks[2], &endp, 0);
    if ((endp == toks[2]) || (errno == ERANGE))
    {
        FatalError("%s(%d): Invalid size: %s for option %s\n", 
            file_name, file_line, toks[2], name);
        free(ssod);
        mSplitFree(&toks, num_toks);
    }

    *dataPtr = ssod;
    mSplitFree(&toks, num_toks);

    return 0;
}

INLINE int s5TcpStreamSizeCompare(u_int32_t size1, u_int32_t size2, char operator)
{
    int retval = 0;
    switch (operator)
    {
        case SSOD_EQUALS:
            if (size1 == size2)
                retval = 1;
            break;
        case SSOD_LESS_THAN:
            if (size1 < size2)
                retval = 1;
            break;
        case SSOD_GREATER_THAN:
            if (size1 > size2)
                retval = 1;
            break;
        case SSOD_NOT_EQUALS:
            if (size1 != size2)
                retval = 1;
            break;
        case SSOD_LESS_THAN_OR_EQUALS:
            if (size1 <= size2)
                retval = 1;
            break;
        case SSOD_GREATER_THAN_OR_EQUALS:
            if (size1 >= size2)
                retval = 1;
            break;
        default:
            break;
    }
    return retval;
}

int s5TcpStreamSizeEval(void *p, const u_int8_t **cursor, void *dataPtr)
{
    Packet *pkt = p;
    Stream5LWSession *lwssn = NULL; 
    TcpSession *tcpssn = NULL;
    StreamSizeOptionData *ssod = (StreamSizeOptionData *)dataPtr;
    u_int32_t client_size;
    u_int32_t server_size;

    if (!pkt || !pkt->ssnptr || !ssod || !pkt->tcph)
        return 0;

    lwssn = pkt->ssnptr;
    if (!lwssn->proto_specific_data)
        return 0;

    tcpssn = (TcpSession *)lwssn->proto_specific_data->data;

    if (tcpssn->client.l_nxt_seq > tcpssn->client.isn)
    {
        /* the normal case... */
        client_size = tcpssn->client.l_nxt_seq - tcpssn->client.isn;
    }
    else
    {
        /* the seq num wrapping case... */
        client_size = tcpssn->client.isn - tcpssn->client.l_nxt_seq;
    }
    if (tcpssn->server.l_nxt_seq > tcpssn->server.isn)
    {
        /* the normal case... */
        server_size = tcpssn->server.l_nxt_seq - tcpssn->server.isn;
    }
    else
    {
        /* the seq num wrapping case... */
        server_size = tcpssn->server.isn - tcpssn->server.l_nxt_seq;
    }

    switch (ssod->direction)
    {
        case SSN_DIR_CLIENT:
            if (s5TcpStreamSizeCompare(client_size, ssod->size, ssod->operator)
                == SSOD_MATCH)
                return 1;
            break;
        case SSN_DIR_SERVER:
            if (s5TcpStreamSizeCompare(server_size, ssod->size, ssod->operator)
                == SSOD_MATCH)
                return 1;
            break;
        case SSN_DIR_NONE: /* overloaded.  really, its an 'either' */
            if ((s5TcpStreamSizeCompare(client_size, ssod->size, ssod->operator)
                    == SSOD_MATCH) ||
                (s5TcpStreamSizeCompare(server_size, ssod->size, ssod->operator)
                    == SSOD_MATCH))
                return 1;
            break;
        case SSN_DIR_BOTH:
            if ((s5TcpStreamSizeCompare(client_size, ssod->size, ssod->operator)
                    == SSOD_MATCH) &&
                (s5TcpStreamSizeCompare(server_size, ssod->size, ssod->operator)
                    == SSOD_MATCH))
                return 1;
            break;
        default:
            break;
    }
    return 0;
}

void s5TcpStreamSizeCleanup(void *dataPtr)
{
    StreamSizeOptionData *ssod = dataPtr;
    if (ssod)
    {
        free(ssod);
    }
}
