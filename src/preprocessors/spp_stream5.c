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
 * @file    spp_stream5.c
 * @author  Martin Roesch <roesch@sourcefire.com>
 *         Steven Sturges <ssturges@sourcefire.com>
 * @date    19 Apr 2005
 *
 * @brief   You can never have too many stream reassemblers...
 */

/*
 * Copyright (C) 2004-2008 Sourcefire, Inc.
 */

/*  I N C L U D E S  ************************************************/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>

#ifndef WIN32
#include <sys/time.h>       /* struct timeval */
#endif
#include <sys/types.h>      /* u_int*_t */

#include "snort.h"
#include "bounds.h"
#include "util.h"
#include "debug.h"
#include "plugbase.h"
#include "spp_stream5.h"
#include "stream_api.h"
#include "stream5_common.h"
#include "snort_stream5_session.h"
#include "snort_stream5_tcp.h"
#include "snort_stream5_udp.h"
#include "snort_stream5_icmp.h"

#include "checksum.h"
#include "mstring.h"
#include "parser/IpAddrSet.h"
#include "decode.h"
#include "detect.h"
#include "generators.h"
#include "event_queue.h"
#include "stream_ignore.h"
#include "stream_api.h"
#include "perf.h"

#include "ipv6_port.h"

#ifdef TARGET_BASED
#include "sftarget_protocol_reference.h"
#include "sftarget_hostentry.h"
#endif

#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats s5PerfStats;
extern PreprocStats s5TcpPerfStats;
extern PreprocStats s5UdpPerfStats;
extern PreprocStats s5IcmpPerfStats;
#endif

extern OptTreeNode *otn_tmp;

/*  M A C R O S  **************************************************/

/* default limits */
#define S5_DEFAULT_PRUNE_QUANTA  30       /* seconds to timeout a session */
#define S5_DEFAULT_MEMCAP        8388608  /* 8MB */
#define S5_RIDICULOUS_HI_MEMCAP  1024*1024*1024 /* 1GB */
#define S5_RIDICULOUS_LOW_MEMCAP 32768    /* 32k*/
#define S5_DEFAULT_MIN_TTL       1        /* default for min TTL */
#define S5_DEFAULT_TTL_LIMIT     5        /* default for TTL Limit */
#define S5_RIDICULOUS_MAX_SESSIONS 1024*1028 /* 1 million sessions */
#define S5_DEFAULT_MAX_TCP_SESSIONS 262144 /* 256k TCP sessions by default */
#define S5_DEFAULT_MAX_UDP_SESSIONS 131072 /* 128k UDP sessions by default */
#define S5_DEFAULT_MAX_ICMP_SESSIONS 65536 /* 64k ICMP sessions by default */
/*  G L O B A L S  **************************************************/
Stream5GlobalConfig s5_global_config;
static char s5_global_config_complete = 0;
static char s5_process_registered = 0;
u_int32_t firstPacketTime = 0;
Stream5Stats s5stats;
MemPool s5FlowMempool;

/* Define this locally when Flow preprocessor has actually been removed */
#ifdef FLOWPP_IS_EIGHTYSIXED
unsigned int giFlowbitSize = 64;
#else
extern unsigned int giFlowbitSize;
//#include "flow.h"
#endif

/*  P R O T O T Y P E S  ********************************************/
static void Stream5GlobalInit(char *);
static void Stream5ParseGlobalArgs(char *);
static void Stream5PolicyInitTcp(char *);
static void Stream5PolicyInitUdp(char *);
static void Stream5PolicyInitIcmp(char *);
static void Stream5Restart(int, void *);
static void Stream5CleanExit(int, void *);
static void Stream5Reset(int, void *);
static void Stream5ResetStats(int, void *);
static void Stream5VerifyConfig(void);
static void Stream5PrintGlobalConfig();
static void Stream5PrintStats(int);
static void Stream5Process(Packet *p, void *context);
static INLINE int IsEligible(Packet *p);

/*  S T R E A M  A P I **********************************************/
static int Stream5MidStreamDropAlert() { return (s5_global_config.flags & STREAM5_CONFIG_MIDSTREAM_DROP_NOALERT) ? 0 : 1; }
static void Stream5UpdateDirection(
                    void * ssnptr,
                    char dir,
                    snort_ip_p ip,
                    u_int16_t port);
static u_int32_t Stream5GetPacketDirection(
                    Packet *p);
static void Stream5StopInspection(
                    void * ssnptr,
                    Packet *p,
                    char dir,
                    int32_t bytes,
                    int response);
static int Stream5IgnoreChannel(
                    snort_ip_p srcIP,
                    u_int16_t srcPort,
                    snort_ip_p dstIP,
                    u_int16_t dstPort,
                    char protocol,
                    char direction,
                    char flags);
static void Stream5ResumeInspection(
                    void *ssnptr,
                    char dir);
static void Stream5DropTraffic(
                    void *ssnptr,
                    char dir);
static void Stream5DropPacket(
                    Packet *p);
static void Stream5SetApplicationData(
                    void *ssnptr,
                    u_int32_t protocol,
                    void *data,
                    StreamAppDataFree free_func);
static void *Stream5GetApplicationData(
                    void *ssnptr,
                    u_int32_t protocol);
static u_int32_t Stream5SetSessionFlags(
                    void *ssnptr,
                    u_int32_t flags);
static u_int32_t Stream5GetSessionFlags(void *ssnptr);
static int Stream5AlertFlushStream(Packet *p);
static int Stream5ResponseFlushStream(Packet *p);
static int Stream5AddSessionAlert(void *ssnptr, 
                                  Packet *p,
                                  u_int32_t gid,
                                  u_int32_t sid);
static int Stream5CheckSessionAlert(void *ssnptr,
                                    Packet *p,
                                    u_int32_t gid,
                                    u_int32_t sid);
static char Stream5SetReassembly(void *ssnptr,
                                    u_int8_t flush_policy,
                                    char dir,
                                    char flags);
static char Stream5GetReassemblyDirection(void *ssnptr);
static char Stream5GetReassemblyFlushPolicy(void *ssnptr, char dir);
static char Stream5IsStreamSequenced(void *ssnptr, char dir);
static char Stream5MissingInReassembled(void *ssnptr, char dir);
static char Stream5PacketsMissing(void *ssnptr, char dir);

static int Stream5GetRebuiltPackets(
                            Packet *p,
                            PacketIterator callback,
                            void *userdata);
static StreamFlowData *Stream5GetFlowData(Packet *p);
#ifdef TARGET_BASED
static int16_t Stream5GetApplicationProtocolId(void *ssnptr);
static int16_t Stream5SetApplicationProtocolId(void *ssnptr, int16_t id);
#endif

StreamAPI s5api = {
    STREAM_API_VERSION5,
    Stream5MidStreamDropAlert,
    Stream5UpdateDirection,
    Stream5GetPacketDirection,
    Stream5StopInspection,
    Stream5IgnoreChannel,
    Stream5ResumeInspection,
    Stream5DropTraffic,
    Stream5DropPacket,
    Stream5SetApplicationData,
    Stream5GetApplicationData,
    Stream5SetSessionFlags,
    Stream5GetSessionFlags,
    Stream5AlertFlushStream,
    Stream5ResponseFlushStream,
    Stream5GetRebuiltPackets,
    Stream5AddSessionAlert,
    Stream5CheckSessionAlert,
    Stream5GetFlowData,
    Stream5SetReassembly,
    Stream5GetReassemblyDirection,
    Stream5GetReassemblyFlushPolicy,
    Stream5IsStreamSequenced,
    Stream5MissingInReassembled,
    Stream5PacketsMissing 
#ifdef TARGET_BASED
    ,
    Stream5GetApplicationProtocolId,
    Stream5SetApplicationProtocolId
#endif
            /* More to follow */
};

void SetupStream5()
{
    RegisterPreprocessor("stream5_global", Stream5GlobalInit);
    RegisterPreprocessor("stream5_tcp", Stream5PolicyInitTcp);
    RegisterPreprocessor("stream5_udp", Stream5PolicyInitUdp);
    RegisterPreprocessor("stream5_icmp", Stream5PolicyInitIcmp);
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "Preprocessor stream5 is setup\n"););
}

void Stream5GlobalInit(char *args)
{
    if (s5_global_config_complete)
    {
        FatalError("%s(%d) ==> Cannot duplicate Stream5 global "
                   "configuration\n", file_name, file_line);
    }

    if (stream_api == NULL)
        stream_api = &s5api;
    else
        FatalError("Cannot use both Stream4 & Stream5 simultaneously\n");

    s5_global_config.track_tcp_sessions = S5_TRACK_YES;
    s5_global_config.max_tcp_sessions = S5_DEFAULT_MAX_TCP_SESSIONS;
    s5_global_config.track_udp_sessions = S5_TRACK_YES;
    s5_global_config.max_udp_sessions = S5_DEFAULT_MAX_UDP_SESSIONS;
    s5_global_config.track_icmp_sessions = S5_TRACK_NO;
    s5_global_config.max_icmp_sessions = S5_DEFAULT_MAX_ICMP_SESSIONS;
    s5_global_config.memcap = S5_DEFAULT_MEMCAP;
    s5_global_config.mem_in_use = 0;

    Stream5ParseGlobalArgs(args);

#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("s5", &s5PerfStats, 0, &totalPerfStats);
    RegisterPreprocessorProfile("s5tcp", &s5TcpPerfStats, 1, &s5PerfStats);
    RegisterPreprocessorProfile("s5udp", &s5UdpPerfStats, 1, &s5PerfStats);
    RegisterPreprocessorProfile("s5icmp", &s5IcmpPerfStats, 1, &s5PerfStats);
#endif

    Stream5InitTcp();
    Stream5InitUdp();
    Stream5InitIcmp();

    snort_runtime.capabilities.stateful_inspection = 1;

    Stream5PrintGlobalConfig();

    AddFuncToPreprocCleanExitList(Stream5CleanExit, NULL, PRIORITY_FIRST, PP_STREAM5);
    AddFuncToPreprocRestartList(Stream5Restart, NULL, PRIORITY_FIRST, PP_STREAM5);
    AddFuncToPreprocResetList(Stream5Reset, NULL, PRIORITY_FIRST, PP_STREAM5);
    AddFuncToPreprocResetStatsList(Stream5ResetStats, NULL, PRIORITY_FIRST, PP_STREAM5);
    AddFuncToConfigCheckList(Stream5VerifyConfig);
    RegisterPreprocStats("stream5", Stream5PrintStats);

    s5_global_config_complete = 1;

    pv.stateful = 1;

    return;
}

static void Stream5ParseGlobalArgs(char *args)
{
    char **toks;
    int num_toks;
    int i;
    char *index;
    char **stoks;
    int s_toks;
    char *endPtr = NULL;
#define MAX_TCP 0x01
#define MAX_UDP 0x02
#define MAX_ICMP 0x04
    char max_set = 0;

    if(args != NULL && strlen(args) != 0)
    {
        toks = mSplit(args, ",", 12, &num_toks, 0);
        i = 0;

        while(i < num_toks)
        {
            index = toks[i];

            while(isspace((int)*index)) index++;

            stoks = mSplit(index, " ", 4, &s_toks, 0);

            if (s_toks == 0)
            {
                FatalError("%s(%d) => Missing parameter in Stream5 Global config.\n",
                    file_name, file_line);
            }

            if(!strcasecmp(stoks[0], "memcap"))
            {
                if (stoks[1])
                {
                    s5_global_config.memcap = strtoul(stoks[1], &endPtr, 10);
                }

                if (!stoks[1] || (endPtr == &stoks[1][0]))
                {
                    FatalError("%s(%d) => Invalid memcap in config file.  Requires integer parameter.\n",
                                file_name, file_line);
                }

                if ((s5_global_config.memcap > S5_RIDICULOUS_HI_MEMCAP) ||
                    (s5_global_config.memcap < S5_RIDICULOUS_LOW_MEMCAP))
                {
                    FatalError("%s(%d) => 'memcap %s' invalid: value must be "
                            "between %d and %d bytes\n",
                            file_name, file_line,
                            stoks[1], S5_RIDICULOUS_LOW_MEMCAP,
                            S5_RIDICULOUS_HI_MEMCAP);
                }
            }
            else if(!strcasecmp(stoks[0], "max_tcp"))
            {
                if (stoks[1])
                {
                    s5_global_config.max_tcp_sessions = strtoul(stoks[1], &endPtr, 10);
                    if (s5_global_config.track_tcp_sessions == S5_TRACK_NO)
                    {
                        if (s5_global_config.max_tcp_sessions != 0)
                        {
                            FatalError("%s(%d) => max_tcp conflict: not "
                                    "tracking TCP sessions\n",
                                    file_name, file_line);
                        }
                    }
                    else
                    {
                        if ((s5_global_config.max_tcp_sessions > S5_RIDICULOUS_MAX_SESSIONS) ||
                            (s5_global_config.max_tcp_sessions == 0))
                        {
                            FatalError("%s(%d) => 'max_tcp %d' invalid: value must be "
                                    "between 1 and %d sessions\n",
                                    file_name, file_line,
                                    s5_global_config.max_tcp_sessions,
                                    S5_RIDICULOUS_MAX_SESSIONS);

                        }
                    }
                }

                if (!stoks[1] || (endPtr == &stoks[1][0]))
                {
                    FatalError("%s(%d) => Invalid max_tcp in config file.  Requires integer parameter.\n",
                                file_name, file_line);
                }

                max_set |= MAX_TCP;
            }
            else if(!strcasecmp(stoks[0], "track_tcp"))
            {
                if (stoks[1])
                {
                    if(!strcasecmp(stoks[1], "no"))
                        s5_global_config.track_tcp_sessions = S5_TRACK_NO;
                    else
                        s5_global_config.track_tcp_sessions = S5_TRACK_YES;
                }
                else
                {
                    FatalError("%s(%d) => 'track_udp' missing option\n",
                        file_name, file_line);
                }

                if ((max_set & MAX_TCP) && 
                    (s5_global_config.track_tcp_sessions == S5_TRACK_NO))
                {
                    FatalError("%s(%d) => max_tcp/track_tcp conflict: not "
                                    "tracking TCP sessions\n",
                                    file_name, file_line);
                }
            }
            else if(!strcasecmp(stoks[0], "max_udp"))
            {
                if (stoks[1])
                {
                    s5_global_config.max_udp_sessions = strtoul(stoks[1], &endPtr, 10);
                    if (s5_global_config.track_udp_sessions == S5_TRACK_NO)
                    {
                        if (s5_global_config.max_udp_sessions != 0)
                        {
                            FatalError("%s(%d) => max_udp conflict: not "
                                    "tracking UDP sessions\n",
                                    file_name, file_line);
                        }
                    }
                    else
                    {
                        if ((s5_global_config.max_udp_sessions > S5_RIDICULOUS_MAX_SESSIONS) ||
                            (s5_global_config.max_udp_sessions == 0))
                        {
                            FatalError("%s(%d) => 'max_udp %d' invalid: value must be "
                                    "between 1 and %d sessions\n",
                                    file_name, file_line,
                                    s5_global_config.max_udp_sessions,
                                    S5_RIDICULOUS_MAX_SESSIONS);
                        }
                    }
                }

                if (!stoks[1] || (endPtr == &stoks[1][0]))
                {
                    FatalError("%s(%d) => Invalid max_udp in config file.  Requires integer parameter.\n",
                                file_name, file_line);
                }
                max_set |= MAX_UDP;
            }
            else if(!strcasecmp(stoks[0], "track_udp"))
            {
                if (stoks[1])
                {
                    if(!strcasecmp(stoks[1], "no"))
                        s5_global_config.track_udp_sessions = S5_TRACK_NO;
                    else
                        s5_global_config.track_udp_sessions = S5_TRACK_YES;
                }
                else
                {
                    FatalError("%s(%d) => 'track_udp' missing option\n",
                        file_name, file_line);
                }

                if ((max_set & MAX_UDP) && 
                    (s5_global_config.track_udp_sessions == S5_TRACK_NO))
                {
                    FatalError("%s(%d) => max_udp/track_udp conflict: not "
                                    "tracking UDP sessions\n",
                                    file_name, file_line);
                }
            }
            else if(!strcasecmp(stoks[0], "max_icmp"))
            {
                if (stoks[1])
                {
                    s5_global_config.max_icmp_sessions = strtoul(stoks[1], &endPtr, 10);

                    if (s5_global_config.track_icmp_sessions == S5_TRACK_NO)
                    {
                        if (s5_global_config.max_icmp_sessions != 0)
                        {
                            FatalError("%s(%d) => max_icmp conflict: not "
                                    "tracking ICMP sessions\n",
                                    file_name, file_line);
                        }
                    }
                    else
                    {
                        if ((s5_global_config.max_icmp_sessions > S5_RIDICULOUS_MAX_SESSIONS) ||
                            (s5_global_config.max_icmp_sessions == 0))
                        {
                            FatalError("%s(%d) => 'max_icmp %d' invalid: value must be "
                                    "between 1 and %d sessions\n",
                                    file_name, file_line,
                                    s5_global_config.max_icmp_sessions,
                                    S5_RIDICULOUS_MAX_SESSIONS);
                        }
                    }
                }

                if (!stoks[1] || (endPtr == &stoks[1][0]))
                {
                    FatalError("%s(%d) => Invalid max_icmp in config file.  Requires integer parameter.\n",
                                file_name, file_line);
                }
                max_set |= MAX_ICMP;
            }
            else if(!strcasecmp(stoks[0], "track_icmp"))
            {
                if (stoks[1])
                {
                    if(!strcasecmp(stoks[1], "no"))
                        s5_global_config.track_icmp_sessions = S5_TRACK_NO;
                    else
                        s5_global_config.track_icmp_sessions = S5_TRACK_YES;
                }
                else
                {
                    FatalError("%s(%d) => 'track_icmp' missing option\n",
                        file_name, file_line);
                }

                if ((max_set & MAX_ICMP) && 
                    (s5_global_config.track_icmp_sessions == S5_TRACK_NO))
                {
                    FatalError("%s(%d) => max_icmp/track_icmp conflict: not "
                                    "tracking ICMP sessions\n",
                                    file_name, file_line);
                }
            }
            else if(!strcasecmp(stoks[0], "flush_on_alert"))
            {
                s5_global_config.flags |= STREAM5_CONFIG_FLUSH_ON_ALERT;
            }
            else if(!strcasecmp(stoks[0], "show_rebuilt_packets"))
            {
                s5_global_config.flags |= STREAM5_CONFIG_SHOW_PACKETS;
            }
#ifdef TBD
            else if(!strcasecmp(stoks[0], "no_midstream_drop_alerts"))
            {
                /*
                 * XXX: Do we want to not alert on drops for sessions picked
                 * up midstream ?  If we're inline, and get a session midstream,
                 * its because it was picked up during startup.  In inline
                 * mode, we should ALWAYS be requiring TCP 3WHS.
                 */
                s5_global_config.flags |= STREAM5_CONFIG_MIDSTREAM_DROP_NOALERT;
            }
#endif
            else
            {
                FatalError("%s(%d) => Unknown Stream5 global option (%s)\n",
                                file_name, file_line, index);
            }

            mSplitFree(&stoks, s_toks);
            i++;
        }

        mSplitFree(&toks, num_toks);

    }

    return;
}

static void Stream5PrintGlobalConfig()
{
    LogMessage("Stream5 global config:\n");
    LogMessage("    Track TCP sessions: %s\n",
        s5_global_config.track_tcp_sessions == S5_TRACK_YES ?
        "ACTIVE" : "INACTIVE");
    if (s5_global_config.track_tcp_sessions == S5_TRACK_YES)
        LogMessage("    Max TCP sessions: %lu\n",
            s5_global_config.max_tcp_sessions);
    LogMessage("    Memcap (for reassembly packet storage): %d\n",
        s5_global_config.memcap);
    LogMessage("    Track UDP sessions: %s\n",
        s5_global_config.track_udp_sessions == S5_TRACK_YES ?
        "ACTIVE" : "INACTIVE");
    if (s5_global_config.track_udp_sessions == S5_TRACK_YES)
        LogMessage("    Max UDP sessions: %lu\n",
            s5_global_config.max_udp_sessions);
    LogMessage("    Track ICMP sessions: %s\n",
        s5_global_config.track_icmp_sessions == S5_TRACK_YES ?
        "ACTIVE" : "INACTIVE");
    if (s5_global_config.track_icmp_sessions == S5_TRACK_YES)
        LogMessage("    Max ICMP sessions: %lu\n",
            s5_global_config.max_icmp_sessions);
}

void Stream5PolicyInitTcp(char *args)
{
    PreprocessFuncNode *pfn;

    if(!s5_global_config_complete)
    {
        LogMessage("Tried to config stream5 TCP policy without global config!\n");
        return;
    }

    if (!s5_process_registered)
    {
        pfn = AddFuncToPreprocList(Stream5Process, PRIORITY_TRANSPORT, PP_STREAM5);
        s5_process_registered = 1;
    }

    if (!s5_global_config.track_tcp_sessions)
    {
        FatalError("Stream5 TCP Configuration specified, but TCP tracking is turned off\n");
    }

    /* Call the protocol specific initializer */
    Stream5TcpPolicyInit(args);

    return;
}

void Stream5PolicyInitUdp(char *args)
{
    PreprocessFuncNode *pfn;

    if(!s5_global_config_complete)
    {
        LogMessage("Tried to config stream5 UDP policy without global config!\n");
        return;
    }

    if (!s5_process_registered)
    {
        pfn = AddFuncToPreprocList(Stream5Process, PRIORITY_TRANSPORT, PP_STREAM5);
        s5_process_registered = 1;
    }

    if (!s5_global_config.track_udp_sessions)
    {
        FatalError("Stream5 UDP Configuration specified, but UDP tracking is turned off\n");
    }

    /* Call the protocol specific initializer */
    Stream5UdpPolicyInit(args);

    return;
}

void Stream5PolicyInitIcmp(char *args)
{
    PreprocessFuncNode *pfn;

    if(!s5_global_config_complete)
    {
        LogMessage("Tried to config stream5 ICMP policy without global config!\n");
        return;
    }

    if (!s5_process_registered)
    {
        pfn = AddFuncToPreprocList(Stream5Process, PRIORITY_TRANSPORT, PP_STREAM5);
        s5_process_registered = 1;
    }

    if (!s5_global_config.track_icmp_sessions)
    {
        FatalError("Stream5 ICMP Configuration specified, but ICMP tracking is turned off\n");
    }

    /* Call the protocol specific initializer */
    Stream5IcmpPolicyInit(args);

    return;
}

static void Stream5Restart(int signal, void *foo)
{
    return;
}

static void Stream5Reset(int signal, void *foo)
{
    Stream5ResetTcp();
    Stream5ResetUdp();
    Stream5ResetIcmp();

    mempool_clean(&s5FlowMempool);
}

static void Stream5ResetStats(int signal, void *foo)
{
    memset(&s5stats, 0, sizeof(s5stats));
}

static void Stream5CleanExit(int signal, void *foo)
{
    /* Clean up the hash tables for these */
    Stream5CleanTcp();
    Stream5CleanUdp();
    Stream5CleanIcmp();

    mempool_destroy(&s5FlowMempool);

    /* Free up the ignore data that was queued */
    CleanupIgnore();

    return;
}

static void Stream5VerifyConfig()
{
    int tcpNotConfigured = 0;
    int udpNotConfigured = 0;
    int icmpNotConfigured = 0;
    PoolCount total_sessions = 0;
    int obj_size = 0;

    if (s5_global_config_complete)
    {
        if (s5_global_config.track_tcp_sessions)
        {
            tcpNotConfigured = Stream5VerifyTcpConfig();
            if (tcpNotConfigured)
            {
                LogMessage("WARNING: Stream5 TCP misconfigured\n");
            }
            else
            {
                total_sessions += s5_global_config.max_tcp_sessions;
            }
        }

        if (s5_global_config.track_udp_sessions)
        {
            udpNotConfigured = Stream5VerifyUdpConfig();
            if (udpNotConfigured)
            {
                LogMessage("WARNING: Stream5 UDP misconfigured\n");
            }
            else
            {
                total_sessions += s5_global_config.max_udp_sessions;
            }
        }

        if (s5_global_config.track_icmp_sessions)
        {
            icmpNotConfigured = Stream5VerifyIcmpConfig();
            if (icmpNotConfigured)
            {
                LogMessage("WARNING: Stream5 ICMP misconfigured\n");
            }
            else
            {
                total_sessions += s5_global_config.max_icmp_sessions;
            }
        }

        if (tcpNotConfigured || udpNotConfigured || icmpNotConfigured)
        {
            FatalError("Stream5 not properly configured... exiting\n");
        }

        /* Initialize the memory pool for Flowbits Data */
        /* use giFlowbitSize - 1, since there is already 1 byte in the
         * StreamFlowData structure */
        obj_size = sizeof(StreamFlowData) + giFlowbitSize - 1;

        if (obj_size % sizeof(long) != 0)
        {
            /* Increase obj_size by sizeof(long) to force sizeof(long) byte
             * alignment for each object in the mempool.  Without this,
             * the mempool data buffer was not aligned. Overlaying the
             * StreamFlowData structure caused problems on some Solaris
             * platforms. */
            obj_size += ( sizeof(long) - (obj_size % sizeof(long)));
        }
        mempool_init(&s5FlowMempool, total_sessions, obj_size);
    }
}

static void Stream5PrintStats(int exiting)
{
    LogMessage("Stream5 statistics:\n");
    LogMessage("            Total sessions: %lu\n",
            s5stats.total_tcp_sessions +
            s5stats.total_udp_sessions +
            s5stats.total_icmp_sessions);
    LogMessage("              TCP sessions: %lu\n", s5stats.total_tcp_sessions);
    LogMessage("              UDP sessions: %lu\n", s5stats.total_udp_sessions);
    LogMessage("             ICMP sessions: %lu\n", s5stats.total_icmp_sessions);

    LogMessage("                TCP Prunes: %lu\n", s5stats.tcp_prunes);
    LogMessage("                UDP Prunes: %lu\n", s5stats.udp_prunes);
    LogMessage("               ICMP Prunes: %lu\n", s5stats.icmp_prunes);
    LogMessage("TCP StreamTrackers Created: %lu\n",
            s5stats.tcp_streamtrackers_created);
    LogMessage("TCP StreamTrackers Deleted: %lu\n",
            s5stats.tcp_streamtrackers_released);
    LogMessage("              TCP Timeouts: %lu\n", s5stats.tcp_timeouts);
    LogMessage("              TCP Overlaps: %lu\n", s5stats.tcp_overlaps);
    LogMessage("       TCP Segments Queued: %lu\n", s5stats.tcp_streamsegs_created);
    LogMessage("     TCP Segments Released: %lu\n", s5stats.tcp_streamsegs_released);
    LogMessage("       TCP Rebuilt Packets: %lu\n", s5stats.tcp_rebuilt_packets);
    LogMessage("         TCP Segments Used: %lu\n", s5stats.tcp_rebuilt_seqs_used);
    LogMessage("              TCP Discards: %lu\n", s5stats.tcp_discards);
    LogMessage("      UDP Sessions Created: %lu\n",
            s5stats.udp_sessions_created);
    LogMessage("      UDP Sessions Deleted: %lu\n",
            s5stats.udp_sessions_released);
    LogMessage("              UDP Timeouts: %lu\n", s5stats.udp_timeouts);
    LogMessage("              UDP Discards: %lu\n", s5stats.udp_discards);
    LogMessage("                    Events: %lu\n", s5stats.events);
}

/*
 * MAIN ENTRY POINT
 */
void Stream5Process(Packet *p, void *context)
{
    PROFILE_VARS;

    if (!firstPacketTime)
        firstPacketTime = p->pkth->ts.tv_sec;

    if(!IsEligible(p))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, "Is not eligible!\n"););
        return;
    }

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                "++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"););
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE, "In Stream5!\n"););

    PREPROC_PROFILE_START(s5PerfStats);

    /* Call individual TCP/UDP/ICMP processing, per GET_IPH_PROTO(p) */
    switch(GET_IPH_PROTO(p))
    {
        case IPPROTO_TCP:
            if (s5_global_config.track_tcp_sessions)
                Stream5ProcessTcp(p);
            break;
        case IPPROTO_UDP:
            if (s5_global_config.track_udp_sessions)
                Stream5ProcessUdp(p);
            break;
        case IPPROTO_ICMP:
            if (s5_global_config.track_icmp_sessions)
                Stream5ProcessIcmp(p);
            break;
    }

    PREPROC_PROFILE_END(s5PerfStats);
    return;
}

static INLINE int IsEligible(Packet *p)
{
    if ((p->frag_flag) || (p->csum_flags & CSE_IP))
        return 0;

    if (p->packet_flags & PKT_REBUILT_STREAM)
        return 0;

    if (!IPH_IS_VALID(p))
        return 0;

    switch(GET_IPH_PROTO(p))
    {
        case IPPROTO_TCP:
        {
             if(p->tcph == NULL)
                 return 0;

             if (p->csum_flags & CSE_TCP)
                 return 0;
        }
        break;
        case IPPROTO_UDP:
        {
             if(p->udph == NULL)
                 return 0;

             if (p->csum_flags & CSE_UDP)
                 return 0;
        }
        break;
        case IPPROTO_ICMP:
        {
             if(p->icmph == NULL)
                 return 0;

             if (p->csum_flags & CSE_ICMP)
                 return 0;
        }
        break;
        default:
            return 0;
    }

    return 1;
}

/*************************** API Implementations *******************/
static void Stream5SetApplicationData(
                    void *ssnptr,
                    u_int32_t protocol,
                    void *data,
                    StreamAppDataFree free_func)
{
    Stream5LWSession *ssn;
    Stream5AppData *appData = NULL;
    if (ssnptr)
    {
        ssn = (Stream5LWSession*)ssnptr;
        appData = ssn->appDataList;
        while (appData)
        {
            if (appData->protocol == protocol)
            {
                /* If changing the pointer to the data, free old one */
                if ((appData->freeFunc) && (appData->dataPointer != data))
                {
                    appData->freeFunc(appData->dataPointer);
                }
                else
                {
                    /* Same pointer, same protocol.  Go away */
                    break;
                }

                appData->dataPointer = NULL;
                break;
            }

            appData = appData->next;
        }

        /* If there isn't one for this protocol, allocate */
        if (!appData)
        {
            appData = SnortAlloc(sizeof(Stream5AppData));

            /* And add it to the list */
            if (ssn->appDataList)
            {
                ssn->appDataList->prev = appData;
            }
            appData->next = ssn->appDataList;
            ssn->appDataList = appData;
        }

        /* This will reset free_func if it already exists */
        appData->protocol = protocol;
        appData->freeFunc = free_func;
        appData->dataPointer = data;
    }
}

static void *Stream5GetApplicationData(
                    void *ssnptr,
                    u_int32_t protocol)
{
    Stream5LWSession *ssn;
    Stream5AppData *appData = NULL;
    void *data = NULL;
    if (ssnptr)
    {
        ssn = (Stream5LWSession*)ssnptr;
        appData = ssn->appDataList;
        while (appData)
        {
            if (appData->protocol == protocol)
            {
                data = appData->dataPointer;
                break;
            }
            appData = appData->next;
        }
    }
    return data;
}

static int Stream5AlertFlushStream(Packet *p)
{
    Stream5LWSession *ssn;

    if (!(s5_global_config.flags & STREAM5_CONFIG_FLUSH_ON_ALERT))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Don't flush on alert from individual packet\n"););
        return 0;
    }

    if (!p || !p->ssnptr)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Don't flush NULL packet or session\n"););
        return 0;
    }

    ssn = p->ssnptr;

    if ((ssn->protocol != IPPROTO_TCP) ||
        (p->packet_flags & PKT_REBUILT_STREAM))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Don't flush on rebuilt packets\n"););
        return 0;
    }

    /* Flush the listener queue -- this is the same side that
     * the packet gets inserted into */
    Stream5FlushListener(p, ssn);

    return 0;
}

static int Stream5ResponseFlushStream(Packet *p)
{
    Stream5LWSession *ssn;

    if ((p == NULL) || (p->ssnptr == NULL))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Don't flush NULL packet or session\n"););
        return 0;
    }

    ssn = p->ssnptr;

    if ((ssn->protocol != IPPROTO_TCP) ||
        (p->packet_flags & PKT_REBUILT_STREAM))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_STATE,
                    "Don't flush on rebuilt packets\n"););
        return 0;
    }

    /* Flush the talker queue -- this is the opposite side that
     * the packet gets inserted into */
    Stream5FlushTalker(p, ssn);

    return 0;
}

static u_int32_t Stream5SetSessionFlags(
                    void *ssnptr,
                    u_int32_t flags)
{
    Stream5LWSession *ssn;
    if (ssnptr)
    {
        ssn = (Stream5LWSession *)ssnptr;
        ssn->session_flags |= flags;
        return ssn->session_flags;
    }

    return 0;
}

static u_int32_t Stream5GetSessionFlags(void *ssnptr)
{
    Stream5LWSession *ssn;
    if (ssnptr)
    {
        ssn = (Stream5LWSession *)ssnptr; 
        return ssn->session_flags;
    }

    return 0;
}

static int Stream5AddSessionAlert(void *ssnptr,
                                  Packet *p,
                                  u_int32_t gid,
                                  u_int32_t sid)
{
    Stream5LWSession *ssn;
    if (ssnptr)
    {
        ssn = (Stream5LWSession *)ssnptr;
        switch (GET_IPH_PROTO(p))
        {
            case IPPROTO_TCP:
                return Stream5AddSessionAlertTcp(ssn, p, gid, sid);
                break;
#if 0 /* Don't need to do this for UDP/ICMP because they don't
         do any reassembly. */
            case IPPROTO_UDP:
                return Stream5AddSessionAlertUdp(ssn, p, gid, sid);
                break;
            case IPPROTO_ICMP:
                return Stream5AddSessionAlertIcmp(ssn, p, gid, sid);
                break;
#endif
        }
    }

    return 0;
}

/* return non-zero if gid/sid have already been seen */
static int Stream5CheckSessionAlert(void *ssnptr,
                                    Packet *p,
                                    u_int32_t gid,
                                    u_int32_t sid)
{
    Stream5LWSession *ssn;

    if (ssnptr)
    {
        ssn = (Stream5LWSession *)ssnptr;
        switch (GET_IPH_PROTO(p))
        {
            case IPPROTO_TCP:
                return Stream5CheckSessionAlertTcp(ssn, p, gid, sid);
                break;
#if 0 /* Don't need to do this for UDP/ICMP because they don't
         do any reassembly. */
            case IPPROTO_UDP:
                return Stream5CheckSessionAlertUdp(ssn, p, gid, sid);
                break;
            case IPPROTO_ICMP:
                return Stream5CheckSessionAlertIcmp(ssn, p, gid, sid);
                break;
#endif
        }
    }
    return 0;
}

static int Stream5IgnoreChannel(
                    snort_ip_p      srcIP,
                    u_int16_t srcPort,
                    snort_ip_p      dstIP,
                    u_int16_t dstPort,
                    char protocol,
                    char direction,
                    char flags)
{
    return IgnoreChannel(srcIP, srcPort, dstIP, dstPort,
                         protocol, direction, flags, 300);
}

void Stream5DisableInspection(Stream5LWSession *lwssn, Packet *p)
{
    /*
     * Don't want to mess up PortScan by "dropping"
     * this packet.
     *
     * Also still want the perfmon to collect the stats.
     *
     * And don't want to do any detection with rules
     */
    DisableDetect(p);
    SetPreprocBit(p, PP_SFPORTSCAN);
    SetPreprocBit(p, PP_PERFMONITOR);
    otn_tmp = NULL;
}

static void Stream5StopInspection(
                    void * ssnptr,
                    Packet *p,
                    char dir,
                    int32_t bytes,
                    int response)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if (!ssn)
        return;

    switch (dir)
    {
        case SSN_DIR_BOTH:
            ssn->ignore_direction = dir;
            break;
        case SSN_DIR_CLIENT:
            ssn->ignore_direction = dir;
            break;
        case SSN_DIR_SERVER:
            ssn->ignore_direction = dir;
            break;
    }

    /* Flush any queued data on the client and/or server */
    if (ssn->protocol == IPPROTO_TCP)
    {
        if (ssn->ignore_direction & SSN_DIR_CLIENT)
        {
            Stream5FlushClient(p, ssn);
        }

        if (ssn->ignore_direction & SSN_DIR_SERVER)
        {
            Stream5FlushServer(p, ssn);
        }
    }

    /* TODO: Handle bytes/response parameters */

    Stream5DisableInspection(ssn, p);
}

static void Stream5ResumeInspection(
                    void *ssnptr,
                    char dir)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if (!ssn)
        return;

    switch (dir)
    {
        case SSN_DIR_BOTH:
            ssn->ignore_direction &= ~dir;
            break;
        case SSN_DIR_CLIENT:
            ssn->ignore_direction &= ~dir;
            break;
        case SSN_DIR_SERVER:
            ssn->ignore_direction &= ~dir;
            break;
    }

}

static void Stream5UpdateDirection(
                    void * ssnptr,
                    char dir,
                    snort_ip_p ip,
                    u_int16_t port)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if (!ssn)
        return;

    switch (ssn->protocol)
    {
        case IPPROTO_TCP:
            TcpUpdateDirection(ssn, dir, ip, port);
            break;
        case IPPROTO_UDP:
            UdpUpdateDirection(ssn, dir, ip, port);
            break;
        case IPPROTO_ICMP:
            //IcmUpdateDirection(ssn, dir, ip, port);
            break;
    }
}

static u_int32_t Stream5GetPacketDirection(Packet *p)
{
    Stream5LWSession *lwssn;
    
    if (!p || !(p->ssnptr))
        return 0;
    
    lwssn = (Stream5LWSession *)p->ssnptr;

    GetLWPacketDirection(p, lwssn);

    return (p->packet_flags & (PKT_FROM_SERVER|PKT_FROM_CLIENT));
}

static void Stream5DropTraffic(
                    void *ssnptr,
                    char dir)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if (!ssn)
        return;

    if (dir & SSN_DIR_CLIENT)
    {
        ssn->session_flags |= STREAM5_STATE_DROP_CLIENT;
        ssn->session_flags |= SSNFLAG_DROP_CLIENT;
    }

    if (dir & SSN_DIR_SERVER)
    {
        ssn->session_flags |= STREAM5_STATE_DROP_SERVER;
        ssn->session_flags |= SSNFLAG_DROP_SERVER;
    }

    /* XXX: Issue resets if TCP or ICMP Unreach if UDP? */
}

static void Stream5DropPacket(
                            Packet *p)
{
    Stream5TcpBlockPacket(p);
    Stream5DropTraffic(p->ssnptr, SSN_DIR_BOTH);
}

static int Stream5GetRebuiltPackets(
                            Packet *p,
                            PacketIterator callback,
                            void *userdata)
{
    Stream5LWSession *ssn = (Stream5LWSession*)p->ssnptr;

    if (!ssn || ssn->protocol != IPPROTO_TCP)
        return 0;

    /* Only if this is a rebuilt packet */
    if (!(p->packet_flags & PKT_REBUILT_STREAM))
        return 0;

    return GetTcpRebuiltPackets(p, ssn, callback, userdata);
}

static StreamFlowData *Stream5GetFlowData(Packet *p)
{
#if 0
    FLOW *fp;
    FLOWDATA *flowdata;
    if (!p->flow)
        return NULL;

    fp = (FLOW *)p->flow;
    flowdata = &fp->data;

    return (StreamFlowData *)flowdata;
#endif
    Stream5LWSession *ssn = (Stream5LWSession*)p->ssnptr;

    if (!ssn)
        return NULL;

    return (StreamFlowData *)ssn->flowdata->data;
}

static char Stream5GetReassemblyDirection(void *ssnptr)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if (!ssn || ssn->protocol != IPPROTO_TCP)
        return SSN_DIR_NONE;

    return Stream5GetReassemblyDirectionTcp(ssn);
}

static char Stream5SetReassembly(void *ssnptr,
                                   u_int8_t flush_policy,
                                   char dir,
                                   char flags)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if (!ssn || ssn->protocol != IPPROTO_TCP)
        return 0;

    return Stream5SetReassemblyTcp(ssn, flush_policy, dir, flags);
}

static char Stream5GetReassemblyFlushPolicy(void *ssnptr, char dir)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if (!ssn || ssn->protocol != IPPROTO_TCP)
        return STREAM_FLPOLICY_NONE;

    return Stream5GetReassemblyFlushPolicyTcp(ssn, dir);
}

static char Stream5IsStreamSequenced(void *ssnptr, char dir)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if (!ssn || ssn->protocol != IPPROTO_TCP)
        return 1;

    return Stream5IsStreamSequencedTcp(ssn, dir);
}

static char Stream5MissingInReassembled(void *ssnptr, char dir)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if (!ssn || ssn->protocol != IPPROTO_TCP)
        return 1;

    return Stream5MissingInReassembledTcp(ssn, dir);
}

static char Stream5PacketsMissing(void *ssnptr, char dir)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;

    if (!ssn || ssn->protocol != IPPROTO_TCP)
        return 1;

    return Stream5PacketsMissingTcp(ssn, dir);
}

#ifdef TARGET_BASED
void Stream5SetIPProtocol(Stream5LWSession *lwssn)
{
    switch (lwssn->protocol)
    {
    case IPPROTO_TCP:
        lwssn->ipprotocol = FindProtocolReference("tcp");
        break;
    case IPPROTO_UDP:
        lwssn->ipprotocol = FindProtocolReference("udp");
        break;
    case IPPROTO_ICMP:
        lwssn->ipprotocol = FindProtocolReference("icmp");
        break;
    }
}

void Stream5SetApplicationProtocolIdFromHostEntry(Stream5LWSession *lwssn,
                                           HostAttributeEntry *host_entry,
                                           int direction)
{
    if (!lwssn || !host_entry)
        return;

    /* Cool, its already set! */
    if (lwssn->application_protocol != 0)
        return;

    if (lwssn->ipprotocol == 0)
    {
        Stream5SetIPProtocol(lwssn);
    }

    if (direction == SSN_DIR_SERVER)
    {
        lwssn->application_protocol = getApplicationProtocolId(host_entry,
                                        lwssn->ipprotocol,
                                        ntohs(lwssn->server_port),
                                        SFAT_SERVICE);
    }
    else
    {
        lwssn->application_protocol = getApplicationProtocolId(host_entry,
                                        lwssn->ipprotocol,
                                        ntohs(lwssn->client_port),
                                        SFAT_SERVICE);
    }
}

static int16_t Stream5GetApplicationProtocolId(void *ssnptr)
{
    Stream5LWSession *lwssn = (Stream5LWSession *)ssnptr;
    /* Not caching the source and dest host_entry in the session so we can
     * swap the table out after processing this packet if we need
     * to.  */
#ifndef SUP_IP6
    HostAttributeEntry *host_entry = NULL;
#endif
    int16_t protocol = 0;

    if (!lwssn)
        return protocol;

    if (lwssn->application_protocol != 0)
        return lwssn->application_protocol;

    if (lwssn->ipprotocol == 0)
    {
        Stream5SetIPProtocol(lwssn);
    }

#ifndef SUP_IP6
    host_entry = SFAT_LookupHostEntryByIp4Addr(ntohl(lwssn->server_ip));
    if (host_entry)
    {
        Stream5SetApplicationProtocolIdFromHostEntry(lwssn,
                                           host_entry, SSN_DIR_SERVER);

        if (lwssn->application_protocol != 0)
        {
            return lwssn->application_protocol;
        }
    }

    host_entry = SFAT_LookupHostEntryByIp4Addr(ntohl(lwssn->client_ip));
    if (host_entry)
    {
        Stream5SetApplicationProtocolIdFromHostEntry(lwssn,
                                           host_entry, SSN_DIR_CLIENT);
        if (lwssn->application_protocol != 0)
        {
            return lwssn->application_protocol;
        }
    }
#endif

    return lwssn->application_protocol;
}

static int16_t Stream5SetApplicationProtocolId(void *ssnptr, int16_t id)
{
    Stream5LWSession *ssn = (Stream5LWSession *)ssnptr;
    if (!ssn)
        return 0;

    ssn->application_protocol = id;

    return id;
}
#endif

