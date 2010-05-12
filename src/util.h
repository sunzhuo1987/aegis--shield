/* $Id$ */
/*
** Copyright (C) 2002-2008 Sourcefire, Inc.
** Copyright (C) 2002 Martin Roesch <roesch@sourcefire.com>
**
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


#ifndef __UTIL_H__
#define __UTIL_H__

#define TIMEBUF_SIZE 26

#ifndef WIN32
#include <sys/time.h>
#include <sys/types.h>
#endif /* !WIN32 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sf_types.h"
#include "sflsq.h"

/* specifies that a function does not return 
 * used for quieting Visual Studio warnings
 */
#ifdef _MSC_VER
#if _MSC_VER >= 1400
#define NORETURN __declspec(noreturn)
#else
#define NORETURN
#endif
#else
#define NORETURN
#endif

#define SNORT_SNPRINTF_SUCCESS 0
#define SNORT_SNPRINTF_TRUNCATION 1
#define SNORT_SNPRINTF_ERROR -1

#define SNORT_STRNCPY_SUCCESS 0
#define SNORT_STRNCPY_TRUNCATION 1
#define SNORT_STRNCPY_ERROR -1

#define SNORT_STRNLEN_ERROR -1

#define SECONDS_PER_DAY  86400  /* number of seconds in a day  */
#define SECONDS_PER_HOUR  3600  /* number of seconds in a hour */
#define SECONDS_PER_MIN     60     /* number of seconds in a minute */

extern u_long netmasks[33];

/* Self preservation memory control struct */
typedef struct _SPMemControl
{
    unsigned long memcap;
    unsigned long mem_usage;
    void *control;
    int (*sp_func)(struct _SPMemControl *);

    unsigned long fault_count;

} SPMemControl;

typedef struct _PcapPktStats
{
    UINT64 recv;
    UINT64 drop;
    u_int32_t wrap_recv;
    u_int32_t wrap_drop;

} PcapPktStats;


typedef struct _IntervalStats
{
    UINT64 recv, recv_total;
    UINT64 drop, drop_total;
    UINT64 processed, processed_total;
    UINT64 tcp, tcp_total;
    UINT64 udp, udp_total;
    UINT64 icmp, icmp_total;
    UINT64 arp, arp_total;
    UINT64 ipx, ipx_total;
    UINT64 eapol, eapol_total;
    UINT64 ipv6, ipv6_total;
    UINT64 ethloopback, ethloopback_total;
    UINT64 other, other_total;
    UINT64 frags, frags_total;
    UINT64 discards, discards_total;
    UINT64 frag_trackers, frag_trackers_total;
    UINT64 frag_rebuilt, frag_rebuilt_total;
    UINT64 frag_element, frag_element_total;
    UINT64 frag_incomp, frag_incomp_total;
    UINT64 frag_timeout, frag_timeout_total;
    UINT64 frag_mem_faults, frag_mem_faults_total;
    UINT64 tcp_str_packets, tcp_str_packets_total;
    UINT64 tcp_str_trackers, tcp_str_trackers_total;
    UINT64 tcp_str_flushes, tcp_str_flushes_total;
    UINT64 tcp_str_segs_used, tcp_str_segs_used_total;
    UINT64 tcp_str_segs_queued, tcp_str_segs_queued_total;
    UINT64 tcp_str_mem_faults, tcp_str_mem_faults_total;

#ifdef GRE
    UINT64 ip4ip4, ip4ip4_total;
    UINT64 ip4ip6, ip4ip6_total;
    UINT64 ip6ip4, ip6ip4_total;
    UINT64 ip6ip6, ip6ip6_total;

    UINT64 gre, gre_total;
    UINT64 gre_ip, gre_ip_total;
    UINT64 gre_eth, gre_eth_total;
    UINT64 gre_arp, gre_arp_total;
    UINT64 gre_ipv6, gre_ipv6_total;
    UINT64 gre_ipx, gre_ipx_total;
    UINT64 gre_loopback, gre_loopback_total;
    UINT64 gre_vlan, gre_vlan_total;
    UINT64 gre_ppp, gre_ppp_total;
#endif

#ifdef DLT_IEEE802_11
    UINT64 wifi_mgmt, wifi_mgmt_total;
    UINT64 wifi_control, wifi_control_total;
    UINT64 wifi_data, wifi_data_total;
#endif

} IntervalStats;



int DisplayBanner();
void GetTime(char *);
int gmt2local(time_t);
void ts_print(register const struct timeval *, char *);
char *copy_argv(char **);
void strip(char *);
double CalcPct(UINT64, UINT64);
void ReadPacketsFromFile();
void GenHomenet(char *);
void InitNetmasks();
void InitBinFrag();
void GoDaemon();
void SignalWaitingParent();
void CheckLogDir();
char *read_infile(char *);
void InitProtoNames();
void CleanupProtoNames();
void ErrorMessage(const char *, ...);
void LogMessage(const char *, ...);
NORETURN void FatalError(const char *, ...);
void CreatePidFile(char *);
void ClosePidFile();
void SetUidGid(void);
void SetChroot(char *, char **);
void DropStats(int);
void GenObfuscationMask(char *);
void *SPAlloc(unsigned long, struct _SPMemControl *);
int SnortSnprintf(char *, size_t, const char *, ...);
int SnortSnprintfAppend(char *, size_t, const char *, ...);
char *SnortStrdup(const char *);
int SnortStrncpy(char *, const char *, size_t);
char *SnortStrndup(const char *, size_t);
int SnortStrnlen(const char *, int);
const char *SnortStrnPbrk(const char *s, int slen, const char *accept);
const char *SnortStrnStr(const char *s, int slen, const char *searchstr);
const char *SnortStrcasestr(const char *s, const char *substr);
void *SnortAlloc(unsigned long);
void *SnortAlloc2(size_t, const char *, ...);
char *CurrentWorkingDir(void);
char *GetAbsolutePath(char *dir);
char *StripPrefixDir(char *prefix, char *dir);
void DefineAllIfaceVars();
void DefineIfaceVar(char *,u_char *, u_char *);
#ifdef TIMESTATS
void DropStatsPerTimeInterval(void);
void ResetTimeStats(void);
#endif
#define PCAP_CLOSE  // allow for rollback for now
#ifdef PCAP_CLOSE
/* cacheReturn = 0 is normal operation; 1 will cause the
 * return value to be returned on the next call with 0 */
int UpdatePcapPktStats(int cacheReturn);
#else
int UpdatePcapPktStats(void);
#endif
UINT64 GetPcapPktStatsRecv(void);
UINT64 GetPcapPktStatsDrop(void);
void TimeStats(void);
#ifndef WIN32
SF_LIST * SortDirectory(const char *);
int GetFilesUnderDir(const char *, SF_QUEUE *, const char *);
#endif

#define COPY4(x, y) \
    x[0] = y[0]; x[1] = y[1]; x[2] = y[2]; x[3] = y[3];

#define COPY16(x,y) \
    x[0] = y[0]; x[1] = y[1]; x[2] = y[2]; x[3] = y[3]; \
    x[4] = y[4]; x[5] = y[5]; x[6] = y[6]; x[7] = y[7]; \
    x[8] = y[8]; x[9] = y[9]; x[10] = y[10]; x[11] = y[11]; \
    x[12] = y[12]; x[13] = y[13]; x[14] = y[14]; x[15] = y[15];

#endif /*__UTIL_H__*/
