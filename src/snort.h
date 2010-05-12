/*
** Copyright (C) 2005-2008 Sourcefire, Inc.
** Copyright (C) 1998-2005 Martin Roesch <roesch@sourcefire.com>
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

/* $Id$ */

#ifndef __SNORT_H__
#define __SNORT_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <pcap.h>
#include <stdio.h>

#include "decode.h"
#include "perf.h"
#include "sf_types.h"
#include "sflsq.h"

#ifdef GIDS
#include "inline.h"
#endif /* GIDS */

#if defined(INLINE_FAILOPEN) || defined(TARGET_BASED)
#include "pthread.h"
#endif

extern SFPERF sfPerf;

/* Mark this as a modern version of snort */
#define SNORT_20

/*  I N C L U D E S  **********************************************************/

/* This macro helps to simplify the differences between Win32 and
   non-Win32 code when printing out the name of the interface */
#ifndef WIN32
    #define PRINT_INTERFACE(i)  (i ? i : "NULL")
#else
    #define PRINT_INTERFACE(i)  print_interface(i)
#endif

/*  D E F I N E S  ************************************************************/
#define STD_BUF  1024

#define RF_ANY_SIP    0x01
#define RF_ANY_DIP    0x02
#define RF_ANY_SP     0x04
#define RF_ANY_DP     0x10
#define RF_ANY_FLAGS  0x20

#define MAX_PIDFILE_SUFFIX 11 /* uniqueness extension to PID file, see '-R' */

#ifndef _PATH_VARRUN
extern char _PATH_VARRUN[STD_BUF];
#endif

#ifndef WIN32
    #define DEFAULT_LOG_DIR            "/var/log/snort"
    #define DEFAULT_DAEMON_ALERT_FILE  "alert"
#else
    #define DEFAULT_LOG_DIR            "log"
    #define DEFAULT_DAEMON_ALERT_FILE  "log/alert.ids"
#endif  /* WIN32 */

/* you can redefine the user ID which is allowed to
 * initialize interfaces using pcap and read from them
 */
#ifndef SNIFFUSER
    #define SNIFFUSER 0
#endif


#ifdef ACCESSPERMS
    #define FILEACCESSBITS ACCESSPERMS
#else
    #ifdef  S_IAMB
        #define FILEACCESSBITS S_IAMB
    #else
        #define FILEACCESSBITS 0x1FF
    #endif
#endif    

#define TIMEBUF_SIZE    26


#define ASSURE_ALL    0  /* all TCP alerts fire regardless of stream state */
#define ASSURE_EST    1  /* only established TCP sessions fire alerts */

#define DO_IP_CHECKSUMS     0x00000001
#define DO_TCP_CHECKSUMS    0x00000002
#define DO_UDP_CHECKSUMS    0x00000004
#define DO_ICMP_CHECKSUMS   0x00000008

#define LOG_UNIFIED         0x00000001
#define LOG_TCPDUMP         0x00000002
#define LOG_UNIFIED2         0x0000004

#define SIGNAL_SNORT_ROTATE_STATS  28
#define SIGNAL_SNORT_CHILD_READY   29
#ifdef TARGET_BASED
#define SIGNAL_SNORT_READ_ATTR_TBL 30
#endif

/*  D A T A  S T R U C T U R E S  *********************************************/

#define MODE_PACKET_DUMP    1
#define MODE_PACKET_LOG     2
#define MODE_IDS            3
#define MODE_TEST           4
#define MODE_RULE_DUMP      5
#define MODE_VERSION        6

extern u_int8_t runMode;

typedef struct _Configuration
{
    char *logging_directory;

} Configuration;

typedef struct _Capabilities
{
    u_int8_t stateful_inspection;

} Capabilities;

typedef struct _runtime_config
{
    Configuration configuration;
    Capabilities capabilities;
} runtime_config;

#define LOG_ASCII   1
#define LOG_PCAP    2
#define LOG_NONE    3

#define ALERT_FULL     1
#define ALERT_FAST     2
#define ALERT_NONE     3
#define ALERT_UNSOCK   4
#define ALERT_STDOUT   5
#define ALERT_CMG      6
#define ALERT_SYSLOG   8
#define ALERT_TEST     9
#define ALERT_UNIFIED  10

#define MAX_IFS        1

#ifdef MPLS
#define DEFAULT_MPLS_MULTICAST        0
#define DEFAULT_MPLS_OVERLAPPING_IP   0
#define MPLS_PAYLOADTYPE_IPV4         1
#define MPLS_PAYLOADTYPE_ETHERNET     2
#define MPLS_PAYLOADTYPE_IPV6         3
#define DEFAULT_MPLS_PAYLOADTYPE      1
#define DEFAULT_LABELCHAIN_LENGTH      -1
#endif

/* This feature allows us to change the state of a rule,
 * independent of it appearing in a rules file.
 */
#define RULE_STATE_DISABLED 0
#define RULE_STATE_ENABLED 1

typedef struct _RuleState
{
    int sid;
    int gid;
    int state;
    int action;
    struct _RuleState *next;
} RuleState;

#include "profiler.h"

/* GetoptLong Option numbers */
#define PID_PATH                  1
#ifdef DYNAMIC_PLUGIN
#define DYNAMIC_LIBRARY_DIRECTORY 2
#define DYNAMIC_LIBRARY_FILE      3
#define DYNAMIC_PREPROC_DIRECTORY 4
#define DYNAMIC_PREPROC_FILE      5
#define DYNAMIC_ENGINE_FILE       6
#define DYNAMIC_ENGINE_DIRECTORY  7
#define DUMP_DYNAMIC_RULES        8
#define DUMP_DYNAMIC_PREPROCS     9
#endif
#define ARG_RESTART               10
#define CREATE_PID_FILE           11
#define TREAT_DROP_AS_ALERT       12
#define PROCESS_ALL_EVENTS        13
#define ALERT_BEFORE_PASS         14
#define NOLOCK_PID_FILE           15
#define DISABLE_INLINE_INIT       16
#ifdef INLINE_FAILOPEN
#define DISABLE_INLINE_FAILOPEN   17
#endif
#define NO_LOGGING_TIMESTAMPS     18
#define PCAP_LOOP                 19
#define PCAP_SINGLE               20
#define PCAP_FILE_LIST            21
#define PCAP_LIST                 22
#define PCAP_DIR                  23
#define PCAP_FILTER               24
#define PCAP_NO_FILTER            25
#define PCAP_RESET                26
#define PCAP_SHOW                 27
#define EXIT_CHECK  // allow for rollback for now
#ifdef EXIT_CHECK
#define ARG_EXIT_CHECK            28
#endif
#ifdef TARGET_BASED
#define DISABLE_ATTRIBUTE_RELOAD  29
#endif
#define DETECTION_SEARCH_METHOD   30
#define CONF_ERROR_OUT                 31
#ifdef MPLS
#define ENABLE_MPLS_MULTICAST     31
#define ENABLE_OVERLAPPING_IP     32
#define MAX_MPLS_LABELCHAIN_LEN   33
#define MPLS_PAYLOAD_TYPE         34
#endif

#ifdef DYNAMIC_PLUGIN
typedef struct _DynamicDetectionSpecifier
{
    int type;
    char *path;
} DynamicDetectionSpecifier;
#endif

/* struct to contain the program variables and command line args */
typedef struct _progvars
{
    int static_hash;
    int stateful;
    int line_buffer_flag;
    int checksums_mode;
    int checksums_drop;
    int assurance_mode;
    int max_pattern;
    int test_mode_flag;
    int alert_interface_flag;
    int verbose_bytedump_flag;
    int obfuscation_flag;
    int log_cmd_override;
    int alert_cmd_override;
    int char_data_flag;
    int data_flag;
    int verbose_flag;
    int readmode_flag;
    int show2hdr_flag;
    int showwifimgmt_flag;
    int inline_flag;
    char disable_inline_init_flag;
#ifdef INLINE_FAILOPEN
    char initialization_done_flag;
    char pass_thread_running_flag;
    pthread_t pass_thread_id;
    pid_t pass_thread_pid;
    int pass_thread_pktcount;
    char inline_failopen_disabled_flag;
#endif
#ifdef GIDS
#ifndef IPFW
    char layer2_resets;
    u_char enet_src[6];
#endif
#ifdef IPFW
    int divert_port;
#endif /* USE IPFW DIVERT socket instead of IPtables */
#endif /* GIDS */
#ifdef WIN32
    int syslog_remote_flag;
    char syslog_server[STD_BUF];
    int syslog_server_port;
#ifdef ENABLE_WIN32_SERVICE
    int terminate_service_flag;
    int pause_service_flag;
#endif  /* ENABLE_WIN32_SERVICE */
#endif  /* WIN32 */
    int promisc_flag;
    int rules_order_flag;
    int track_flag;
    int daemon_flag;
    int daemon_restart_flag;
    int logtosyslog_flag;
    int quiet_flag;
    int print_version;
    int pkt_cnt;
    int pkt_snaplen;
#ifdef SUP_IP6
    sfip_t homenet;
    sfip_t obfuscation_net;
#else
    u_long homenet;
    u_long netmask;
    u_int32_t obfuscation_net;
    u_int32_t obfuscation_mask;
#endif
    int alert_mode;
    int log_plugin_active;
    int alert_plugin_active;
    u_int32_t log_bitmap;
    char pid_filename[STD_BUF];
    char *config_file;
    char *config_dir;
    char *log_dir;
    char readfile[STD_BUF];
    char pid_path[STD_BUF];
    char *interface;
    char *pcap_cmd;
    char *alert_filename;
    char *binLogFile;
    int use_utc;
    int include_year;
    char *chroot_dir;
    u_int8_t min_ttl;
    u_int8_t log_mode;
    int num_rule_types;
    char pidfile_suffix[MAX_PIDFILE_SUFFIX+1]; /* room for a null */
    char create_pid_file;
    char nolock_pid_file;
    DecoderFlags decoder_flags; /* if decode.c alerts are going to be enabled */
    char ignore_ports[0x10000]; /* 65536, enough to hold ports */
    int rotate_perf_file;
    u_int32_t event_log_id;

#ifdef DYNAMIC_PLUGIN
#define MAX_DYNAMIC_ENGINES 16
    u_int32_t dynamicEngineCount;
    u_int8_t dynamicEngineCurrentDir;
    DynamicDetectionSpecifier *dynamicEngine[MAX_DYNAMIC_ENGINES];

#define MAX_DYNAMIC_DETECTION_LIBS 16
    u_int8_t dynamicLibraryCount;
    u_int8_t dynamicLibraryCurrentDir;
    DynamicDetectionSpecifier *dynamicDetection[MAX_DYNAMIC_DETECTION_LIBS];

    char dump_dynamic_rules_flag;
    char dynamic_rules_path[STD_BUF];

#define MAX_DYNAMIC_PREPROC_LIBS 16
    u_int8_t dynamicPreprocCount;
    u_int8_t dynamicPreprocCurrentDir;
    DynamicDetectionSpecifier *dynamicPreprocs[MAX_DYNAMIC_PREPROC_LIBS];

#endif

    int default_rule_state; /* Enabled */
    u_int32_t numRuleStates;
    RuleState *ruleStateList;

    int done_processing;

#if defined(ENABLE_RESPONSE2) && !defined(ENABLE_RESPONSE)
    int respond2_link;
    int respond2_rows;
    int respond2_memcap;
    u_int8_t respond2_attempts;
    char *respond2_ethdev;
#endif
    int usr_signal;
    int cant_hup_signal;
#ifdef TIMESTATS
    int alrm_signal;
    u_int32_t timestats_interval;
#endif
    int exit_signal;
    int restart_flag;
#ifdef PERF_PROFILING
    int profile_rules_flag;
    int profile_rules_sort;
    int profile_preprocs_flag;
    int profile_preprocs_sort;
    char *profile_rules_filename;
    int profile_rules_append;
    char *profile_preprocs_filename;
    int profile_preprocs_append;
#endif
    int tagged_packet_limit;
    int treat_drop_as_alert;
    int process_all_events;
    int alert_before_pass;
    int alert_packet_count;/* diplays packet count with alerts in console mode */
    char nostamp;

    /* XXX Move to IPv6 frag preprocessor once written */
    u_int32_t ipv6_frag_timeout;
    u_int32_t ipv6_max_frag_sessions;


#ifdef TARGET_BASED
    pthread_t attribute_reload_thread_id;
    pid_t attribute_reload_thread_pid;
    char attribute_reload_thread_running;
    char attribute_reload_thread_stop;
#define ATTRIBUTE_TABLE_RELOAD_FLAG 0x01
#define ATTRIBUTE_TABLE_AVAILABLE_FLAG 0x02
#define ATTRIBUTE_TABLE_RELOADING_FLAG 0x04
#define ATTRIBUTE_TABLE_TAKEN_FLAG 0x08
#define ATTRIBUTE_TABLE_PARSE_FAILED_FLAG 0x10
    char reload_attribute_table_flags;
#define DEFAULT_MAX_ATTRIBUTE_HOSTS 10000
#define MAX_MAX_ATTRIBUTE_HOSTS 512 * 1024
#define MIN_MAX_ATTRIBUTE_HOSTS 32
    u_int32_t max_attribute_hosts;
    char disable_attribute_reload_thread;
#endif

#ifdef PREPROCESSOR_AND_DECODER_RULE_EVENTS
    char generate_preprocessor_decoder_otn;
#endif

    SF_QUEUE *pcap_queue;
    SF_QUEUE *pcap_save_queue;
    int pcap_loop_count;
    char pcap_reset;
    char pcap_show;

#ifdef EXIT_CHECK
    unsigned long exit_check;
#endif
    long pcre_match_limit;
    long pcre_match_limit_recursion;

    unsigned max_inq;
    UINT64 tot_inq_flush;
    UINT64 tot_inq_inserts;
    UINT64 tot_inq_uinserts;
    int conf_error_out;
#ifdef MPLS
    u_int8_t mpls_multicast;
    u_int8_t overlapping_IP;
    int mpls_stack_depth;
    u_int8_t mpls_payload_type;
#endif
} PV;

/* struct to collect packet statistics */
typedef struct _PacketCount
{
    UINT64 total_from_pcap;
    UINT64 total_processed;

    UINT64 s5tcp1;
    UINT64 s5tcp2;
    UINT64 ipv6opts;
    UINT64 eth;
    UINT64 ethdisc;
    UINT64 ipv6disc;
    UINT64 ip6ext;
    UINT64 other;
    UINT64 tcp;
    UINT64 udp;
    UINT64 icmp;
    UINT64 arp;
    UINT64 eapol;
    UINT64 vlan;
    UINT64 ipv6;
    UINT64 ipv6_up;
    UINT64 ipv6_upfail;
    UINT64 frag6;
    UINT64 icmp6;
    UINT64 tdisc;
    UINT64 udisc;
    UINT64 tcp6;
    UINT64 udp6;
    UINT64 ipdisc;
    UINT64 icmpdisc;
    UINT64 embdip;
    UINT64 ip;
    UINT64 ipx;
    UINT64 ethloopback;

    UINT64 invalid_checksums;

#ifdef GRE
    UINT64 ip4ip4;
    UINT64 ip4ip6;
    UINT64 ip6ip4;
    UINT64 ip6ip6;

    UINT64 gre;
    UINT64 gre_ip;
    UINT64 gre_eth;
    UINT64 gre_arp;
    UINT64 gre_ipv6;
    UINT64 gre_ipv6ext;
    UINT64 gre_ipx;
    UINT64 gre_loopback;
    UINT64 gre_vlan;
    UINT64 gre_ppp;
#endif

    UINT64 discards;
    UINT64 alert_pkts;
    UINT64 log_pkts;
    UINT64 pass_pkts;

    UINT64 frags;           /* number of frags that have come in */
    UINT64 frag_trackers;   /* number of tracking structures generated */
    UINT64 rebuilt_frags;   /* number of packets rebuilt */
    UINT64 frag_incomp;     /* number of frags cleared due to memory issues */
    UINT64 frag_timeout;    /* number of frags cleared due to timeout */
    UINT64 rebuild_element; /* frags that were element of rebuilt pkt */
    UINT64 frag_mem_faults; /* number of times the memory cap was hit */

    UINT64 tcp_stream_pkts; /* number of packets tcp reassembly touches */
    UINT64 rebuilt_tcp;     /* number of phoney tcp packets generated */
    UINT64 tcp_streams;     /* number of tcp streams created */
    UINT64 rebuilt_segs;    /* number of tcp segments used in rebuilt pkts */
    UINT64 queued_segs;     /* number of tcp segments stored for rebuilt pkts */
    UINT64 str_mem_faults;  /* number of times the stream memory cap was hit */

#ifdef TARGET_BASED
    UINT64 attribute_table_reloads; /* number of times attribute table was reloaded. */
#endif

#ifdef DLT_IEEE802_11
  /* wireless statistics */
    UINT64 wifi_mgmt;
    UINT64 wifi_data;
    UINT64 wifi_control; 
    UINT64 assoc_req;
    UINT64 assoc_resp;
    UINT64 reassoc_req;
    UINT64 reassoc_resp;
    UINT64 probe_req;
    UINT64 probe_resp;
    UINT64 beacon;
    UINT64 atim;
    UINT64 dissassoc;
    UINT64 auth;
    UINT64 deauth;
    UINT64 ps_poll;
    UINT64 rts;
    UINT64 cts;
    UINT64 ack;
    UINT64 cf_end;
    UINT64 cf_end_cf_ack;
    UINT64 data;
    UINT64 data_cf_ack;
    UINT64 data_cf_poll;
    UINT64 data_cf_ack_cf_poll;
    UINT64 cf_ack;
    UINT64 cf_poll;
    UINT64 cf_ack_cf_poll;
#endif

#ifdef GIDS
#ifndef IPFW
    UINT64 iptables;
#else
    UINT64 ipfw;
#endif
#endif

#ifdef MPLS
    UINT64 mpls;    
#endif
} PacketCount;

typedef struct _PcapReadObject
{
    int type;
    char *arg;
    char *filter;

} PcapReadObject;


/*  G L O B A L S  ************************************************************/
extern PV pv;                 /* program vars (command line args) */
extern int datalink;          /* the datalink value */
extern char *progname;        /* name of the program (from argv[0]) */
extern char **progargs;
extern char *username;
extern char *groupname;
extern unsigned long userid;
extern unsigned long groupid;
extern struct passwd *pw;
extern struct group *gr;
extern char *pcap_cmd;        /* the BPF command string */
extern char *pktidx;          /* index ptr for the current packet */
extern pcap_t *pd; /* array of packet descriptors per interface */
extern Packet *BsdPseudoPacket; /* Specifically for logging the IPv6 
                                  fragmented ICMP BSD vulnerability */

/* backwards compatibility */
extern FILE *alert;           /* alert file ptr */
extern FILE *binlog_ptr;      /* binary log file ptr */
extern int flow;              /* flow var (probably obsolete) */
extern int thiszone;          /* time zone info */
extern PacketCount pc;        /* packet count information */
extern u_long netmasks[33];   /* precalculated netmask array */
extern struct pcap_pkthdr *g_pkthdr; /* packet header ptr */
extern u_char *g_pkt;         /* ptr to the packet data */
extern u_long g_caplen;       /* length of the current packet */
extern char *protocol_names[256];
extern u_int snaplen;


typedef void (*grinder_t)(Packet *, const struct pcap_pkthdr *, const u_int8_t *);  /* ptr to the packet processor */

extern grinder_t grinder;

/* Snort run-time configuration struct*/
extern runtime_config snort_runtime;

/*  P R O T O T Y P E S  ******************************************************/
int SnortMain(int argc, char *argv[]);
int ParseCmdLine(int, char**);
void *InterfaceThread(void *);
void InitPcap( int );
int OpenPcap();
int SetPktProcessor(void);
void CleanExit(int);
void PcapProcessPacket(char *, struct pcap_pkthdr *, u_char *);
void ProcessPacket(char *, const struct pcap_pkthdr *, const u_char *, void *);
int ShowUsage(char *);
void SigCantHupHandler(int signal);
void print_packet_count();


#endif  /* __SNORT_H__ */
