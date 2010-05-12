/* $Id$ */
/*
** Copyright (C) 2002-2008 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
** Copyright (C) 1999,2000,2001 Christian Lademann <cal@zls.de>
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

/*
 * CREDITS:
 *
 * The functionality presented here was inspired by
 * the program "couic" by Michel Arboi <arboi@bigfoot.com>
 *
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#if defined(ENABLE_RESPONSE) && !defined(ENABLE_RESPONSE2)
#include <libnet.h>

#include "decode.h"
#include "rules.h"
#include "plugbase.h"
#include "parser.h"
#include "debug.h"
#include "util.h"
#include "log.h"
#include "plugin_enum.h"
#include "snort.h"

#include "snort.h"
#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats respondPerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif

#ifdef DETECTION_OPTION_TREE
#include "sfhashfcn.h"
#include "detection_options.h"
#endif /* DETECTION_OPTION_TREE */

typedef struct _RespondData
{
    u_int response_flag;
} RespondData;

void RespondInit(char *, OptTreeNode *, int ); 
void RespondRestartFunction(int, void *);
int ParseResponse(char *);
int SendICMP_UNREACH(int, snort_ip_p, snort_ip_p, Packet *);
int SendTCPRST(snort_ip_p, snort_ip_p, u_short, u_short, u_long, u_long, u_short);
int Respond(Packet *, RspFpList *);

#ifdef DETECTION_OPTION_TREE
u_int32_t RespondHash(void *d)
{
    u_int32_t a,b,c;
    RespondData *data = (RespondData *)d;

    a = data->response_flag;
    b = RULE_OPTION_TYPE_RESPOND;
    c = 0;

    final(a,b,c);

    return c;
}

int RespondCompare(void *l, void *r)
{
    RespondData *left = (RespondData *)l;
    RespondData *right = (RespondData *)r;

    if (!left || !right)
        return DETECTION_OPTION_NOT_EQUAL;

    if (left->response_flag == right->response_flag)
    {
        return DETECTION_OPTION_EQUAL;
    }

    return DETECTION_OPTION_NOT_EQUAL;
}
#endif /* DETECTION_OPTION_TREE */

int nd; /* raw socket descriptor */
u_int8_t ttl;   /* placeholder for randomly generated TTL */

u_int8_t *tcp_pkt;
u_int8_t *icmp_pkt;

void PrecacheTcp(void);
void PrecacheIcmp(void);

/**************************************************************************
 *
 * Function: SetupRespond();
 *
 * Purpose: Initialize repsond plugin
 *
 * Arguments: None.
 *
 * Returns: void
 **************************************************************************/

void SetupRespond(void)
{
    RegisterPlugin("resp", RespondInit, OPT_TYPE_ACTION);
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("resp", &respondPerfStats, 3, &ruleOTNEvalPerfStats);
#endif
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Plugin: Respond Setup\n"););
    nd = -1;
}

void RespondRestartFunction(int signal, void *foo)
{
    if (nd != -1)
    {
        libnet_close_raw_sock(nd);
        nd = -1;
    }
    if (tcp_pkt != NULL)
        libnet_destroy_packet((u_char **)&tcp_pkt);
    if (icmp_pkt != NULL)
        libnet_destroy_packet((u_char **)&icmp_pkt);

    return;
}

void RespondInit(char *data, OptTreeNode *otn, int protocol) 
{
    RespondData *rd;
#ifdef DETECTION_OPTION_TREE
    void *idx_dup;
#endif

    if(protocol != IPPROTO_TCP && protocol != IPPROTO_UDP &&
       protocol != IPPROTO_ICMP)
    {
        FatalError("%s(%d): Can't respond to IP protocol rules\n", 
                   file_name, file_line);
    }
    if(nd == -1) /* need to open it only once */
    {
        if((nd = libnet_open_raw_sock(IPPROTO_RAW)) < 0)
        {
            FatalError("cannot open raw socket for libnet, exiting...\n");
        }
    }

    ttl = (u_int8_t)libnet_get_prand(PR8);

    if(ttl < 64)
    {
        ttl += 64;
    } 

    rd = (RespondData *)SnortAlloc(sizeof(RespondData));
    
    rd->response_flag = ParseResponse(data);
    
#ifdef DETECTION_OPTION_TREE
    if (add_detection_option(RULE_OPTION_TYPE_RESPOND, (void *)rd, &idx_dup) == DETECTION_OPTION_EQUAL)
    {
        free(rd);
        rd = idx_dup;
     }
#endif /* DETECTION_OPTION_TREE */

    AddRspFuncToList(Respond, otn, (void *)rd );
    AddFuncToRestartList(RespondRestartFunction, NULL);

    return;
}

/****************************************************************************
 *
 * Function: ParseResponse(char *)
 *
 * Purpose: Figure out how to handle hostile connection attempts
 *
 * Arguments: type => string of comma-sepatared modifiers
 *
 * Returns: void function
 *
 ***************************************************************************/
int ParseResponse(char *type)
{
    char *p;
    int response_flag;
    int make_tcp = 0;
    int make_icmp = 0;

    while(isspace((int) *type))
        type++;

    if(!type || !(*type))
        return 0;

    response_flag = 0;

    p = strtok(type, ",");
    while(p)
    {
        if(!strncasecmp(p, "rst_snd", 7))
        {
            response_flag |= RESP_RST_SND;
            make_tcp = 1;
        }
        else if(!strncasecmp(p, "rst_rcv", 7))
        {
            response_flag |= RESP_RST_RCV;
            make_tcp = 1;
        }
        else if(!strncasecmp(p, "rst_all", 7))
        {
            response_flag |= (RESP_RST_SND | RESP_RST_RCV);
            make_tcp = 1;
        }
        else if(!strncasecmp(p, "icmp_net", 8))
        {
            response_flag |= RESP_BAD_NET;
            make_icmp = 1;
        }
        else if(!strncasecmp(p, "icmp_host", 9))
        {
            response_flag |= RESP_BAD_HOST;
            make_icmp = 1;
        }
        else if(!strncasecmp(p, "icmp_port", 9))
        {
            response_flag |= RESP_BAD_PORT;
            make_icmp = 1;
        }
        else if(!strncasecmp(p, "icmp_all", 9))
        {
            response_flag |= (RESP_BAD_NET | RESP_BAD_HOST | RESP_BAD_PORT);
            make_icmp = 1;
        }
        else
        {
            FatalError("%s(%d): invalid response modifier: %s\n", file_name, 
                    file_line, p);
        }

        p = strtok(NULL, ",");
    }

    if(make_tcp)
    {
        PrecacheTcp();
    }

    if(make_icmp)
    {
        /* someday came sooner than expected. -Jeff */
        PrecacheIcmp();
    }

    return response_flag;
}


void PrecacheTcp(void)
{
    int sz = IP_H + TCP_H + 1;  /* extra octet required to avoid crash - why? */

    if((tcp_pkt = calloc(sz, sizeof(u_int8_t))) == NULL)
    {
        FatalError("PrecacheTCP() calloc failed!\n");
    }

    libnet_build_ip( TCP_H                             /* Length of packet data */
                   , 0                                 /* IP tos */
                   , (u_short) libnet_get_prand(PRu16) /* IP ID */
                   , 0                                 /* Fragmentation flags and offset */
                   , ttl                               /* TTL */
                   , IPPROTO_TCP                       /* Protocol */
                   , 0                                 /* Source IP Address */
                   , 0                                 /* Destination IP Address */
                   , NULL                              /* Pointer to packet data (or NULL) */
                   , 0                                 /* Packet payload size */
                   , tcp_pkt                           /* Pointer to packet header memory */
                   );

    libnet_build_tcp( 0              /* Source port */
                    , 0              /* Destination port */
                    , 0              /* Sequence Number */
                    , 0              /* Acknowledgement Number */
                    , TH_RST|TH_ACK  /* Control bits */
                    , 0              /* Advertised Window Size */
                    , 0              /* Urgent Pointer */
                    , NULL           /* Pointer to packet data (or NULL) */
                    , 0              /* Packet payload size */
                    , tcp_pkt + IP_H /* Pointer to packet header memory */
                    );

    return;
}

void PrecacheIcmp(void)
{
    int sz = IP_H + ICMP_UNREACH_H + 68;    /* plan for IP options */

    if((icmp_pkt = calloc(sz, sizeof(char))) == NULL)
    {
        FatalError("PrecacheIcmp() calloc failed!\n");
    }

    libnet_build_ip( ICMP_UNREACH_H                    /* Length of packet data */
                   , 0                                 /* IP tos */
                   , (u_short) libnet_get_prand(PRu16) /* IP ID */
                   , 0                                 /* Fragmentation flags and offset */
                   , ttl                               /* TTL */
                   , IPPROTO_ICMP                      /* Protocol */
                   , 0                                 /* Source IP Address */
                   , 0                                 /* Destination IP Address */
                   , NULL                              /* Pointer to packet data (or NULL) */
                   , 0                                 /* Packet payload size */
                   , icmp_pkt                          /* Pointer to packet header memory */
                   );

    libnet_build_icmp_unreach( 3                /* icmp type */
                             , 0                /* icmp code */
                             , 0                /* Original Length of packet data */
                             , 0                /* Original IP tos */
                             , 0                /* Original IP ID */
                             , 0                /* Original Fragmentation flags and offset */
                             , 0                /* Original TTL */
                             , 0                /* Original Protocol */
                             , 0                /* Original Source IP Address */
                             , 0                /* Original Destination IP Address */
                             , NULL             /* Pointer to original packet data (or NULL) */
                             , 0                /* Packet payload size (or 0) */
                             , icmp_pkt + IP_H  /* Pointer to packet header memory */
                             );

    return;
}


/****************************************************************************

 *
 * Function: Respond(Packet *p, RspFpList)
 *
 * Purpose: Respond to hostile connection attempts
 *
 * Arguments:
 *
 * Returns: void function
 *
 ***************************************************************************/

int Respond(Packet *p, RspFpList *fp_list)
{
    RespondData *rd;
    PROFILE_VARS;
    
    rd = (RespondData *)fp_list->params;

    if(!IPH_IS_VALID(p))
    {
        return 0;
    }

    PREPROC_PROFILE_START(respondPerfStats);
    
    if(rd->response_flag)
    {
        if(rd->response_flag & (RESP_RST_SND | RESP_RST_RCV))
        {
            if(GET_IPH_PROTO(p) == IPPROTO_TCP && p->tcph != NULL)
            {
                /*
                **  This ensures that we don't reset packets that we just
                **  spoofed ourselves, thus inflicting a self-induced DOS
                **  attack.
                **
                **  We still reset packets that may have the SYN set, though.
                */
                if((p->tcph->th_flags & (TH_SYN | TH_RST)) != TH_RST)
                {
                    if(rd->response_flag & RESP_RST_SND)
                    {
                        SendTCPRST(GET_DST_IP(p), 
                                   GET_SRC_IP(p),
                                   p->tcph->th_dport, p->tcph->th_sport,
                                   p->tcph->th_ack, 
                                   htonl(ntohl(p->tcph->th_seq) + p->dsize),
                                   p->tcph->th_win);
                    }

                    if(rd->response_flag & RESP_RST_RCV)
                    {
                        SendTCPRST(GET_SRC_IP(p), 
                                   GET_DST_IP(p),
                                   p->tcph->th_sport, p->tcph->th_dport, 
                                   p->tcph->th_seq, 
                                   htonl(ntohl(p->tcph->th_ack) + p->dsize),
                                   p->tcph->th_win);
                    }
                }
            }
        }

        /*
        **  We check that we only reset packets with an ICMP packet if it is
        **  valid.  This means that we don't reset ICMP error types and will
        **  only reset ICMP query request.
        */
        if((p->icmph == NULL) || 
           (p->icmph->type == ICMP_ECHO) ||
           (p->icmph->type == ICMP_TIMESTAMP) || 
           (p->icmph->type == ICMP_INFO_REQUEST) ||
           (p->icmph->type == ICMP_ADDRESS))
        {
            if(rd->response_flag & RESP_BAD_NET)
                SendICMP_UNREACH(ICMP_UNREACH_NET, GET_DST_IP(p),
                                 GET_SRC_IP(p), p);

            if(rd->response_flag & RESP_BAD_HOST)
                SendICMP_UNREACH(ICMP_UNREACH_HOST, GET_DST_IP(p),
                                 GET_SRC_IP(p), p);

            if(rd->response_flag & RESP_BAD_PORT)
                SendICMP_UNREACH(ICMP_UNREACH_PORT, GET_DST_IP(p),
                                 GET_SRC_IP(p), p);
        }
    }
    PREPROC_PROFILE_END(respondPerfStats);
    return 1; /* always success */
}


int SendICMP_UNREACH(int code, snort_ip_p saddr, snort_ip_p daddr, Packet * p)
{
    int payload_len, sz;
    IPHdr *iph;
    ICMPHdr *icmph;

    if(p == NULL)
        return -1;

    /* don't send ICMP port unreachable errors in response to ICMP messages */
    if (GET_IPH_PROTO(p) == 1 && code == ICMP_UNREACH_PORT)
    {
        if (pv.verbose_flag)
        {
            ErrorMessage("ignoring icmp_port set on ICMP packet.\n");
        }
        
        return 0;
    }

    iph = (IPHdr *) icmp_pkt;
    icmph = (ICMPHdr *) (icmp_pkt + IP_H);

#ifdef SUP_IP6
// XXX-IPv6 Not yet implemented - sp_respond.c
#else
    iph->ip_src.s_addr = saddr;
    iph->ip_dst.s_addr = daddr;
#endif

    icmph->code = code;

    if ((payload_len = ntohs(p->iph->ip_len) - (IP_HLEN(p->iph) << 2)) > 8)
        payload_len = 8;

    memcpy((char *)icmph + ICMP_UNREACH_H, p->iph, (IP_HLEN(p->iph) << 2)
            + payload_len);

    sz = IP_H + ICMP_UNREACH_H + (IP_HLEN(p->iph) << 2) + payload_len;
    iph->ip_len = htons( (u_short) sz);

    libnet_do_checksum(icmp_pkt, IPPROTO_ICMP, sz - IP_H);

#ifdef DEBUG
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "firing ICMP response packet\n"););
    PrintNetData(stdout, icmp_pkt, sz);
    //ClearDumpBuf();
#endif
    if(libnet_write_ip(nd, icmp_pkt, sz) < sz)
    {
        libnet_error(LIBNET_ERR_CRITICAL, "SendICMP_UNREACH: libnet_write_ip");
        return -1;
    }
    return 0;
}


int SendTCPRST(snort_ip_p saddr, snort_ip_p daddr, u_short sport, u_short dport, 
        u_long seq, u_long ack, u_short win)
{
    int sz = IP_H + TCP_H;
    IPHdr *iph;
    TCPHdr *tcph;

    iph = (IPHdr *) tcp_pkt;
    tcph = (TCPHdr *) (tcp_pkt + IP_H);

#ifdef SUP_IP6
#else
    iph->ip_src.s_addr = saddr;
    iph->ip_dst.s_addr = daddr;
#endif
    
    tcph->th_sport = sport;
    tcph->th_dport = dport;
    tcph->th_seq = seq;
    tcph->th_ack = ack;
    tcph->th_win = 0;

    libnet_do_checksum(tcp_pkt, IPPROTO_TCP, sz - IP_H);
    
    DEBUG_WRAP(
	       PrintNetData(stdout, tcp_pkt, sz);
	       //ClearDumpBuf();
	       DebugMessage(DEBUG_PLUGIN, "firing response packet\n");
	       DebugMessage(DEBUG_PLUGIN,
                   "0x%lX:%u -> 0x%lX:%d (seq: 0x%lX  ack: 0x%lX)\n",
			        saddr, sport, daddr, dport, seq, ack););
    
    if(libnet_write_ip(nd, tcp_pkt, sz) < sz)
    {
        libnet_error(LIBNET_ERR_CRITICAL, "SendTCPRST: libnet_write_ip");
        return -1;
    }

    return 0;
}

#endif /* ENABLE_RESPONSE && !ENABLE_RESPONSE2 */
