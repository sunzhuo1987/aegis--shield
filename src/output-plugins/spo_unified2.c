/*
** Copyright (C) 2007-2008 Sourcefire, Inc.
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

/* spo_unified2.c
 * Adam Keeton
 * 
 * 09/26/06
 * This file is litterally spo_unified.c converted to write unified2
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <errno.h>
#include <time.h>

#include "decode.h"
#include "rules.h"
#include "util.h"
#include "plugbase.h"
#include "spo_plugbase.h"
#include "parser.h"
#include "debug.h"
#include "mstring.h"
#include "event.h"
#include "generators.h"
#include "debug.h"
#include "bounds.h"

#include "snort.h"
#include "pcap_pkthdr32.h"

/* For the traversal of reassembled packets */
#include "stream_api.h"

#ifdef GIDS
#include "inline.h"
#endif

/* From fpdetect.c, for logging reassembled packets */
extern u_int16_t event_id;

/* Each unified 2 record will start out with one of these */
typedef struct _Unified2RecordHeader
{
    uint32_t type;          /* Type of header.  A set most-significant
                               bit indicates presence of extended header */
    uint32_t length;

} Unified2RecordHeader;

/* The Unified2Event and Unified2Packet structures below are copied from the 
 * original unified 2 library, sfunified2 */
typedef struct _Unified2Event
{
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t event_microsecond;
    uint32_t signature_id;
    uint32_t generator_id;
    uint32_t signature_revision;
    uint32_t classification_id;
    uint32_t priority_id;
    uint32_t ip_source;
    uint32_t ip_destination;
    uint16_t sport_itype;
    uint16_t dport_icode;
    uint8_t  protocol;
    uint8_t  packet_action;
} Unified2Event;

typedef struct _Unified2Event_MPLS
{
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t event_microsecond;
    uint32_t signature_id;
    uint32_t generator_id;
    uint32_t signature_revision;
    uint32_t classification_id;
    uint32_t priority_id;
    uint32_t ip_source;
    uint32_t ip_destination;
    uint16_t sport_itype;
    uint16_t dport_icode;
    uint8_t  protocol;
    uint8_t  packet_action;
    uint32_t mpls_label;
} Unified2Event_MPLS;

typedef struct _Unified2Event6
{
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t event_microsecond;
    uint32_t signature_id;
    uint32_t generator_id;
    uint32_t signature_revision;
    uint32_t classification_id;
    uint32_t priority_id;
    struct in6_addr ip_source;
    struct in6_addr ip_destination;
    uint16_t sport_itype;
    uint16_t dport_icode;
    uint8_t  protocol;
    uint8_t  packet_action;
} Unified2Event6;

typedef struct _Unified2Event6_MPLS
{
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t event_microsecond;
    uint32_t signature_id;
    uint32_t generator_id;
    uint32_t signature_revision;
    uint32_t classification_id;
    uint32_t priority_id;
    struct in6_addr ip_source;
    struct in6_addr ip_destination;
    uint16_t sport_itype;
    uint16_t dport_icode;
    uint8_t  protocol;
    uint8_t  packet_action;
    uint32_t mpls_label;
} Unified2Event6_MPLS;

typedef struct _Unified2Packet
{
    uint32_t sensor_id;
    uint32_t event_id;
    uint32_t event_second;
    uint32_t packet_second;
    uint32_t packet_microsecond;
    uint32_t linktype;
    uint32_t packet_length;
    uint8_t packet_data[4];
} Unified2Packet;

/* ----------------External variables -------------------- */
extern OptTreeNode *otn_tmp;
extern int thiszone;

#ifdef GIDS
#ifndef IPFW
extern ipq_packet_msg_t *g_m;
#endif
#endif

/* ------------------ Data structures --------------------------*/
typedef struct _Unified2Config
{
    char *filename;
    FILE *stream;
    unsigned int limit;
    unsigned int current;
    int nostamp;
#ifdef MPLS
    int mpls_event_types;
#endif
} Unified2Config;


/* -------------------- Global Variables ----------------------*/
#ifdef GIDS
EtherHdr g_ethernet;
#endif
/* -------------------- Local Functions -----------------------*/
static Unified2Config *Unified2ParseArgs(char *, char *);
static void Unified2CleanExit(int, void *);
static void Unified2Restart(int, void *);

/* Unified2 Output functions */
static void Unified2Init(char *);
static void Unified2InitFile(Unified2Config *);
static void Unified2RotateFile(Unified2Config *);
static void Unified2LogAlert(Packet *, char *, void *, Event *);
static void Unified2LogPacketAlert(Packet *, char *, void *, Event *);
static void _Unified2LogPacketAlert(Packet *p, char *msg, void *arg, Event *event);
static void _Unified2LogStreamAlert(Packet *,char *,void *,Event *);

/* Unified2 Alert functions (deprecated) */
static void Unified2AlertInit(char *);

/* Unified2 Packet Log functions (deprecated) */
static void Unified2LogInit(char *);

static Unified2Config *unifiedConfig;

/* XXX Remove these when the real Unified 2 header becomes available */
#define UNIFIED2_EVENT 1
#define UNIFIED2_PACKET 2
#define UNIFIED2_IDS_EVENT 7
#define UNIFIED2_EVENT_EXTENDED 66
#define UNIFIED2_PERFORMANCE 67
#define UNIFIED2_PORTSCAN 68
#define UNIFIED2_IDS_EVENT_IPV6 72
#define UNIFIED2_IDS_EVENT_MPLS 99
#define UNIFIED2_IDS_EVENT_IPV6_MPLS 100

#define U2_PACKET_FLAG 1

#define U2_FLAG_BLOCKED 0x20

/* Used for buffering header and payload of unified records so only one
 * write is necessary. */
static char write_pkt_buffer[sizeof(Unified2RecordHeader) + 
                             sizeof(Unified2Event) + IP_MAXPACKET];
#define write_pkt_end \
            write_pkt_buffer + sizeof(Unified2RecordHeader) + \
            sizeof(Unified2Event) + IP_MAXPACKET

static char write_pkt_buffer_mpls[sizeof(Unified2RecordHeader) + 
                             sizeof(Unified2Event_MPLS) + IP_MAXPACKET];
#define write_pkt_end_mpls \
            write_pkt_buffer_mpls + sizeof(Unified2RecordHeader) + \
            sizeof(Unified2Event_MPLS) + IP_MAXPACKET

/*
 * Function: SetupUnified2()
 *
 * Purpose: Registers the output plugin keyword and initialization 
 *          function into the output plugin list.  This is the function that
 *          gets called from InitOutputPlugins() in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 */
void Unified2Setup()
{
    /* link the preprocessor keyword to the init function in 
       the preproc list */
    RegisterOutputPlugin("log_unified2", NT_OUTPUT_LOG, Unified2LogInit);
    RegisterOutputPlugin("alert_unified2", NT_OUTPUT_ALERT, Unified2AlertInit);
    RegisterOutputPlugin("unified2", NT_OUTPUT_SPECIAL, Unified2Init);
    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Output plugin: Unified2 "
                "logging/alerting is setup...\n"););
}

/*
 * Function: Unified2Init(char *)
 *
 * Purpose: Calls the argument parsing function, performs final setup on data
 *          structs, links the preproc function into the function list.
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
void Unified2Init(char *args)
{
    if(unifiedConfig)
    {
        FatalError("unified can only be instantiated once\n");
    }

    //DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Output: Unified2 Initialized\n"););
    pv.log_plugin_active = 1;
    pv.alert_plugin_active = 1;

    /* parse the argument list from the rules file */
    unifiedConfig = Unified2ParseArgs(args, "snort-unified");

    Unified2InitFile(unifiedConfig);

    /* Set the preprocessor function into the function list */
    AddFuncToOutputList(Unified2LogAlert, NT_OUTPUT_ALERT, unifiedConfig);
    AddFuncToOutputList(Unified2LogPacketAlert, NT_OUTPUT_LOG, unifiedConfig);

    AddFuncToCleanExitList(Unified2CleanExit, unifiedConfig);
    AddFuncToRestartList(Unified2Restart, unifiedConfig);
}

/*
 * Function: InitOutputFile()
 *
 * Purpose: Initialize the unified ouput file 
 *
 * Arguments: data => pointer to the plugin's reference data struct 
 *
 * Returns: void function
 */
static void Unified2InitFile(Unified2Config *data)
{
    time_t curr_time;      /* place to stick the clock data */
    char logdir[STD_BUF];
    int ret;

    bzero(logdir, STD_BUF);
    curr_time = time(NULL);

    if(data == NULL)
        FatalError("SpoUnified2: Unable to get context data\n");

    if(data->nostamp) 
    {
        if(data->filename[0] == '/')
            ret = SnortSnprintf(logdir, STD_BUF, "%s",  data->filename);
        else
            ret = SnortSnprintf(logdir, STD_BUF, "%s/%s", pv.log_dir, data->filename);
    }
    else
    {
        if(*(data->filename) == '/')
            ret = SnortSnprintf(logdir, STD_BUF, "%s.%u", data->filename, 
                                (u_int32_t)curr_time);
        else
            ret = SnortSnprintf(logdir, STD_BUF, "%s/%s.%u", pv.log_dir,  
                                data->filename, (u_int32_t)curr_time);
    }

    if (ret != SNORT_SNPRINTF_SUCCESS)
        FatalError("SpoUnified2: filepath too long\n");

    if((data->stream = fopen(logdir, "wb")) == NULL)
        FatalError("Unified2InitFile(%s): %s\n", logdir, strerror(errno));

    return;
}

void Unified2RotateFile(Unified2Config *data)
{
    fclose(data->stream);
    data->current = 0;
    Unified2InitFile(data);
}

int Unified2FirstPacketCallback(struct pcap_pkthdr *pkth,
                                u_int8_t *packet_data, void *userdata)
{
    Unified2Event *alertdata = (Unified2Event*)userdata;
    /* loop thru all the packets in the stream */
    if(pkth != NULL )
    {
        alertdata->event_second = htonl((u_int32_t)pkth->ts.tv_sec);
        alertdata->event_microsecond = htonl((u_int32_t)pkth->ts.tv_usec);
    } 

    /* return non-zero so we only do this once */
    return 1;
}

int Unified2FirstPacketCallback_mpls(struct pcap_pkthdr *pkth,
                                u_int8_t *packet_data, void *userdata)
{
    Unified2Event_MPLS *alertdata = (Unified2Event_MPLS *)userdata;
    /* loop thru all the packets in the stream */
    if(pkth != NULL )
    {
        alertdata->event_second = htonl((u_int32_t)pkth->ts.tv_sec);
        alertdata->event_microsecond = htonl((u_int32_t)pkth->ts.tv_usec);
    } 

    /* return non-zero so we only do this once */
    return 1;
}

static void _AlertIP4(Packet *p, char *msg, void *arg, Event *event)
{
    Unified2RecordHeader hdr;
    Unified2Config *data = (Unified2Config *)arg;
    Unified2Event alertdata;
    
    bzero(&alertdata, sizeof(alertdata));

    alertdata.sensor_id = 0;
    alertdata.event_id = htonl(event->event_id);
    alertdata.event_second = htonl(event->ref_time.tv_sec);
    alertdata.event_microsecond = htonl(event->ref_time.tv_usec);
    alertdata.generator_id = htonl(event->sig_generator);
    alertdata.signature_id = htonl(event->sig_id);
    alertdata.signature_revision = htonl(event->sig_rev);
    alertdata.classification_id = htonl(event->classification);
    alertdata.priority_id = htonl(event->priority);

    if(p)
    {
        if (p->packet_flags & PKT_INLINE_DROP)
        {
            alertdata.packet_action = U2_FLAG_BLOCKED;
        }

        if((p->packet_flags & PKT_REBUILT_STREAM) && stream_api)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_LOG, "man:Logging rebuilt stream data.\n");); 
            /*stream_api->traverse_reassembled(p, Unified2FirstPacketCallback, &alertdata);*/
        }

        if(IPH_IS_VALID(p))
        {
            alertdata.ip_source = p->iph->ip_src.s_addr;
            alertdata.ip_destination = p->iph->ip_dst.s_addr;
            alertdata.protocol = GET_IPH_PROTO(p);
            if((alertdata.protocol == IPPROTO_ICMP) && p->icmph)
            {
                alertdata.sport_itype = htons(p->icmph->type);
                alertdata.dport_icode = htons(p->icmph->code);
            }
            else
            {
                alertdata.sport_itype = htons(p->sp);
                alertdata.dport_icode = htons(p->dp);
            }
        }

        if(alertdata.protocol == 255) 
        {
             alertdata.sport_itype = 0;             
             alertdata.dport_icode = 0;             
        }   
    }
    
    if((sizeof(Unified2RecordHeader) + sizeof(Unified2Event)) > data->limit)
    {
       Unified2RotateFile(data);
    }

    hdr.length = htonl(sizeof(Unified2Event));
    hdr.type = htonl(UNIFIED2_IDS_EVENT);

    SafeMemcpy(write_pkt_buffer, &hdr, sizeof(Unified2RecordHeader), 
               write_pkt_buffer, write_pkt_end);
    
    SafeMemcpy(write_pkt_buffer + sizeof(Unified2RecordHeader),
               &alertdata, sizeof(Unified2Event), 
               write_pkt_buffer, write_pkt_end);

    if(fwrite(write_pkt_buffer, 
              sizeof(Unified2RecordHeader) + sizeof(Unified2Event),
               1, data->stream) != 1)
        FatalError("SpoUnified2: write failed: %s\n", strerror(errno));

    fflush(data->stream);
    data->current += sizeof(Unified2RecordHeader) + sizeof(Unified2Event);
}
#ifdef MPLS
static void _AlertIP4_mpls(Packet *p, char *msg, void *arg, Event *event)
{
    Unified2RecordHeader hdr;
    Unified2Config *data = (Unified2Config *)arg;
    Unified2Event_MPLS alertdata;
    
    bzero(&alertdata, sizeof(alertdata));

    alertdata.sensor_id = 0;
    alertdata.event_id = htonl(event->event_id);
    alertdata.event_second = htonl(event->ref_time.tv_sec);
    alertdata.event_microsecond = htonl(event->ref_time.tv_usec);
    alertdata.generator_id = htonl(event->sig_generator);
    alertdata.signature_id = htonl(event->sig_id);
    alertdata.signature_revision = htonl(event->sig_rev);
    alertdata.classification_id = htonl(event->classification);
    alertdata.priority_id = htonl(event->priority);

    if(p)
    {
        if (p->packet_flags & PKT_INLINE_DROP)
        {
            alertdata.packet_action = U2_FLAG_BLOCKED;
        }

        if((p->packet_flags & PKT_REBUILT_STREAM) && stream_api)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_LOG, "man:Logging rebuilt stream data.\n");); 
            stream_api->traverse_reassembled(p, Unified2FirstPacketCallback_mpls, &alertdata);
        }

        if(IPH_IS_VALID(p))
        {
            alertdata.ip_source = p->iph->ip_src.s_addr;
            alertdata.ip_destination = p->iph->ip_dst.s_addr;
            alertdata.protocol = GET_IPH_PROTO(p);
            if((alertdata.protocol == IPPROTO_ICMP) && p->icmph)
            {
                alertdata.sport_itype = htons(p->icmph->type);
                alertdata.dport_icode = htons(p->icmph->code);
            }
            else
            {
                alertdata.sport_itype = htons(p->sp);
                alertdata.dport_icode = htons(p->dp);
            }
            alertdata.mpls_label = p->mplsHdr.label;
        }

        if(alertdata.protocol == 255) 
        {
            alertdata.sport_itype = 0;             
            alertdata.dport_icode = 0;             
        }   
    }
    
    if((sizeof(Unified2RecordHeader) + sizeof(Unified2Event_MPLS)) > data->limit)
    {
        Unified2RotateFile(data);
    }

    hdr.length = htonl(sizeof(Unified2Event_MPLS));
    hdr.type = htonl(UNIFIED2_IDS_EVENT_MPLS);

    SafeMemcpy(write_pkt_buffer_mpls, &hdr, sizeof(Unified2RecordHeader), 
               write_pkt_buffer_mpls, write_pkt_end_mpls);
    
    SafeMemcpy(write_pkt_buffer_mpls + sizeof(Unified2RecordHeader),
               &alertdata, sizeof(Unified2Event_MPLS), 
               write_pkt_buffer_mpls, write_pkt_end_mpls);

    if(fwrite(write_pkt_buffer_mpls, 
              sizeof(Unified2RecordHeader) + sizeof(Unified2Event_MPLS),
               1, data->stream) != 1)
        FatalError("SpoUnified2: write failed: %s\n", strerror(errno));

    fflush(data->stream);
    data->current += sizeof(Unified2RecordHeader) + sizeof(Unified2Event_MPLS);
}
#endif

static void _AlertIP6(Packet *p, char *msg, void *arg, Event *event) 
{
#ifdef SUP_IP6
    Unified2RecordHeader hdr;
    Unified2Config *data = (Unified2Config *)arg;
    Unified2Event6 alertdata;
    
    bzero(&alertdata, sizeof(alertdata));

    alertdata.sensor_id = 0;
    alertdata.event_id = htonl(event->event_id);
    alertdata.event_second = htonl(event->ref_time.tv_sec);
    alertdata.event_microsecond = htonl(event->ref_time.tv_usec);
    alertdata.generator_id = htonl(event->sig_generator);
    alertdata.signature_id = htonl(event->sig_id);
    alertdata.signature_revision = htonl(event->sig_rev);
    alertdata.classification_id = htonl(event->classification);
    alertdata.priority_id = htonl(event->priority);

    if(p)
    {
        if (p->packet_flags & PKT_INLINE_DROP)
        {
            alertdata.packet_action = U2_FLAG_BLOCKED;
        }

        if((p->packet_flags & PKT_REBUILT_STREAM) && stream_api)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_LOG, "man:Logging rebuilt stream data.\n");); 
            /*stream_api->traverse_reassembled(p, Unified2FirstPacketCallback, &alertdata);*/
        }

        if(IPH_IS_VALID(p))
        {
            snort_ip_p ip;
            ip = GET_SRC_IP(p);
            alertdata.ip_source = *(struct in6_addr*)ip->ip32;
            ip = GET_DST_IP(p);
            alertdata.ip_destination = *(struct in6_addr*)ip->ip32;
            alertdata.protocol = GET_IPH_PROTO(p);
            if((alertdata.protocol == IPPROTO_ICMP) && p->icmph)
            {
                alertdata.sport_itype = htons(p->icmph->type);
                alertdata.dport_icode = htons(p->icmph->code);
            }
            else
            {
                alertdata.sport_itype = htons(p->sp);
                alertdata.dport_icode = htons(p->dp);
            }
        }

        if(alertdata.protocol == 255) 
        {
             alertdata.sport_itype = 0;             
             alertdata.dport_icode = 0;             
        }   
    }
    
    if((sizeof(Unified2RecordHeader) + sizeof(Unified2Event6)) > data->limit)
    {
       Unified2RotateFile(data);
    }

    hdr.length = htonl(sizeof(Unified2Event6));
    hdr.type = htonl(UNIFIED2_IDS_EVENT_IPV6);

    SafeMemcpy(write_pkt_buffer, &hdr, sizeof(Unified2RecordHeader), 
               write_pkt_buffer, write_pkt_end);
    
    SafeMemcpy(write_pkt_buffer + sizeof(Unified2RecordHeader),
               &alertdata, sizeof(Unified2Event6), 
               write_pkt_buffer, write_pkt_end);

    if(fwrite(write_pkt_buffer, 
              sizeof(Unified2RecordHeader) +  sizeof(Unified2Event6),
               1, data->stream) != 1)
        FatalError("SpoUnified2: write failed: %s\n", strerror(errno));

    fflush(data->stream);
    data->current += sizeof(Unified2RecordHeader) + sizeof(Unified2Event6);
#endif
}

#ifdef MPLS
static void _AlertIP6_mpls(Packet *p, char *msg, void *arg, Event *event) 
{
#ifdef SUP_IP6
    Unified2RecordHeader hdr;
    Unified2Config *data = (Unified2Config *)arg;
    Unified2Event6_MPLS alertdata;
    
    bzero(&alertdata, sizeof(alertdata));

    alertdata.sensor_id = 0;
    alertdata.event_id = htonl(event->event_id);
    alertdata.event_second = htonl(event->ref_time.tv_sec);
    alertdata.event_microsecond = htonl(event->ref_time.tv_usec);
    alertdata.generator_id = htonl(event->sig_generator);
    alertdata.signature_id = htonl(event->sig_id);
    alertdata.signature_revision = htonl(event->sig_rev);
    alertdata.classification_id = htonl(event->classification);
    alertdata.priority_id = htonl(event->priority);

    if(p)
    {
        if (p->packet_flags & PKT_INLINE_DROP)
        {
            alertdata.packet_action = U2_FLAG_BLOCKED;
        }

        if((p->packet_flags & PKT_REBUILT_STREAM) && stream_api)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_LOG, "man:Logging rebuilt stream data.\n");); 
            stream_api->traverse_reassembled(p, Unified2FirstPacketCallback_mpls, &alertdata);
        }

        if(IPH_IS_VALID(p))
        {
            snort_ip_p ip;
            ip = GET_SRC_IP(p);
            alertdata.ip_source = *(struct in6_addr*)ip->ip32;
            ip = GET_DST_IP(p);
            alertdata.ip_destination = *(struct in6_addr*)ip->ip32;
            alertdata.protocol = GET_IPH_PROTO(p);
            if((alertdata.protocol == IPPROTO_ICMP) && p->icmph)
            {
                alertdata.sport_itype = htons(p->icmph->type);
                alertdata.dport_icode = htons(p->icmph->code);
            }
            else
            {
                alertdata.sport_itype = htons(p->sp);
                alertdata.dport_icode = htons(p->dp);
            }
            alertdata.mpls_label = p->mplsHdr.label;
        }

        if(alertdata.protocol == 255) 
        {
             alertdata.sport_itype = 0;             
             alertdata.dport_icode = 0;             
        }   
    }
    
    if((sizeof(Unified2RecordHeader) + sizeof(Unified2Event6_MPLS)) > data->limit)
    {
       Unified2RotateFile(data);
    }

    hdr.length = htonl(sizeof(Unified2Event6_MPLS));
    hdr.type = htonl(UNIFIED2_IDS_EVENT_IPV6_MPLS);

    SafeMemcpy(write_pkt_buffer_mpls, &hdr, sizeof(Unified2RecordHeader), 
               write_pkt_buffer_mpls, write_pkt_end_mpls);
    
    SafeMemcpy(write_pkt_buffer_mpls + sizeof(Unified2RecordHeader),
               &alertdata, sizeof(Unified2Event6_MPLS), 
               write_pkt_buffer_mpls, write_pkt_end_mpls);

    if(fwrite(write_pkt_buffer_mpls, 
              sizeof(Unified2RecordHeader) +  sizeof(Unified2Event6_MPLS),
               1, data->stream) != 1)
        FatalError("SpoUnified2: write failed: %s\n", strerror(errno));

    fflush(data->stream);
    data->current += sizeof(Unified2RecordHeader) + sizeof(Unified2Event6_MPLS);
#endif
}
#endif

void Unified2LogAlert(Packet *p, char *msg, void *arg, Event *event)
{
    if(!event) return;
#ifdef MPLS
    if(IS_IP4(p))
    {
        if((p->mpls) && (unifiedConfig->mpls_event_types))
            _AlertIP4_mpls(p, msg, arg, event); 
        else 
            _AlertIP4(p, msg, arg, event);
    } 
    else 
    {
        if((p->mpls) && (unifiedConfig->mpls_event_types))
            _AlertIP6_mpls(p, msg, arg, event); 
        else 
            _AlertIP6(p, msg, arg, event);
    }
    return;
#else
    if(IS_IP4(p)) _AlertIP4(p, msg, arg, event);
    else _AlertIP6(p, msg, arg, event);
#endif
}

static void Unified2LogPacketAlert(Packet *p, char *msg, void *arg, Event *event)
{
    if(p) 
    {
        if( p->packet_flags & PKT_REBUILT_STREAM)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_LOG, 
                        "[*] Reassembled packet, dumping stream packets\n"););
            _Unified2LogStreamAlert(p, msg, arg, event);
        }
        else 
        {
            DEBUG_WRAP(DebugMessage(DEBUG_LOG, "[*] Logging unified 2 packets...\n"););
            _Unified2LogPacketAlert(p, msg, arg, event);
        }
   }
}

static void _Unified2LogPacketAlert(Packet *p, char *msg, 
                void *arg, Event *event)
{ 
    Unified2RecordHeader hdr;
    Unified2Packet logheader;
    Unified2Config *data = (Unified2Config *)arg;
    uint32_t pkt_length; 

    if(event != NULL)
    {
        logheader.sensor_id = 0;
        logheader.event_id = htonl(event->event_reference);
        logheader.event_second = htonl(event->ref_time.tv_sec);
        logheader.linktype = htonl(datalink);

        DEBUG_WRAP(DebugMessage(DEBUG_LOG, "------------\n"));
    }

    if(p && p->pkt && p->pkth)
    {
        logheader.packet_second = htonl((u_int32_t)p->pkth->ts.tv_sec);
        logheader.packet_microsecond = htonl((u_int32_t)p->pkth->ts.tv_usec);
        pkt_length = p->pkth->caplen;
        logheader.packet_length = htonl(pkt_length);
    }
    else
    {
        logheader.packet_second = 0;
        logheader.packet_microsecond = 0;
        logheader.packet_length = 0;
        pkt_length = 0;
    }

    if((data->current + sizeof(Unified2Packet) + 
                sizeof(Unified2RecordHeader) +
                pkt_length - 4) > data->limit)
    {
       Unified2RotateFile(data);
    }

    hdr.length = htonl(sizeof(Unified2Packet) - 4 + pkt_length);
    hdr.type = htonl(UNIFIED2_PACKET);

    SafeMemcpy(write_pkt_buffer, &hdr, sizeof(Unified2RecordHeader), 
               write_pkt_buffer, write_pkt_end);
    
    SafeMemcpy(write_pkt_buffer + sizeof(Unified2RecordHeader),
               &logheader, sizeof(Unified2Packet) - 4, 
               write_pkt_buffer, write_pkt_end);

    if(p && p->pkt && p->pkth)
    {
        SafeMemcpy(write_pkt_buffer + sizeof(Unified2RecordHeader) +
               sizeof(Unified2Packet) - 4,
               p->pkt, p->pkth->caplen, 
               write_pkt_buffer, write_pkt_end);
            
        if(fwrite(write_pkt_buffer, 
           sizeof(Unified2RecordHeader) + sizeof(Unified2Packet)-4 + p->pkth->caplen,
           1, data->stream) != 1)
            FatalError("SpoUnified2: write failed: %s\n", strerror(errno));
        
        data->current += p->pkth->caplen;
    }
    else
    {
        if(fwrite(write_pkt_buffer, 
           sizeof(Unified2RecordHeader) + sizeof(Unified2Packet) - 4,
           1, data->stream) != 1)
            FatalError("SpoUnified2: write failed: %s\n", strerror(errno));
    }

    data->current += sizeof(Unified2RecordHeader) +
                            sizeof(Unified2Packet);

    fflush(data->stream);
}

typedef struct _Unified2LogStreamCallbackData
{
    Unified2Packet *logheader;
    Unified2Config *data;
    Event *event;
    int once;
} Unified2LogStreamCallbackData;

/**
 * Callback for the Stream reassembler to log packets
 *
 */
int Unified2LogStreamCallback(struct pcap_pkthdr *pkth,
                              u_int8_t *packet_data, void *userdata)
{
    Unified2LogStreamCallbackData *unifiedData;
    Unified2RecordHeader hdr;

    if (!userdata || !pkth || !packet_data)
        return -1;

    unifiedData = (Unified2LogStreamCallbackData *)userdata;

    if((unifiedData->data->current +
        sizeof(Unified2Packet) + sizeof(Unified2RecordHeader) +
        pkth->caplen - 4) > unifiedData->data->limit)
    {
       Unified2RotateFile(unifiedData->data);
    }

    hdr.type = htonl(UNIFIED2_PACKET);
    hdr.length = htonl(sizeof(Unified2Packet) - 4 + pkth->caplen);
            
    unifiedData->logheader->event_id = htonl(unifiedData->event->event_reference);
    unifiedData->logheader->event_second = htonl(unifiedData->event->ref_time.tv_sec);
    unifiedData->logheader->packet_second = htonl((u_int32_t)pkth->ts.tv_sec);
    unifiedData->logheader->packet_microsecond = htonl((u_int32_t)pkth->ts.tv_usec);
    unifiedData->logheader->packet_length = htonl(pkth->caplen);

    SafeMemcpy(write_pkt_buffer, &hdr, sizeof(Unified2RecordHeader),
               write_pkt_buffer, write_pkt_end);

    SafeMemcpy(write_pkt_buffer + sizeof(Unified2RecordHeader), 
               unifiedData->logheader, sizeof(Unified2Packet) - 4,
               write_pkt_buffer, write_pkt_end);

    SafeMemcpy(write_pkt_buffer + 
                sizeof(Unified2RecordHeader) + sizeof(Unified2Packet) - 4, 
               packet_data, pkth->caplen,
               write_pkt_buffer, write_pkt_end);

    //if(fwrite(write_pkt_buffer, pkth->caplen, 1, 
    if(fwrite(write_pkt_buffer, sizeof(Unified2RecordHeader) + sizeof(Unified2Packet) - 4 + pkth->caplen, 1, 
               unifiedData->data->stream) != 1)
    {
         FatalError("SpoUnified2: write failed: %s\n", strerror(errno));
    }

    unifiedData->data->current += ntohl(hdr.length);

#if 0 
    /* DO NOT DO THIS FOR UNIFIED2.
     * The event referenced below in the unifiedData is a pointer
     * to the actual event and this changes its gid & sid to 2:1.
     * That is baaaaad.
     */
    /* after the first logged packet modify the event headers */
    if(!unifiedData->once++)
    {
        unifiedData->event->sig_generator = GENERATOR_TAG;
        unifiedData->event->sig_id = TAG_LOG_PKT;
        unifiedData->event->sig_rev = 1;
        unifiedData->event->classification = 0;
        unifiedData->event->priority = unifiedData->event->priority;
        /* Note that event_id is now incorrect. 
         * See OldUnified2LogPacketAlert() for details. */
    }
#endif

    return 0;
}


/**
 * Log a set of packets stored in the stream reassembler
 *
 */
static void _Unified2LogStreamAlert(Packet *p, char *msg, void *arg, Event *event)
{
    Unified2LogStreamCallbackData unifiedData;
    Unified2Packet logheader;
    Unified2Config *data = (Unified2Config *)arg;
    int once = 0;

    /* setup the event header */
    if(event != NULL)
    {
        logheader.sensor_id = 0;
        logheader.event_id = htonl(event->event_reference);
        logheader.event_second = htonl(event->ref_time.tv_sec);
        logheader.linktype = htonl(datalink);
    }

    /* queue up the stream for logging */
    if(p && stream_api)
    {
        unifiedData.logheader = &logheader;
        unifiedData.data = data;
        unifiedData.event = event;
        unifiedData.once = once;
        stream_api->traverse_reassembled(p, Unified2LogStreamCallback, &unifiedData);
    }
    
    fflush(data->stream);
}

/*
 * Function: Unified2ParseArgs(char *)
 *
 * Purpose: Process the preprocessor arguements from the rules file and 
 *          initialize the preprocessor's data struct.  This function doesn't
 *          have to exist if it makes sense to parse the args in the init 
 *          function.
 *
 * Arguments: args => argument list
 *
 * Returns: void function
 *
 */
Unified2Config *Unified2ParseArgs(char *args, char *default_filename)
{
    Unified2Config *tmp;
    int limit = 0;

    tmp = (Unified2Config *)calloc(sizeof(Unified2Config), sizeof(char));

    if(tmp == NULL)
    {
        FatalError("Unable to allocate Unified2 Data struct!\n");
    }

    /* This is so the if 'nostamps' option is used on the command line,
     * it will be honored by unified2, and only one variable is used. */
    tmp->nostamp = pv.nostamp;

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Args: %s\n", args););

    if(args != NULL)
    {
        char **toks, *end;
        int num_toks;
        int i = 0;
        toks = mSplit((char *)args, ",", 31, &num_toks, '\\');
        for(i = 0; i < num_toks; ++i)
        {
            char **stoks;
            int num_stoks;
            char *index = toks[i];
            while(isspace((int)*index))
                ++index;
          
            stoks = mSplit(index, " ", 2, &num_stoks, 0);
            
            if(strcasecmp("filename", stoks[0]) == 0)
            {
                if(num_stoks > 1 && tmp->filename == NULL)
                    tmp->filename = strdup(stoks[1]);
                else
                    FatalError("Argument Error in %s(%i): %s\n",
                            file_name, file_line, index);
            }
            else if(strcasecmp("limit", stoks[0]) == 0)
            {
                if(num_stoks > 1 && limit == 0) 
                {
                    limit = strtol(stoks[1], &end, 10);

                    if(stoks[1] == end)
                        FatalError("Argument Error in %s(%i): %s\n",
                            file_name, file_line, index);
                }
                else
                    FatalError("Argument Error in %s(%i): %s\n",
                            file_name, file_line, index);
            }
            else if(strcasecmp("nostamp", stoks[0]) == 0)
            {
                tmp->nostamp = 1;
            }
#ifdef MPLS
            else if(strcasecmp("mpls_event_types", stoks[0]) == 0)
            {
                tmp->mpls_event_types = 1;
            }
#endif
            else
            {
                FatalError("Argument Error in %s(%i): %s\n",
                        file_name, file_line, index);
            }

            mSplitFree(&stoks, num_stoks);
        }
        mSplitFree(&toks, num_toks);
    }

    if(tmp->filename == NULL)
        tmp->filename = strdup(default_filename);
    
    //LogMessage("limit == %i\n", limit);

    if(limit <= 0)
    {
        limit = 128;
    }
    if(limit > 512)
    {
        LogMessage("spo_unified %s(%d)=> Lowering limit of %iMB to 512MB\n", 
            file_name, file_line, limit);
        limit = 512;
    }

    /* convert the limit to "MB" */
    tmp->limit = limit << 20;

    return tmp;
}

/*
 * Function: Unified2CleanExitFunc()
 *
 * Purpose: Cleanup at exit time
 *
 * Arguments: signal => signal that caused this event
 *            arg => data ptr to reference this plugin's data
 *
 * Returns: void function
 */
static void Unified2CleanExit(int signal, void *arg)
{
    /* cast the arg pointer to the proper type */
    Unified2Config *data = (Unified2Config *)arg;

    DEBUG_WRAP(DebugMessage(DEBUG_FLOW, "SpoUnified2: CleanExit\n"););

    fclose(data->stream);

    /* free up initialized memory */
    free(data->filename);
    free(data);
}

/*
 * Function: Restart()
 *
 * Purpose: For restarts (SIGHUP usually) clean up structs that need it
 *
 * Arguments: signal => signal that caused this event
 *            arg => data ptr to reference this plugin's data
 *
 * Returns: void function
 */
static void Unified2Restart(int signal, void *arg)
{
    Unified2Config *data = (Unified2Config *)arg;

    DEBUG_WRAP(DebugMessage(DEBUG_FLOW, "SpoUnified2: Restart\n"););

    fclose(data->stream);
    free(data->filename);
    free(data);
}

/* Unified2 Alert functions (deprecated) */
void Unified2AlertInit(char *args)
{
    Unified2Config *data;

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Output: Unified2 Alert Initialized\n"););

    pv.alert_plugin_active = 1;

    /* parse the argument list from the rules file */
    data = Unified2ParseArgs(args, "snort-unified.alert");

    Unified2InitFile(data);

    /* Set the preprocessor function into the function list */
    AddFuncToOutputList(Unified2LogAlert, NT_OUTPUT_ALERT, data);
    AddFuncToCleanExitList(Unified2CleanExit, data);
    AddFuncToRestartList(Unified2Restart, data);
}

/* Unified2 Packet Log functions (deprecated) */
void Unified2LogInit(char *args)
{
    Unified2Config *Unified2Info;

    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Output: Unified2 Log Initialized\n"););

    /* tell command line loggers to go away */
    pv.log_plugin_active = 1;

    /* parse the argument list from the rules file */
    Unified2Info = Unified2ParseArgs(args, "snort-unified.log");

    //LogMessage("Unified2LogFilename = %s\n", Unified2Info->filename);

    Unified2InitFile(Unified2Info);

    pv.log_bitmap |= LOG_UNIFIED2;

    /* Set the preprocessor function into the function list */
    AddFuncToOutputList(Unified2LogPacketAlert, NT_OUTPUT_LOG, Unified2Info);
    AddFuncToCleanExitList(Unified2CleanExit, Unified2Info);
    AddFuncToRestartList(Unified2Restart, Unified2Info);
}

