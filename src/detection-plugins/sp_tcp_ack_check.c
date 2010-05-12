/*
** Copyright (C) 2002-2008 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>

#include "rules.h"
#include "decode.h"
#include "plugbase.h"
#include "parser.h"
#include "debug.h"
#include "util.h"
#include "plugin_enum.h"

#include "snort.h"
#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats tcpAckPerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif

#ifdef DETECTION_OPTION_TREE
#include "sfhashfcn.h"
#include "detection_options.h"
#endif /* DETECTION_OPTION_TREE */

typedef struct _TcpAckCheckData
{
    u_long tcp_ack;
} TcpAckCheckData;

void TcpAckCheckInit(char *, OptTreeNode *, int);
void ParseTcpAck(char *, OptTreeNode *);
#ifdef DETECTION_OPTION_TREE
int CheckTcpAckEq(void *option_data, Packet *p);
#else
int CheckTcpAckEq(Packet *, struct _OptTreeNode *, OptFpList *);
#endif

#ifdef DETECTION_OPTION_TREE
u_int32_t TcpAckCheckHash(void *d)
{
    u_int32_t a,b,c;
    TcpAckCheckData *data = (TcpAckCheckData *)d;

    a = data->tcp_ack;
    b = RULE_OPTION_TYPE_TCP_ACK;
    c = 0;

    final(a,b,c);

    return c;
}

int TcpAckCheckCompare(void *l, void *r)
{
    TcpAckCheckData *left = (TcpAckCheckData *)l;
    TcpAckCheckData *right = (TcpAckCheckData *)r;

    if (!left || !right)
        return DETECTION_OPTION_NOT_EQUAL;

    if (left->tcp_ack == right->tcp_ack)
    {
        return DETECTION_OPTION_EQUAL;
    }

    return DETECTION_OPTION_NOT_EQUAL;
}
#endif /* DETECTION_OPTION_TREE */

/****************************************************************************
 * 
 * Function: SetupTcpAckCheck()
 *
 * Purpose: Link the ack keyword to the initialization function
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetupTcpAckCheck(void)
{
    /* map the keyword to an initialization/processing function */
    RegisterPlugin("ack", TcpAckCheckInit, OPT_TYPE_DETECTION);
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("ack", &tcpAckPerfStats, 3, &ruleOTNEvalPerfStats);
#endif
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: TcpAckCheck Initialized\n"););
}


/****************************************************************************
 * 
 * Function: TcpAckCheckInit(char *, OptTreeNode *)
 *
 * Purpose: Attach the option data to the rule data struct and link in the
 *          detection function to the function pointer list.
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
void TcpAckCheckInit(char *data, OptTreeNode *otn, int protocol)
{
    OptFpList *fpl;

    if(protocol != IPPROTO_TCP)
    {
        FatalError("%s(%d) TCP Options on non-TCP rule\n", file_name, file_line);
    }

    /* multiple declaration check */ 
    if(otn->ds_list[PLUGIN_TCP_ACK_CHECK])
    {
        FatalError("%s(%d): Multiple TCP ack options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_TCP_ACK_CHECK] = (TcpAckCheckData *)
            SnortAlloc(sizeof(TcpAckCheckData));

    /* this is where the keyword arguments are processed and placed into the 
       rule option's data structure */
    ParseTcpAck(data, otn);

    /* finally, attach the option's detection function to the rule's 
       detect function pointer list */
    fpl = AddOptFuncToList(CheckTcpAckEq, otn);
#ifdef DETECTION_OPTION_TREE
    fpl->type = RULE_OPTION_TYPE_TCP_ACK;
    fpl->context = otn->ds_list[PLUGIN_TCP_ACK_CHECK];
#endif
}



/****************************************************************************
 * 
 * Function: ParseTcpAck(char *, OptTreeNode *)
 *
 * Purpose: Attach the option rule's argument to the data struct.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
void ParseTcpAck(char *data, OptTreeNode *otn)
{
    TcpAckCheckData *ds_ptr;  /* data struct pointer */
#ifdef DETECTION_OPTION_TREE
    void *ds_ptr_dup;
#endif
    char **ep = NULL;

    /* set the ds pointer to make it easier to reference the option's
       particular data struct */
    ds_ptr = otn->ds_list[PLUGIN_TCP_ACK_CHECK];

    ds_ptr->tcp_ack = strtoul(data, ep, 0);
    ds_ptr->tcp_ack = htonl(ds_ptr->tcp_ack);

#ifdef DETECTION_OPTION_TREE
    if (add_detection_option(RULE_OPTION_TYPE_TCP_ACK, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
    {
        free(ds_ptr);
        ds_ptr = otn->ds_list[PLUGIN_TCP_ACK_CHECK] = ds_ptr_dup;
    }
#endif /* DETECTION_OPTION_TREE */

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Ack set to %lX\n", ds_ptr->tcp_ack););
}


/****************************************************************************
 * 
 * Function: CheckTcpAckEq(char *, OptTreeNode *)
 *
 * Purpose: Check to see if the packet's TCP ack field is equal to the rule
 *          ack value.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
#ifdef DETECTION_OPTION_TREE
int CheckTcpAckEq(void *option_data, Packet *p)
{
    TcpAckCheckData *ackCheckData = (TcpAckCheckData *)option_data;
    int rval = DETECTION_OPTION_NO_MATCH;
    PROFILE_VARS;

    if(!p->tcph)
        return rval; /* if error appeared when tcp header was processed,
               * test fails automagically */
    PREPROC_PROFILE_START(tcpAckPerfStats);

    if(ackCheckData->tcp_ack == p->tcph->th_ack)
    {
        rval = DETECTION_OPTION_MATCH;
    }
    else
    {
        /* you can put debug comments here or not */
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"No match\n"););
    }

    /* if the test isn't successful, return 0 */
    PREPROC_PROFILE_END(tcpAckPerfStats);
    return rval;
}
#else
int CheckTcpAckEq(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    PROFILE_VARS;

    if(!p->tcph)
        return 0; /* if error appeared when tcp header was processed,
               * test fails automagically */
    PREPROC_PROFILE_START(tcpAckPerfStats);

    if(((TcpAckCheckData *)otn->ds_list[PLUGIN_TCP_ACK_CHECK])->tcp_ack == p->tcph->th_ack)
    {
        /* call the next function in the function list recursively */
        PREPROC_PROFILE_END(tcpAckPerfStats);
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }
    else
    {
        /* you can put debug comments here or not */
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"No match\n"););
    }

    /* if the test isn't successful, return 0 */
    PREPROC_PROFILE_END(tcpAckPerfStats);
    return 0;
}
#endif
