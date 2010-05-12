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
/* sp_icmp_seq_check 
 * 
 * Purpose:
 *
 * Test the Sequence number field of ICMP ECHO and ECHO_REPLY packets for 
 * specified values.  This is useful for detecting TFN attacks, amongst others.
 *
 * Arguments:
 *   
 * The ICMP Seq plugin takes a number as an option argument.
 *
 * Effect:
 *
 * Tests ICMP ECHO and ECHO_REPLY packet Seq field values and returns a 
 * "positive" detection result (i.e. passthrough) upon a value match.
 *
 * Comments:
 *
 * This plugin was developed to detect TFN distributed attacks.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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
PreprocStats icmpSeqPerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif

#ifdef DETECTION_OPTION_TREE
#include "sfhashfcn.h"
#include "detection_options.h"
#endif /* DETECTION_OPTION_TREE */

typedef struct _IcmpSeqCheckData
{
    unsigned short icmpseq;

} IcmpSeqCheckData; 

void IcmpSeqCheckInit(char *, OptTreeNode *, int);
void ParseIcmpSeq(char *, OptTreeNode *);
#ifdef DETECTION_OPTION_TREE
int IcmpSeqCheck(void *option_data, Packet *p);
#else
int IcmpSeqCheck(Packet *, struct _OptTreeNode *, OptFpList *);
#endif

#ifdef DETECTION_OPTION_TREE
u_int32_t IcmpSeqCheckHash(void *d)
{
    u_int32_t a,b,c;
    IcmpSeqCheckData *data = (IcmpSeqCheckData *)d;

    a = data->icmpseq;
    b = RULE_OPTION_TYPE_ICMP_SEQ;
    c = 0;

    final(a,b,c);

    return c;
}

int IcmpSeqCheckCompare(void *l, void *r)
{
    IcmpSeqCheckData *left = (IcmpSeqCheckData *)l;
    IcmpSeqCheckData *right = (IcmpSeqCheckData *)r;

    if (!left || !right)
        return DETECTION_OPTION_NOT_EQUAL;

    if (left->icmpseq == right->icmpseq)
    {
        return DETECTION_OPTION_EQUAL;
    }

    return DETECTION_OPTION_NOT_EQUAL;
}
#endif /* DETECTION_OPTION_TREE */



/****************************************************************************
 * 
 * Function: SetupIcmpSeqCheck()
 *
 * Purpose: Registers the configuration function and links it to a rule
 *          keyword.  This is the function that gets called from InitPlugins
 *          in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetupIcmpSeqCheck(void)
{
    /* map the keyword to an initialization/processing function */
    RegisterPlugin("icmp_seq", IcmpSeqCheckInit, OPT_TYPE_DETECTION);

#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("icmp_seq", &icmpSeqPerfStats, 3, &ruleOTNEvalPerfStats);
#endif
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: IcmpSeqCheck Setup\n"););
}


/****************************************************************************
 * 
 * Function: IcmpSeqCheckInit(char *, OptTreeNode *)
 *
 * Purpose: Handles parsing the rule information and attaching the associated
 *          detection function to the OTN.
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
void IcmpSeqCheckInit(char *data, OptTreeNode *otn, int protocol)
{
    OptFpList *fpl;
    if(protocol != IPPROTO_ICMP)
    {
        FatalError("%s(%d): ICMP Options on non-ICMP rule\n", file_name, file_line);
    }

    /* multiple declaration check */ 
    if(otn->ds_list[PLUGIN_ICMP_SEQ_CHECK])
    {
        FatalError("%s(%d): Multiple ICMP seq options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_ICMP_SEQ_CHECK] = (IcmpSeqCheckData *)
        SnortAlloc(sizeof(IcmpSeqCheckData));

    /* this is where the keyword arguments are processed and placed into the 
       rule option's data structure */
    ParseIcmpSeq(data, otn);

    /* finally, attach the option's detection function to the rule's 
       detect function pointer list */
    fpl = AddOptFuncToList(IcmpSeqCheck, otn);
#ifdef DETECTION_OPTION_TREE
    fpl->type = RULE_OPTION_TYPE_ICMP_SEQ;
    fpl->context = otn->ds_list[PLUGIN_ICMP_SEQ_CHECK];
#endif
}



/****************************************************************************
 * 
 * Function: ParseIcmpSeq(char *, OptTreeNode *)
 *
 * Purpose: Convert the rule option argument to program data.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
void ParseIcmpSeq(char *data, OptTreeNode *otn)
{
    IcmpSeqCheckData *ds_ptr;  /* data struct pointer */
#ifdef DETECTION_OPTION_TREE
    void *ds_ptr_dup;
#endif

    /* set the ds pointer to make it easier to reference the option's
       particular data struct */
    ds_ptr = otn->ds_list[PLUGIN_ICMP_SEQ_CHECK];

    /* advance past whitespace */
    while(isspace((int)*data)) data++;

    ds_ptr->icmpseq = atoi(data);
    ds_ptr->icmpseq = htons(ds_ptr->icmpseq);
    
#ifdef DETECTION_OPTION_TREE
    if (add_detection_option(RULE_OPTION_TYPE_ICMP_SEQ, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
    {
        free(ds_ptr);
        ds_ptr = otn->ds_list[PLUGIN_ICMP_SEQ_CHECK] = ds_ptr_dup;
    }
#endif /* DETECTION_OPTION_TREE */

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Set ICMP Seq test value to %d\n", ds_ptr->icmpseq););
}


/****************************************************************************
 * 
 * Function: IcmpSeqCheck(char *, OptTreeNode *)
 *
 * Purpose: Compare the ICMP Sequence field to the rule value.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: If the detection test fails, this function *must* return a zero!
 *          On success, it calls the next function in the detection list 
 *
 ****************************************************************************/
#ifdef DETECTION_OPTION_TREE
int IcmpSeqCheck(void *option_data, Packet *p)
{
    IcmpSeqCheckData *icmpSeq = (IcmpSeqCheckData *)option_data;
    PROFILE_VARS;

    if(!p->icmph)
        return DETECTION_OPTION_NO_MATCH; /* if error occured while icmp header
                   * was processed, return 0 automagically.  */

    PREPROC_PROFILE_START(icmpSeqPerfStats);

    if( (p->icmph->type == ICMP_ECHO || p->icmph->type == ICMP_ECHOREPLY) 
#ifdef SUP_IP6
        || (p->icmph->type == ICMP6_ECHO || p->icmph->type == ICMP6_REPLY) 
#endif
      ) 
    {
        /* test the rule ID value against the ICMP extension ID field */
        if(icmpSeq->icmpseq == p->icmph->s_icmp_seq)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "ICMP ID check success\n"););
            PREPROC_PROFILE_END(icmpSeqPerfStats);
            return DETECTION_OPTION_MATCH;
        }
        else
        {
            /* you can put debug comments here or not */
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "ICMP ID check failed\n"););
        }
    }
    PREPROC_PROFILE_END(icmpSeqPerfStats);
    return DETECTION_OPTION_NO_MATCH;
}
#else
int IcmpSeqCheck(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    PROFILE_VARS;

    if(!p->icmph)
        return 0; /* if error occured while icmp header
                   * was processed, return 0 automagically.  */

    PREPROC_PROFILE_START(icmpSeqPerfStats);

    if( (p->icmph->type == ICMP_ECHO || p->icmph->type == ICMP_ECHOREPLY) 
#ifdef SUP_IP6
        || (p->icmph->type == ICMP6_ECHO || p->icmph->type == ICMP6_REPLY) 
#endif
        )
    {
        /* test the rule ID value against the ICMP extension ID field */
        if(((IcmpSeqCheckData *) otn->ds_list[PLUGIN_ICMP_SEQ_CHECK])->icmpseq == 
           p->icmph->s_icmp_seq)
        {
            /* call the next function in the function list recursively */
            PREPROC_PROFILE_END(icmpSeqPerfStats);
            return fp_list->next->OptTestFunc(p, otn, fp_list->next);
        }
        else
        {
            /* you can put debug comments here or not */
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"ICMP Seq check failed\n"););
        }
    }

    /* if the test isn't successful, this function *must* return 0 */
    PREPROC_PROFILE_END(icmpSeqPerfStats);
    return 0;
}
#endif
