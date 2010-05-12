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

#include <stdlib.h>
#include <ctype.h>

#include "rules.h"
#include "decode.h"
#include "debug.h"
#include "plugbase.h"
#include "parser.h"
#include "plugin_enum.h"
#include "util.h"

#include "snort.h"
#include "profiler.h"
#ifdef PERF_PROFILING
#ifdef DETECTION_OPTION_TREE
PreprocStats ttlCheckPerfStats;
#else
PreprocStats ttlEQPerfStats;
PreprocStats ttlGTPerfStats;
PreprocStats ttlLTPerfStats;
PreprocStats ttlRangePerfStats;
#endif
extern PreprocStats ruleOTNEvalPerfStats;
#endif

#ifdef DETECTION_OPTION_TREE
#include "sfhashfcn.h"
#include "detection_options.h"
#endif /* DETECTION_OPTION_TREE */

#define TTL_CHECK_EQ 1
#define TTL_CHECK_GT 2
#define TTL_CHECK_LT 3
#define TTL_CHECK_RG 4

typedef struct _TtlCheckData
{
    int ttl;
    int h_ttl;
    char oper;
} TtlCheckData;

void TtlCheckInit(char *, OptTreeNode *, int);
void ParseTtl(char *, OptTreeNode *);
#ifdef DETECTION_OPTION_TREE
int CheckTtl(void *option_data, Packet *p);
#else
int CheckTtlEq(Packet *, struct _OptTreeNode *, OptFpList *);
int CheckTtlGT(Packet *, struct _OptTreeNode *, OptFpList *);
int CheckTtlLT(Packet *, struct _OptTreeNode *, OptFpList *);
int CheckTtlRG(Packet *, struct _OptTreeNode *, OptFpList *);
#endif

/****************************************************************************
 * 
 * Function: SetupTtlCheck()
 *
 * Purpose: Register the ttl option keyword with its setup function
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetupTtlCheck(void)
{
    /* map the keyword to an initialization/processing function */
    RegisterPlugin("ttl", TtlCheckInit, OPT_TYPE_DETECTION);
#ifdef PERF_PROFILING
#ifdef DETECTION_OPTION_TREE
    RegisterPreprocessorProfile("ttl_check", &ttlCheckPerfStats, 3, &ruleOTNEvalPerfStats);
#else
    RegisterPreprocessorProfile("ttl_eq", &ttlEQPerfStats, 3, &ruleOTNEvalPerfStats);
    RegisterPreprocessorProfile("ttl_gt", &ttlGTPerfStats, 3, &ruleOTNEvalPerfStats);
    RegisterPreprocessorProfile("ttl_lt", &ttlLTPerfStats, 3, &ruleOTNEvalPerfStats);
    RegisterPreprocessorProfile("ttl_range", &ttlRangePerfStats, 3, &ruleOTNEvalPerfStats);
#endif
#endif
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: TTLCheck Initialized\n"););
}

#ifdef DETECTION_OPTION_TREE
u_int32_t TtlCheckHash(void *d)
{
    u_int32_t a,b,c;
    TtlCheckData *data = (TtlCheckData *)d;

    a = data->ttl;
    b = data->h_ttl;
    c = data->oper;

    mix(a,b,c);

    a += RULE_OPTION_TYPE_TTL;

    final(a,b,c);

    return c;
}

int TtlCheckCompare(void *l, void *r)
{
    TtlCheckData *left = (TtlCheckData *)l;
    TtlCheckData *right = (TtlCheckData *)r;

    if (!left || !right)
        return DETECTION_OPTION_NOT_EQUAL;
    
    if ((left->ttl == right->ttl) &&
        (left->h_ttl == right->h_ttl) &&
        (left->oper == right->oper))
    {
        return DETECTION_OPTION_EQUAL;
    }

    return DETECTION_OPTION_NOT_EQUAL;
}
#endif /* DETECTION_OPTION_TREE */

/****************************************************************************
 * 
 * Function: TtlCheckInit(char *, OptTreeNode *)
 *
 * Purpose: Parse the ttl keyword arguments and link the detection module
 *          into the function list
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
void TtlCheckInit(char *data, OptTreeNode *otn, int protocol)
{
    /* multiple declaration check */ 
    if(otn->ds_list[PLUGIN_TTL_CHECK])
    {
        FatalError("%s(%d): Multiple IP ttl options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_TTL_CHECK] = (TtlCheckData *)
            SnortAlloc(sizeof(TtlCheckData));

    /* this is where the keyword arguments are processed and placed into the 
       rule option's data structure */
    ParseTtl(data, otn);

    /* NOTE: the AddOptFuncToList call is moved to the parsing function since
       the linking is best determined within that function */
}



/****************************************************************************
 * 
 * Function: ParseTtl(char *, OptTreeNode *)
 *
 * Purpose: Parse the TTL keyword's arguments
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
void ParseTtl(char *data, OptTreeNode *otn)
{
    OptFpList *fpl = NULL;
    TtlCheckData *ds_ptr;  /* data struct pointer */
#ifdef DETECTION_OPTION_TREE
    void *ds_ptr_dup;
#endif
    char ttlrel;

    /* set the ds pointer to make it easier to reference the option's
       particular data struct */
    ds_ptr = (TtlCheckData *)otn->ds_list[PLUGIN_TTL_CHECK];

    while(isspace((int)*data)) data++;

    ttlrel = *data;

    switch (ttlrel) {
        case '-':
            ds_ptr->h_ttl = -1; /* leading dash flag */
        case '>':
        case '<':
        case '=':
            data++;
            break;
       default:     
            ttlrel = '=';
    }
    while(isspace((int)*data)) data++;

    ds_ptr->ttl = atoi(data);

    /* skip digit */
    while(isdigit((int)*data)) data++;
    /* and spaces.. if any */ 
    while(isspace((int)*data)) data++;
    if (*data == '-')
    {
        data++;
        ttlrel = '-';
    }
    switch (ttlrel)
    {
        case '>':
#ifdef DETECTION_OPTION_TREE
            fpl = AddOptFuncToList(CheckTtl, otn);
#else
            fpl = AddOptFuncToList(CheckTtlGT, otn);
#endif
            ds_ptr->oper = TTL_CHECK_GT;
            break;
        case '<':     
#ifdef DETECTION_OPTION_TREE
            fpl = AddOptFuncToList(CheckTtl, otn);
#else
            fpl = AddOptFuncToList(CheckTtlLT, otn);
#endif
            ds_ptr->oper = TTL_CHECK_LT;
            break;
        case '=':
#ifdef DETECTION_OPTION_TREE
            fpl = AddOptFuncToList(CheckTtl, otn);
#else
            fpl = AddOptFuncToList(CheckTtlEq, otn);
#endif
            ds_ptr->oper = TTL_CHECK_EQ;
            break;
        case '-':
            while(isspace((int)*data)) data++;
            if (ds_ptr->h_ttl != -1 && atoi(data) == 0)
            {
                ds_ptr->h_ttl = 255;
            }
            else
            {
                ds_ptr->h_ttl = atoi(data);
            }
            /* sanity check.. */
            if (ds_ptr->h_ttl < ds_ptr->ttl) 
            {
                ds_ptr->h_ttl = ds_ptr->ttl;
                ds_ptr->ttl   = atoi(data);
            }
#ifdef DETECTION_OPTION_TREE
            fpl = AddOptFuncToList(CheckTtl, otn);
#else
            fpl = AddOptFuncToList(CheckTtlRG, otn);
#endif
            ds_ptr->oper = TTL_CHECK_RG;
            break;
        default:
            /* wtf? */
            /* we need at least one statement after "default" or else Visual C++ issues a warning */
            break;
    }

#ifdef DETECTION_OPTION_TREE
    if (add_detection_option(RULE_OPTION_TYPE_TTL, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
    {
        free(ds_ptr);
        ds_ptr = otn->ds_list[PLUGIN_TTL_CHECK] = ds_ptr_dup;
    }

    if (fpl)
    {
        fpl->type = RULE_OPTION_TYPE_TTL;
        fpl->context = ds_ptr;
    }
#endif /* DETECTION_OPTION_TREE */

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Set TTL check value to %c%d (%d)\n", ttlrel, ds_ptr->ttl, ds_ptr->h_ttl););

}


#ifdef DETECTION_OPTION_TREE
int CheckTtl(void *option_data, Packet *p)
{
    TtlCheckData *ttlCheckData = (TtlCheckData *)option_data;
    int rval = DETECTION_OPTION_NO_MATCH;
    PROFILE_VARS;

    if(!IPH_IS_VALID(p))
        return rval;

    PREPROC_PROFILE_START(ttlCheckPerfStats);

    switch (ttlCheckData->oper)
    {
        case TTL_CHECK_EQ:
            if (ttlCheckData->ttl == GET_IPH_TTL(p))
                rval = DETECTION_OPTION_MATCH;
#ifdef DEBUG
            else
            {
                DebugMessage(DEBUG_PLUGIN, "CheckTtlEq: Not equal to %d\n",
                    ttlCheckData->ttl);
            }
#endif
            break;
        case TTL_CHECK_GT:
            if (ttlCheckData->ttl < GET_IPH_TTL(p))
                rval = DETECTION_OPTION_MATCH;
#ifdef DEBUG
            else
            {
                DebugMessage(DEBUG_PLUGIN, "CheckTtlEq: Not greater than %d\n",
                    ttlCheckData->ttl);
            }
#endif
            break;
        case TTL_CHECK_LT:
            if (ttlCheckData->ttl > GET_IPH_TTL(p))
                rval = DETECTION_OPTION_MATCH;
#ifdef DEBUG
            else
            {
                DebugMessage(DEBUG_PLUGIN, "CheckTtlEq: Not less than %d\n",
                    ttlCheckData->ttl);
            }
#endif
            break;
         case TTL_CHECK_RG:
            if ((ttlCheckData->ttl <= GET_IPH_TTL(p)) &&
                (ttlCheckData->h_ttl >= GET_IPH_TTL(p)))
                rval = DETECTION_OPTION_MATCH;
#ifdef DEBUG
            else
            {
                DebugMessage(DEBUG_PLUGIN, "CheckTtlLT: Not Within the range %d - %d (%d)\n", 
                     ttlCheckData->ttl,
                     ttlCheckData->h_ttl,
                     GET_IPH_TTL(p));
            }
#endif
            break;
        default:
            break;
    }

    /* if the test isn't successful, return 0 */
    PREPROC_PROFILE_END(ttlCheckPerfStats);
    return rval;
}
#else
/****************************************************************************
 * 
 * Function: CheckTtlEq(char *, OptTreeNode *)
 *
 * Purpose: Test if the packet TTL equals the rule option's ttl
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns:  0 on failure, return value of next list function on success
 *
 ****************************************************************************/
int CheckTtlEq(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(ttlEQPerfStats);

    if(IPH_IS_VALID(p) &&
        ((TtlCheckData *)otn->ds_list[PLUGIN_TTL_CHECK])->ttl == GET_IPH_TTL(p))
    {
        /* call the next function in the function list recursively */
        PREPROC_PROFILE_END(ttlEQPerfStats);
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }
#ifdef DEBUG
    else
    {
        /* you can put debug comments here or not */
        DebugMessage(DEBUG_PLUGIN, "CheckTtlEq: Not equal to %d\n",
        ((TtlCheckData *)otn->ds_list[PLUGIN_TTL_CHECK])->ttl);
    }
#endif

    /* if the test isn't successful, return 0 */
    PREPROC_PROFILE_END(ttlEQPerfStats);
    return 0;
}



/****************************************************************************
 * 
 * Function: CheckTtlGT(char *, OptTreeNode *)
 *
 * Purpose: Test the packet's payload size against the rule payload size 
 *          value.  This test determines if the packet payload size is 
 *          greater than the rule ttl.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns:  0 on failure, return value of next list function on success
 *
 ****************************************************************************/
int CheckTtlGT(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(ttlGTPerfStats);

    if(IPH_IS_VALID(p) &&
         ((TtlCheckData *)otn->ds_list[PLUGIN_TTL_CHECK])->ttl < GET_IPH_TTL(p))
    {
        /* call the next function in the function list recursively */
        PREPROC_PROFILE_END(ttlGTPerfStats);
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }
#ifdef DEBUG
    else
    {
        /* you can put debug comments here or not */
        DebugMessage(DEBUG_PLUGIN, "CheckTtlGt: Not greater than %d\n",
        ((TtlCheckData *)otn->ds_list[PLUGIN_TTL_CHECK])->ttl);
    }
#endif

    /* if the test isn't successful, return 0 */
    PREPROC_PROFILE_END(ttlGTPerfStats);
    return 0;
}




/****************************************************************************
 * 
 * Function: CheckTtlLT(char *, OptTreeNode *)
 *
 * Purpose: Test the packet's payload size against the rule payload size 
 *          value.  This test determines if the packet payload size is 
 *          less than the rule ttl.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns:  0 on failure, return value of next list function on success
 *
 ****************************************************************************/
int CheckTtlLT(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(ttlLTPerfStats);

    if(IPH_IS_VALID(p) &&
         ((TtlCheckData *)otn->ds_list[PLUGIN_TTL_CHECK])->ttl > GET_IPH_TTL(p))
    {
        /* call the next function in the function list recursively */
        PREPROC_PROFILE_END(ttlLTPerfStats);
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }
#ifdef DEBUG
    else
    {
        /* you can put debug comments here or not */
        DebugMessage(DEBUG_PLUGIN, "CheckTtlLT: Not Less than %d\n",
        ((TtlCheckData *)otn->ds_list[PLUGIN_TTL_CHECK])->ttl);
    }
#endif

    /* if the test isn't successful, return 0 */
    PREPROC_PROFILE_END(ttlLTPerfStats);
    return 0;
}





/****************************************************************************
 * 
 * Function: CheckTtlRG(char *, OptTreeNode *)
 *
 * Purpose: Test the packet's payload size against the rule payload size 
 *          value.  This test determines if the packet payload size is 
 *          within the rule ttl.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns:  0 on failure, return value of next list function on success
 *
 ****************************************************************************/
int CheckTtlRG(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(ttlRangePerfStats);

    if(IPH_IS_VALID(p) &&
         ((TtlCheckData *)otn->ds_list[PLUGIN_TTL_CHECK])->ttl <= GET_IPH_TTL(p) &&
         ((TtlCheckData *)otn->ds_list[PLUGIN_TTL_CHECK])->h_ttl >= GET_IPH_TTL(p))
    {
        /* call the next function in the function list recursively */
        PREPROC_PROFILE_END(ttlRangePerfStats);
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }
#ifdef DEBUG
    else if (IPH_IS_VALID(p))
    {
        /* you can put debug comments here or not */
        DebugMessage(DEBUG_PLUGIN, "CheckTtlLT: Not Within the range %d - %d (%d)\n", 
                     ((TtlCheckData *)otn->ds_list[PLUGIN_TTL_CHECK])->ttl,
                     ((TtlCheckData *)otn->ds_list[PLUGIN_TTL_CHECK])->h_ttl,
                     GET_IPH_TTL(p));
    }
#endif

    /* if the test isn't successful, return 0 */
    PREPROC_PROFILE_END(ttlRangePerfStats);
    return 0;
}
#endif
