/* $Id$ */
/*
 * sp_dynamic.c
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
 * Copyright (C) 2005-2008 Sourcefire Inc.
 *
 * Author: Steven Sturges
 *
 * Purpose:
 *      Supports dynamically loaded detection plugin to check the packet.
 *
 *      does not update the doe_ptr
 *
 * Arguments:
 *      Required:
 *        None
 *      Optional:
 *        None
 *
 *   sample rules:
 *   alert tcp any any -> any any (msg: "DynamicRuleCheck"; );
 *
 * Effect:
 *
 *      Returns 1 if the dynamic detection plugin matches, 0 if it doesn't.
 *
 * Comments:
 *
 *
 */
#ifdef DYNAMIC_PLUGIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <errno.h>

#include "rules.h"
#include "decode.h"
#include "bitop_funcs.h"
#include "plugbase.h"
#include "parser.h"
#include "debug.h"
#include "util.h"
#include "plugin_enum.h"
#include "sp_dynamic.h"
#include "sf_dynamic_engine.h"
#include "detection-plugins/sp_flowbits.h"
#include "detection-plugins/sp_asn1_detect.h"
#include "dynamic-plugins/sf_engine/sf_snort_plugin_api.h"
#include "sfhashfcn.h"

#include "snort.h"
#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats dynamicRuleEvalPerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif

void DynamicInit(char *, OptTreeNode *, int);
void DynamicParse(char *, OptTreeNode *);
#ifdef DETECTION_OPTION_TREE
int DynamicCheck(void *option_data, Packet *p);
#else
int DynamicCheck(Packet *, struct _OptTreeNode *, OptFpList *);
#endif

#ifdef DETECTION_OPTION_TREE
u_int32_t DynamicRuleHash(void *d)
{
    u_int32_t a,b,c;
    DynamicData *dynData = (DynamicData *)d;
#if (defined(__ia64) || defined(__amd64) || defined(_LP64))
    {
        /* Cleanup warning because of cast from 64bit ptr to 32bit int
         * warning on 64bit OSs */
        UINT64 ptr; /* Addresses are 64bits */
        ptr = (UINT64)dynData->contextData;
        a = (ptr << 32) & 0XFFFFFFFF;
        b = (ptr & 0xFFFFFFFF);
        
        ptr = (UINT64)dynData->checkFunction;
        c = (ptr << 32) & 0XFFFFFFFF;
        
        mix (a,b,c);
        
        a += (ptr & 0xFFFFFFFF);

        ptr = (UINT64)dynData->hasOptionFunction;
        b += (ptr << 32) & 0XFFFFFFFF;
        c += (ptr & 0xFFFFFFFF);

        ptr = (UINT64)dynData->fastPatternContents;
        a += (ptr << 32) & 0XFFFFFFFF;
        b += (ptr & 0xFFFFFFFF);
        c += dynData->fpContentFlags;

        mix (a,b,c);
    
        a += RULE_OPTION_TYPE_DYNAMIC;
    }
#else
    {
        a = (u_int32_t)dynData->contextData;
        b = (u_int32_t)dynData->checkFunction;
        c = (u_int32_t)dynData->hasOptionFunction;
        mix(a,b,c);

        a += (u_int32_t)dynData->fastPatternContents;
        b += dynData->fpContentFlags;
        c += RULE_OPTION_TYPE_DYNAMIC;
    }
#endif

    final(a,b,c);

    return c;
}

int DynamicRuleCompare(void *l, void *r)
{
    DynamicData *left = (DynamicData *)l;
    DynamicData *right = (DynamicData *)r;

    if (!left || !right)
        return DETECTION_OPTION_NOT_EQUAL;

    if ((left->contextData == right->contextData) &&
        (left->checkFunction == right->checkFunction) &&
        (left->hasOptionFunction == right->hasOptionFunction) &&
        (left->fastPatternContents == right->fastPatternContents) &&
        (left->fpContentFlags == right->fpContentFlags))
    {
        return DETECTION_OPTION_EQUAL;
    }

    return DETECTION_OPTION_NOT_EQUAL;
}
#endif

/****************************************************************************
 * 
 * Function: SetupDynamic()
 *
 * Purpose: Load it up
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetupDynamic(void)
{
    /* map the keyword to an initialization/processing function */
    RegisterPlugin("dynamic", DynamicInit, OPT_TYPE_DETECTION);

#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("dynamic_rule", &dynamicRuleEvalPerfStats, 3, &ruleOTNEvalPerfStats);
#endif
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Plugin: Dynamic Setup\n"););
}


/****************************************************************************
 * 
 * Function: DynamicInit(char *, OptTreeNode *)
 *
 * Purpose: Configuration function.  Handles parsing the rule 
 *          information and attaching the associated detection function to
 *          the OTN.
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *            protocol => protocol the rule is on (we don't care in this case)
 *
 * Returns: void function
 *
 ****************************************************************************/
void DynamicInit(char *data, OptTreeNode *otn, int protocol)
{
    OptFpList *fpl;
    DynamicData *dynData;
#ifdef DETECTION_OPTION_TREE
    void *option_dup;
#endif

    dynData = (DynamicData *)otn->ds_list[PLUGIN_DYNAMIC];

    fpl = AddOptFuncToList(DynamicCheck, otn);

    /* attach it to the context node so that we can call each instance
     * individually
     */
    fpl->context = (void *) dynData;

#ifdef DETECTION_OPTION_TREE
    if (add_detection_option(RULE_OPTION_TYPE_DYNAMIC, (void *)dynData, &option_dup) == DETECTION_OPTION_EQUAL)
    {
        free(dynData);
        fpl->context = dynData = option_dup;
    }
    fpl->type = RULE_OPTION_TYPE_DYNAMIC;
#endif
}

/****************************************************************************
 * 
 * Function: DynamicCheck(char *, OptTreeNode *, OptFpList *)
 *
 * Purpose: Use this function to perform the particular detection routine
 *          that this rule keyword is supposed to encompass.
 *
 * Arguments: p => pointer to the decoded packet
 *            otn => pointer to the current rule's OTN
 *            fp_list => pointer to the function pointer list
 *
 * Returns: If the detection test fails, this function *must* return a zero!
 *          On success, it calls the next function in the detection list 
 *
 ****************************************************************************/
#ifdef DETECTION_OPTION_TREE
int DynamicCheck(void *option_data, Packet *p)
{
    DynamicData *dynData = (DynamicData *)option_data;
    int result = 0;
    PROFILE_VARS;

    PREPROC_PROFILE_START(dynamicRuleEvalPerfStats);

    if (!dynData)
    {
        LogMessage("Dynamic Rule with no context data available");
        PREPROC_PROFILE_END(dynamicRuleEvalPerfStats);
        return DETECTION_OPTION_NO_MATCH;
    }

    result = dynData->checkFunction((void *)p, dynData->contextData);
    if (result)
    {
        PREPROC_PROFILE_END(dynamicRuleEvalPerfStats);
        return DETECTION_OPTION_MATCH;
    }

    /* Detection failed */
    PREPROC_PROFILE_END(dynamicRuleEvalPerfStats);
    return DETECTION_OPTION_NO_MATCH;
}
#else
int DynamicCheck(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    DynamicData *dynData;
    int result = 0;
    PROFILE_VARS;

    PREPROC_PROFILE_START(dynamicRuleEvalPerfStats);

    dynData = (DynamicData *)otn->ds_list[PLUGIN_DYNAMIC];
    if (!dynData)
    {
        LogMessage("Dynamic Rule with no context data available");
        PREPROC_PROFILE_END(dynamicRuleEvalPerfStats);
        return 0;
    }

    result = dynData->checkFunction((void *)p, dynData->contextData);
    if (result)
    {
        PREPROC_PROFILE_END(dynamicRuleEvalPerfStats);
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }

    /* Detection failed */
    PREPROC_PROFILE_END(dynamicRuleEvalPerfStats);
    return 0;
}
#endif

/****************************************************************************
 * 
 * Function: RegisterDynamicRule(u_int32_t, u_int32_t, char *, void *,
 *                               OTNCheckFunction, int, GetFPContentFunction)
 *
 * Purpose: A dynamically loaded detection engine library can use this
 *          function to register a dynamically loaded rule/preprocessor.  It
 *          provides a pointer to context specific data for the
 *          rule/preprocessor and a reference to the function used to
 *          check the rule.
 *
 * Arguments: sid => Signature ID
 *            gid => Generator ID  
 *            info => context specific data
 *            chkFunc => Function to call to check if the rule matches
 *            has*Funcs => Functions used to categorize this rule
 *            fpContentFlags => Flags indicating which Fast Pattern Contents
 *                              are available
 *            fpFunc => Function to call to get list of fast pattern contents
 *
 * Returns: 0 on success
 *
 ****************************************************************************/
int RegisterDynamicRule(
    u_int32_t sid, u_int32_t gid, void *info,
    OTNCheckFunction chkFunc, OTNHasFunction hasFunc,
    int fpContentFlags, GetFPContentFunction fpFunc
)
{
    DynamicData *dynData;
    struct _OptTreeNode *otn = NULL;
    OptFpList *idx;     /* index pointer */
    OptFpList *prev = NULL;
    OptFpList *fpl;
#ifdef DETECTION_OPTION_TREE
    char done_once = 0;
    void *option_dup;
#endif

    /* Get OTN/RTN from SID */
    otn = soid_sg_otn_lookup(gid, sid);
    if (!otn)
    {
        if(pv.conf_error_out)
        {
            FatalError("DynamicPlugin: Rule [%u:%u] not enabled in configuration.\n", gid, sid);
        }
        else
        {
#ifndef SOURCEFIRE 
            LogMessage("DynamicPlugin: Rule [%u:%u] not enabled in configuration, rule will not be used.\n", gid, sid);
#endif
        }
        return -1;
    }

    /* allocate the data structure and attach it to the
     * rule's data struct list */
    dynData = (DynamicData *) SnortAlloc(sizeof(DynamicData));

    if(dynData == NULL)
    {
        FatalError("DynamicPlugin: Unable to allocate Dynamic data node for rule [%u:%u]\n",
                    gid, sid);
    }

    dynData->contextData = info;
    dynData->checkFunction = chkFunc;
    dynData->hasOptionFunction = hasFunc;
    dynData->fastPatternContents = fpFunc;
    dynData->fpContentFlags = fpContentFlags;

    while (otn)
    {
        otn->ds_list[PLUGIN_DYNAMIC] = (void *)dynData;

        /* And add this function into the tail of the list */
        fpl = AddOptFuncToList(DynamicCheck, otn);
        fpl->context = dynData;
#ifdef DETECTION_OPTION_TREE
        if (done_once == 0)
        {
            if (add_detection_option(RULE_OPTION_TYPE_DYNAMIC, (void *)dynData, &option_dup) == DETECTION_OPTION_EQUAL)
            {
                free(dynData);
                fpl->context = dynData = option_dup;
            }
            fpl->type = RULE_OPTION_TYPE_DYNAMIC;
            done_once = 1;
        }
#endif

        /* Arrgh.  Because we read this rule in earlier, there is
         * already an OptListEnd node there.  Need to mvoe this new
         * one to just before it.
         */
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Adding new rule to list\n"););

        /* set the index pointer to the start of this OTN's function list */
        idx = otn->opt_func;

        /* if there are no nodes on the function list... */
        while(idx != NULL)
        {
            if (idx->next == fpl) /* The last one in the list before us */
            {
                if (prev)
                {
                    prev->next = fpl;
                    fpl->next = idx;
                    idx->next = NULL;
                }
                else /* idx is the head of the list */
                {
                    otn->opt_func = fpl;
                    fpl->next = idx;
                    idx->next = NULL;
                }
            }
            prev = idx;
            idx = idx->next;
        }

        otn = soid_sg_otn_lookup_next(gid, sid);
    }
    return 0;
}

extern SFGHASH *flowbits_hash;
extern u_int32_t flowbits_count;
u_int32_t DynamicFlowbitRegister(char *name, int op)
{
    u_int32_t retFlowId; /* ID */
    int hashRet;
    FLOWBITS_OBJECT *flowbits_item = sfghash_find(flowbits_hash, name);

    if (flowbits_item)
    {
        flowbits_item->types |= op;
        retFlowId = flowbits_item->id;
    }
    else
    {
        flowbits_item = (FLOWBITS_OBJECT *)SnortAlloc(sizeof(FLOWBITS_OBJECT));

        flowbits_item->id = flowbits_count;
        flowbits_item->types |= op;

        hashRet = sfghash_add(flowbits_hash, name, flowbits_item);
        if (hashRet)
        {
            FatalError("DynamicPlugin: Unable to add flowbits key (%s) to hash", name);
        }
            
        retFlowId = flowbits_item->id;
        flowbits_count++;

        if(flowbits_count >= (giFlowbitSize<<3) )
        {
            FatalError("FLOWBITS ERROR: The number of flowbit IDs in the "
                       "current ruleset (%d) exceed the maximum number of IDs "
                       "that are allowed (%d).\n", flowbits_count,giFlowbitSize<<3);
        }
    }
    return retFlowId;
}

int DynamicFlowbitCheck(void *pkt, int op, u_int32_t id)
{
    StreamFlowData *flowdata;
    Packet *p = (Packet *)pkt;
    int result = 0;

    flowdata = GetFlowbitsData(p);
    if (!flowdata)
    {
        return 0;
    }

    switch(op)
    {
        case FLOWBITS_SET:
            boSetBit(&(flowdata->boFlowbits), id);
            result = 1;
            break;

        case FLOWBITS_UNSET:
            boClearBit(&(flowdata->boFlowbits), id);
            result = 1;
            break;

        case FLOWBITS_RESET:
            boResetBITOP(&(flowdata->boFlowbits));
            result = 1;

        case FLOWBITS_ISSET:
            if (boIsBitSet(&(flowdata->boFlowbits), id))
                result = 1;
            break;

        case FLOWBITS_ISNOTSET:
            if (boIsBitSet(&(flowdata->boFlowbits), id))
                result = 0;
            else
                result = 1;
            break;

        case FLOWBITS_TOGGLE:
            if (boIsBitSet(&(flowdata->boFlowbits), id))
            {
                boClearBit(&(flowdata->boFlowbits), id);
            }
            else
            {
                boSetBit(&(flowdata->boFlowbits), id);
            }
            result = 1;
            break;
        case FLOWBITS_NOALERT:
            /* Shouldn't see this case here... But, just for
             * safety sake, return 0.
             */
            result = 0;
            break;

        default:
            /* Shouldn't see this case here... But, just for
             * safety sake, return 0.
             */
            result = 0;
            break;
    }

    return result;
}


int DynamicAsn1Detect(void *pkt, void *ctxt, const u_int8_t *cursor)
{
    Packet *p    = (Packet *) pkt;
    ASN1_CTXT *c = (ASN1_CTXT *) ctxt;   
    
    /* Call same detection function that snort calls */
    return Asn1DoDetect(p->data, p->dsize, c, cursor);
}

static inline int DynamicHasOption(
    OptTreeNode *otn, enum DynamicOptionType optionType, int flowFlag
) {
    DynamicData *dynData;
    
    dynData = (DynamicData *)otn->ds_list[PLUGIN_DYNAMIC];
    if (!dynData)
    {
        return 0;
    }

    return dynData->hasOptionFunction(dynData->contextData, optionType, flowFlag);
}

int DynamicHasFlow(OptTreeNode *otn)
{
    return DynamicHasOption(otn, OPTION_TYPE_FLOWFLAGS, 0);
}

int DynamicHasFlowbit(OptTreeNode *otn)
{
    return DynamicHasOption(otn, OPTION_TYPE_FLOWBIT, 0);
}

int DynamicHasContent(OptTreeNode *otn)
{
    return DynamicHasOption(otn, OPTION_TYPE_CONTENT, 0);
}

int DynamicHasByteTest(OptTreeNode *otn)
{
    return DynamicHasOption(otn, OPTION_TYPE_BYTE_TEST, 0);
}

int DynamicHasPCRE(OptTreeNode *otn)
{
    return DynamicHasOption(otn, OPTION_TYPE_PCRE, 0);
}

#endif /* DYNAMIC_PLUGIN */

