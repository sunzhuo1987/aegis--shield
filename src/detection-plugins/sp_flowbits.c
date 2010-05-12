/*
** $Id$
**
** sp_flowbits
** 
** Purpose:
**
** Wouldn't it be nice if we could do some simple state tracking 
** across multiple packets?  Well, this allows you to do just that.
**
** Effect:
**
** - [Un]set a bitmask stored with the session
** - Check the value of the bitmask
**
** Copyright (C) 2003-2008 Sourcefire, Inc.
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

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>

#include "rules.h"
#include "decode.h"
#include "plugbase.h"
#include "parser.h"
#include "debug.h"
#include "util.h"
#include "plugin_enum.h"
#include "snort.h"
#include "bitop_funcs.h"
#include "sfghash.h"
#include "spp_flow.h"
#include "sp_flowbits.h"

#include "stream_api.h"

#include "snort.h"
#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats flowBitsPerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif

#ifdef DETECTION_OPTION_TREE
#include "sfhashfcn.h"
#include "detection_options.h"
#endif /* DETECTION_OPTION_TREE */

/**
**  This structure is the context ptr for each detection option
**  on a rule.  The id is associated with a FLOWBITS_OBJECT id.
**
**  The type element track only one operation.
*/
typedef struct _FLOWBITS_OP
{
    u_int32_t id;
    u_int8_t  type;        /* Set, Unset, Invert, IsSet, IsNotSet, Reset  */
    char *name;
} FLOWBITS_OP;

extern unsigned int giFlowbitSize;

u_int32_t flowbits_count = 0;
SFGHASH *flowbits_hash=NULL;

static void FlowBitsInit(char *, OptTreeNode *, int);
static void FlowBitsParse(char *, FLOWBITS_OP *, OptTreeNode *);
#ifdef DETECTION_OPTION_TREE
static int  FlowBitsCheck(void *option_data, Packet *p);
#else
static int  FlowBitsCheck(Packet *, struct _OptTreeNode *, OptFpList *);
#endif

#ifdef DETECTION_OPTION_TREE
void FlowBitsFree(void *d)
{
    FLOWBITS_OP *data = (FLOWBITS_OP *)d;

    free(data->name);
    free(data);
}

u_int32_t FlowBitsHash(void *d)
{
    u_int32_t a,b,c;
    FLOWBITS_OP *data = (FLOWBITS_OP *)d;

    a = data->id;
    b = data->type;
    c = RULE_OPTION_TYPE_FLOWBIT;

    final(a,b,c);

    return c;
}

int FlowBitsCompare(void *l, void *r)
{
    FLOWBITS_OP *left = (FLOWBITS_OP *)l;
    FLOWBITS_OP *right = (FLOWBITS_OP *)r;

    if (!left || !right)
        return DETECTION_OPTION_NOT_EQUAL;
                                
    if (( left->id == right->id) &&
        ( left->type == right->type))
    {
        return DETECTION_OPTION_EQUAL;
    }

    return DETECTION_OPTION_NOT_EQUAL;
}
#endif /* DETECTION_OPTION_TREE */

void FlowBitsCleanExit(int sig, void *data)
{
    sfghash_delete(flowbits_hash);
    flowbits_hash = NULL;
    flowbits_count = 0;
}


/****************************************************************************
 * 
 * Function: SetupFlowBits()
 *
 * Purpose: Generic detection engine plugin template.  Registers the
 *          configuration function and links it to a rule keyword.  This is
 *          the function that gets called from InitPlugins in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 * 3/4/05 - man beefed up the hash table size from 100 -> 10000
 *
 ****************************************************************************/
void SetupFlowBits()
{
    /* setup our storage hash */
    flowbits_hash = sfghash_new( 10000, 0 , 0, free);
    if (!flowbits_hash) {
        FatalError("Could not setup flowbits hash\n");
    }

    /* map the keyword to an initialization/processing function */
    RegisterPlugin("flowbits", FlowBitsInit, OPT_TYPE_DETECTION);
    AddFuncToCleanExitList(FlowBitsCleanExit, NULL);
    AddFuncToRestartList(FlowBitsCleanExit, NULL);

#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("flowbits", &flowBitsPerfStats, 3, &ruleOTNEvalPerfStats);
#endif

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: FlowBits Setup\n"););
}


/****************************************************************************
 * 
 * Function: FlowBitsInit(char *, OptTreeNode *)
 *
 * Purpose: Configure the flow init option to register the appropriate checks
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
static void FlowBitsInit(char *data, OptTreeNode *otn, int protocol)
{
    FLOWBITS_OP *flowbits;
    OptFpList *fpl;
#ifdef DETECTION_OPTION_TREE
    void *idx_dup;
#endif
 
    /* Flow bits are handled by Stream5 if its enabled */
    if(!SppFlowIsRunning() &&
       (stream_api && stream_api->version != STREAM_API_VERSION5))
    {
        if(pv.conf_error_out)
        {
            FatalError("Warning: %s (%d) => flowbits without flow or Stream5. "
                "either flow or Stream5 must be enabled for this plugin.\n",
                file_name,file_line);
        }
        else
        {
            LogMessage("Warning: %s (%d) => flowbits without flow or Stream5. "
                "either flow or Stream5 must be enabled for this plugin.\n",
                file_name,file_line);
        }
    }

    flowbits = (FLOWBITS_OP *) SnortAlloc(sizeof(FLOWBITS_OP));
    if (!flowbits) {
        FatalError("%s (%d): Unable to allocate flowbits node\n", file_name,
                file_line);
    }

    /* Set the ds_list value to 1 (yes, we have flowbits for this rule) */
    otn->ds_list[PLUGIN_FLOWBIT] = (void *)1;

    FlowBitsParse(data, flowbits, otn);
#ifdef DETECTION_OPTION_TREE
    if (add_detection_option(RULE_OPTION_TYPE_FLOWBIT, (void *)flowbits, &idx_dup) == DETECTION_OPTION_EQUAL)
    {
#if 0
        LogMessage("Duplicate FlowBit:\n%d %c\n%d %c\n\n",
            flowbits->id,
            flowbits->type,
            ((FLOWBITS_OP *)idx_dup)->id,
            ((FLOWBITS_OP *)idx_dup)->type);
#endif
        free(flowbits->name);
        free(flowbits);
        flowbits = idx_dup;
     }
#endif /* DETECTION_OPTION_TREE */

    fpl = AddOptFuncToList(FlowBitsCheck, otn);
#ifdef DETECTION_OPTION_TREE
    fpl->type = RULE_OPTION_TYPE_FLOWBIT;
#endif

    /*
     * attach it to the context node so that we can call each instance 
     * individually
     */
    
    fpl->context = (void *) flowbits;
    return;
}


/****************************************************************************
 * 
 * Function: FlowBitsParse(char *, FlowBits *flowbits, OptTreeNode *)
 *
 * Purpose: parse the arguments to the flow plugin and alter the otn
 *          accordingly
 *
 * Arguments: otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
static void FlowBitsParse(char *data, FLOWBITS_OP *flowbits, OptTreeNode *otn)
{
    FLOWBITS_OBJECT *flowbits_item;
    char *token, *str, *p;
    u_int32_t id = 0;
    int hstatus;

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "flowbits parsing %s\n",data););
    
    str = SnortStrdup(data);

    p = str;

    /* nuke leading whitespace */
    while(isspace((int)*p)) p++;

    token = strtok(p, ", \t");
    if(!token || !strlen(token))
    {
        FatalError("%s(%d) ParseFlowArgs: Must specify flowbits operation.",
                file_name, file_line);
    }

    while(isspace((int)*token))
        token++;

    if(!strcasecmp("set",token))
    {
        flowbits->type = FLOWBITS_SET;
    } 
    else if(!strcasecmp("unset",token))
    {
        flowbits->type = FLOWBITS_UNSET;
    }
    else if(!strcasecmp("toggle",token))
    {
        flowbits->type = FLOWBITS_TOGGLE;
    }
    else if(!strcasecmp("isset",token))
    {
        flowbits->type = FLOWBITS_ISSET;
    }
    else if(!strcasecmp("isnotset",token))
    {
        flowbits->type = FLOWBITS_ISNOTSET;
    } 
    else if(!strcasecmp("noalert", token))
    {
        if(strtok(NULL, " ,\t"))
        {
            FatalError("%s (%d): Do not specify a flowbits tag id for the "
                       "keyword 'noalert'.\n", file_name, file_line);
        }

        flowbits->type = FLOWBITS_NOALERT;
        flowbits->id   = 0;
        free(str);
        return;
    }
    else if(!strcasecmp("reset",token))
    {
        if(strtok(NULL, " ,\t"))
        {
            FatalError("%s (%d): Do not specify a flowbits tag id for the "
                       "keyword 'reset'.\n", file_name, file_line);
        }

        flowbits->type = FLOWBITS_RESET;
        flowbits->id   = 0;
        free(str);
        return;
    } 
    else
    {
        FatalError("%s(%d) ParseFlowArgs: Invalid token %s\n",
                file_name, file_line, token);
    }

    /*
    **  Let's parse the flowbits name
    */
    token = strtok(NULL, " ,\t");
    if(!token || !strlen(token))
    {
        FatalError("%s (%d): flowbits tag id must be provided\n",
                file_name, file_line);
    }

    /*
    **  Take space from the beginning
    */
    while(isspace((int)*token)) 
        token++;

    /*
    **  Do we still have a ID tag left.
    */
    if (!strlen(token))
    {
        FatalError("%s (%d): flowbits tag id must be provided\n",
                file_name, file_line);
    }

    /*
    **  Is there a anything left?
    */
    if(strtok(NULL, " ,\t"))
    {
        FatalError("%s (%d): flowbits tag id cannot include spaces or "
                   "commas.\n", file_name, file_line);
    }
    
    flowbits_item = (FLOWBITS_OBJECT *)sfghash_find(flowbits_hash, token);

    if (flowbits_item) 
    {
        flowbits_item->types |= flowbits->type;
        id = flowbits_item->id;
    } 
    else
    {
        flowbits_item = 
            (FLOWBITS_OBJECT *)SnortAlloc(sizeof(FLOWBITS_OBJECT));

        flowbits_item->id = flowbits_count;
        flowbits_item->types |= flowbits->type;

        hstatus = sfghash_add( flowbits_hash, token, flowbits_item);
        if(hstatus) 
        {
            FatalError("Could not add flowbits key (%s) to hash",token);
        }

        id = flowbits_count;

        flowbits_count++;

        if(flowbits_count > (giFlowbitSize<<3) )
        {
            FatalError("FLOWBITS ERROR: The number of flowbit IDs in the "
                       "current ruleset (%d) exceed the maximum number of IDs "
                       "that are allowed (%d).\n", flowbits_count,giFlowbitSize<<3);
        }
    }

    flowbits->id = id;
    flowbits->name = SnortStrdup(token);

    free(str);
}

static int ResetFlowbits(Packet *p)
{
    if(!p || !p->ssnptr)
    {
        return 0;
    }

    /*
    ** UDP or ICMP, don't reset.  This is handled by the
    ** session tracking within Stream, since we may not
    ** have seen both sides at this point.
    */
    if (p->udph || p->icmph)
    {
        return 0;
    }

    /*
    **  Check session_flags for new TCP session
    **
    **  PKT_STREAM_EST is pretty obvious why it's in here
    **
    **  SEEN_CLIENT and SEEN_SERVER allow us to only reset the bits
    **  once on the first SYN pkt.  There after bits will be
    **  accumulated for that session.
    */
    if((p->packet_flags & PKT_STREAM_EST) ||
       (stream_api && p->tcph && 
        ((stream_api->get_session_flags(p->ssnptr) & (SSNFLAG_SEEN_CLIENT | SSNFLAG_SEEN_SERVER)) == 
        (SSNFLAG_SEEN_CLIENT | SSNFLAG_SEEN_SERVER))))
    {
        return 0;
    }

    return 1;
}

/*
**  NAME
**    GetFlowbitsData::
*/
/**
**  This function initializes/retrieves flowbits data that is associated
**  with a given flow.
*/
StreamFlowData *GetFlowbitsData(Packet *p)
{
    StreamFlowData *flowdata = NULL;
    if(stream_api)
    {
        flowdata = stream_api->get_flow_data(p);
    }
    else
    {
        /* What?  Stream isn't enabled? */
        /* XXX, need to remove this when flow preprocessor is removed */
        FLOW *fp;
        FLOWDATA *flow_data;

        if (!p->flow)
        {
            return NULL;
        }

        fp = (FLOW *)p->flow;

        flow_data = &(fp->data);

        return (StreamFlowData *)flow_data;
    }

    if(!flowdata)
        return NULL;
    /*
    **  Since we didn't initialize BITOP (which resets during init)
    **  we have to check for resetting here, because it may be
    **  a new flow.
    **
    **  NOTE:
    **    We can only do this on TCP flows because we know when a
    **    connection begins and ends.  So that's what we check.
    */
    if(ResetFlowbits(p))
    {
        boResetBITOP(&(flowdata->boFlowbits));
    }

    return flowdata;
}

/****************************************************************************
 * 
 * Function: FlowBitsCheck(Packet *, struct _OptTreeNode *, OptFpList *)
 *
 * Purpose: Check flow bits foo 
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: 0 on failure
 *
 ****************************************************************************/
#ifdef DETECTION_OPTION_TREE
static int FlowBitsCheck(void *option_data, Packet *p)
{
    FLOWBITS_OP *flowbits = (FLOWBITS_OP*)option_data;
    int rval = DETECTION_OPTION_NO_MATCH;
    StreamFlowData *flowdata;
    int result = 0;
    PROFILE_VARS;

    if(!p)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, 
                   "FLOWBITSCHECK: No pkt."););
        return rval;
    }

    PREPROC_PROFILE_START(flowBitsPerfStats);

    flowdata = GetFlowbitsData(p);
    if(!flowdata)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "No FLOWBITS_DATA"););
        PREPROC_PROFILE_END(flowBitsPerfStats);
        return rval;
    }

    DEBUG_WRAP
    (
        DebugMessage(DEBUG_PLUGIN,"flowbits: type = %d\n",flowbits->type);
        DebugMessage(DEBUG_PLUGIN,"flowbits: value = %d\n",flowbits->id);
    );

    switch(flowbits->type)
    {
        case FLOWBITS_SET:
            boSetBit(&(flowdata->boFlowbits),flowbits->id);
            result = 1;
            break;

        case FLOWBITS_UNSET:
            boClearBit(&(flowdata->boFlowbits),flowbits->id);
            result = 1;
            break;

        case FLOWBITS_RESET:
            boResetBITOP(&(flowdata->boFlowbits));
            result = 1;
            break;

        case FLOWBITS_ISSET:
            if(boIsBitSet(&(flowdata->boFlowbits),flowbits->id))
            {
                result = 1;
            }
            else
            {
                rval = DETECTION_OPTION_FAILED_BIT;
            }
            break;

        case FLOWBITS_ISNOTSET:
            if (boIsBitSet(&(flowdata->boFlowbits),flowbits->id))
            {
                result = 0;
            }
            else
            {
                result = 1;
            }
            break;

        case FLOWBITS_TOGGLE:
            if (boIsBitSet(&(flowdata->boFlowbits),flowbits->id))
            {
                boClearBit(&(flowdata->boFlowbits),flowbits->id);
            }
            else
            {
                boSetBit(&(flowdata->boFlowbits),flowbits->id);
            }

            result = 1;

            break;

        case FLOWBITS_NOALERT:
            /*
            **  This logic allows us to put flowbits: noalert any where
            **  in the detection chain, and still do bit ops after this
            **  option.
            */
            PREPROC_PROFILE_END(flowBitsPerfStats);
            return DETECTION_OPTION_NO_ALERT;

        default:
            /*
            **  Always return failure here.
            */
            PREPROC_PROFILE_END(flowBitsPerfStats);
            return rval;
    }
    
    /*
    **  Now return what we found
    */
    if (result == 1)
    {
        rval = DETECTION_OPTION_MATCH;
    }

    PREPROC_PROFILE_END(flowBitsPerfStats);
    return rval;
}
#else
static int FlowBitsCheck(Packet *p,struct _OptTreeNode *otn, OptFpList *fp_list)
{
    FLOWBITS_OP *flowbits;   /* pointer to the eval struct */
    StreamFlowData *flowdata;
    int result = 0;
    PROFILE_VARS;

    if(!p)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, 
                   "FLOWBITSCHECK: No pkt."););
        return 0;
    }

    PREPROC_PROFILE_START(flowBitsPerfStats);

    flowdata = GetFlowbitsData(p);
    if(!flowdata)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "No FLOWBITS_DATA"););
        PREPROC_PROFILE_END(flowBitsPerfStats);
        return 0;
    }

    flowbits = (FLOWBITS_OP *) fp_list->context;

    DEBUG_WRAP
    (
        DebugMessage(DEBUG_PLUGIN,"flowbits: type = %d\n",flowbits->type);
        DebugMessage(DEBUG_PLUGIN,"flowbits: value = %d\n",flowbits->id);
    );

    switch(flowbits->type)
    {
        case FLOWBITS_SET:
            boSetBit(&(flowdata->boFlowbits),flowbits->id);
            result = 1;
            break;

        case FLOWBITS_UNSET:
            boClearBit(&(flowdata->boFlowbits),flowbits->id);
            result = 1;
            break;

        case FLOWBITS_RESET:
            boResetBITOP(&(flowdata->boFlowbits));
            result = 1;
            break;

        case FLOWBITS_ISSET:
            if(boIsBitSet(&(flowdata->boFlowbits),flowbits->id))
            {
                result = 1;
                otn->failedCheckBits = 0;
            }
            else
            {
                otn->failedCheckBits = 1;
            }
            break;

        case FLOWBITS_ISNOTSET:
            if (boIsBitSet(&(flowdata->boFlowbits),flowbits->id))
            {
                result = 0;
            }
            else
            {
                result = 1;
            }
            break;

        case FLOWBITS_TOGGLE:
            if (boIsBitSet(&(flowdata->boFlowbits),flowbits->id))
            {
                boClearBit(&(flowdata->boFlowbits),flowbits->id);
            }
            else
            {
                boSetBit(&(flowdata->boFlowbits),flowbits->id);
            }

            result = 1;

            break;

        case FLOWBITS_NOALERT:
            /*
            **  This logic allows us to put flowbits: noalert any where
            **  in the detection chain, and still do bit ops after this
            **  option.
            */
            if (fp_list->next->OptTestFunc(p, otn, fp_list->next))
            {
                OTN_PROFILE_NOALERT(otn);
            }
            PREPROC_PROFILE_END(flowBitsPerfStats);
            return 0;

        default:
            /*
            **  Always return failure here.
            */
            PREPROC_PROFILE_END(flowBitsPerfStats);
            return 0;
    }
    
    /*
    **  Now return what we found
    */
    if (result == 1)
    {
        PREPROC_PROFILE_END(flowBitsPerfStats);
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }

    PREPROC_PROFILE_END(flowBitsPerfStats);
    return 0;
}
#endif

/******************************************************************************
* Function: FlowBitsPrintConfig()
*
* Purpose: Print configuration information after parsing
*
* Arguments:
*
* Returns: nothing
*
******************************************************************************/
void FlowBitsPrintConfig(void)
{
    LogMessage("%d out of %d flowbits in use.\n", 
               flowbits_count, giFlowbitSize<<3);
}

/****************************************************************************
 * 
 * Function: FlowBitsVerify()
 *
 * Purpose: Check flow bits foo to make sure its valid
 *
 * Arguments: 
 *
 * Returns: 0 on failure
 *
 ****************************************************************************/
void FlowBitsVerify(void)
{
    SFGHASH_NODE * n;
    FLOWBITS_OBJECT *fb;

    if( !flowbits_hash ) return;

    for (n = sfghash_findfirst(flowbits_hash); 
         n != 0; 
         n= sfghash_findnext(flowbits_hash))
    {
        fb = (FLOWBITS_OBJECT *)n->data;

        if (fb->types & FLOWBITS_SET) {
            if (!(fb->types & FLOWBITS_ISSET || fb->types & FLOWBITS_ISNOTSET))
            {
                LogMessage("Warning: flowbits key '%s' is set but not ever checked.\n",n->key);
            }
        } else {
            if (fb->types & FLOWBITS_ISSET || fb->types & FLOWBITS_ISNOTSET) {
                LogMessage("Warning: flowbits key '%s' is checked but not ever set.\n",n->key);
            }
        }
    }

    FlowBitsPrintConfig();
}

