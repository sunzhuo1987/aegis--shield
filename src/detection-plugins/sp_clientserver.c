/* $Id$ */
/*
 ** Copyright (C) 2002-2008 Sourcefire, Inc.
 ** Author: Martin Roesch
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

/* sp_clientserver 
 * 
 * Purpose:
 *
 * Wouldn't be nice if we could tell a TCP rule to only apply if it's going 
 * to or from the client or server side of a connection?  Think of all the 
 * false alarms we could elminate!  That's what we're doing with this one,
 * it allows you to write rules that only apply to client or server packets.
 * One thing though, you *must* have stream4 enabled for it to work!
 *
 * Arguments:
 *   
 *   None.
 *
 * Effect:
 *
 * Test the packet to see if it's coming from the client or the server side
 * of a connection.
 *
 * Comments:
 *
 * None.
 *
 */

/* put the name of your pluging header file here */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "rules.h"
#include "decode.h"
#include "plugbase.h"
#include "parser.h"
#include "debug.h"
#include "util.h"
#include "plugin_enum.h"
#include "snort.h"
//#include "signature.h"

#include "stream_api.h"

#include "snort.h"
#include "profiler.h"
#ifdef PERF_PROFILING
#ifdef DETECTION_OPTION_TREE
PreprocStats flowCheckPerfStats;
#else
PreprocStats flowFromClientPerfStats;
PreprocStats flowFromServerPerfStats;
PreprocStats flowReassembledPerfStats;
PreprocStats flowNonReassembledPerfStats;
#endif
extern PreprocStats ruleOTNEvalPerfStats;
#endif

typedef struct _ClientServerData
{
    u_int8_t from_server;
    u_int8_t from_client;    
    u_int8_t ignore_reassembled; /* ignore reassembled sessions */
    u_int8_t only_reassembled; /* ignore reassembled sessions */
#ifdef DETECTION_OPTION_TREE
    u_int8_t stateless;    
    u_int8_t established;    
    u_int8_t unestablished;    
#endif
} ClientServerData;

#ifdef DETECTION_OPTION_TREE
#include "sfhashfcn.h"
#include "detection_options.h"
#endif /* DETECTION_OPTION_TREE */

void FlowInit(char *, OptTreeNode *, int);
void ParseFlowArgs(char *, OptTreeNode *);
void InitFlowData(OptTreeNode *);
#ifdef DETECTION_OPTION_TREE
int CheckFlow(void *option_data, Packet *p);
#else
int CheckFromClient(Packet *, struct _OptTreeNode *, OptFpList *);
int CheckFromServer(Packet *, struct _OptTreeNode *, OptFpList *);
int CheckForReassembled(Packet *, struct _OptTreeNode *, OptFpList *);
int CheckForNonReassembled(Packet *p, struct _OptTreeNode *, OptFpList *);
#endif

#ifdef DETECTION_OPTION_TREE
u_int32_t FlowHash(void *d)
{
    u_int32_t a,b,c;
    ClientServerData *data = (ClientServerData *)d;

    a = data->from_server || data->from_client << 16;
    b = data->ignore_reassembled || data->only_reassembled << 16;
    c = data->stateless || data->established << 16;

    mix(a,b,c);

    a += data->unestablished;
    b += RULE_OPTION_TYPE_FLOW;

    final(a,b,c);

    return c;
}

int FlowCompare(void *l, void *r)
{   
    ClientServerData *left = (ClientServerData *)l;
    ClientServerData *right = (ClientServerData *)r;

    if (!left || !right)
        return DETECTION_OPTION_NOT_EQUAL;
                                                             
    if (( left->from_server == right->from_server) &&
        ( left->from_client == right->from_client) &&
        ( left->ignore_reassembled == right->ignore_reassembled) &&
        ( left->only_reassembled == right->only_reassembled) &&
        ( left->stateless == right->stateless) &&
        ( left->established == right->established) &&
        ( left->unestablished == right->unestablished))
    {
        return DETECTION_OPTION_EQUAL;
    }

    return DETECTION_OPTION_NOT_EQUAL;
}
#endif /* DETECTION_OPTION_TREE */


int OtnFlowFromServer( OptTreeNode * otn )
{
    ClientServerData *csd;

    csd = (ClientServerData *)otn->ds_list[PLUGIN_CLIENTSERVER];
    if(csd )
    {
        if( csd->from_server ) return 1;
    }
    return 0; 
}
int OtnFlowFromClient( OptTreeNode * otn )
{
    ClientServerData *csd;

    csd = (ClientServerData *)otn->ds_list[PLUGIN_CLIENTSERVER];
    if(csd )
    {
        if( csd->from_client ) return 1;
    }
    return 0; 
}
int OtnFlowIgnoreReassembled( OptTreeNode * otn )
{
    ClientServerData *csd;

    csd = (ClientServerData *)otn->ds_list[PLUGIN_CLIENTSERVER];
    if( csd )
    {
        if( csd->ignore_reassembled ) return 1;
    }
    return 0; 
}
int OtnFlowOnlyReassembled( OptTreeNode * otn )
{
    ClientServerData *csd;

    csd = (ClientServerData *)otn->ds_list[PLUGIN_CLIENTSERVER];
    if( csd )
    {
        if( csd->only_reassembled ) return 1;
    }
    return 0; 
}

/****************************************************************************
 * 
 * Function: SetupClientServer()
 *
 * Purpose: Generic detection engine plugin template.  Registers the
 *          configuration function and links it to a rule keyword.  This is
 *          the function that gets called from InitPlugins in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetupClientServer(void)
{
    /* map the keyword to an initialization/processing function */
    RegisterPlugin("flow", FlowInit, OPT_TYPE_DETECTION);

#ifdef PERF_PROFILING
#ifdef DETECTION_OPTION_TREE
    RegisterPreprocessorProfile("flow", &flowCheckPerfStats, 3, &ruleOTNEvalPerfStats);
#else
    RegisterPreprocessorProfile("flow_from_client", &flowFromClientPerfStats, 3, &ruleOTNEvalPerfStats);
    RegisterPreprocessorProfile("flow_from_server", &flowFromServerPerfStats, 3, &ruleOTNEvalPerfStats);
    RegisterPreprocessorProfile("flow_reassembled", &flowReassembledPerfStats, 3, &ruleOTNEvalPerfStats);
    RegisterPreprocessorProfile("flow_non_reassembled", &flowNonReassembledPerfStats, 3, &ruleOTNEvalPerfStats);
#endif
#endif

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, 
                            "Plugin: ClientServerName(Flow) Setup\n"););
}


/****************************************************************************
 * 
 * Function: FlowInit(char *, OptTreeNode *)
 *
 * Purpose: Configure the flow init option to register the appropriate checks
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
void FlowInit(char *data, OptTreeNode *otn, int protocol)
{
#ifdef STREAM4_UDP
    if ((protocol != IPPROTO_TCP) && (protocol != IPPROTO_UDP))
    {
        FatalError("%s(%d): Cannot check flow connection "
                   "for non-TCP and non-UDP traffic\n", file_name, file_line);
    }
#else
    if(protocol != IPPROTO_TCP)
    {
        if (!stream_api || (stream_api->version != STREAM_API_VERSION5))
        {
            FatalError("%s(%d): Cannot check flow connection "
                   "for non-TCP traffic\n", file_name, file_line);
        }
    }
#endif

    /* multiple declaration check */
    if(otn->ds_list[PLUGIN_CLIENTSERVER])
    {
        FatalError("%s(%d): Multiple flow options in rule\n", file_name, 
                file_line);
    }
        

    InitFlowData(otn);
    ParseFlowArgs(data, otn);
}



/****************************************************************************
 * 
 * Function: ParseFlowArgs(char *, OptTreeNode *)
 *
 * Purpose: parse the arguments to the flow plugin and alter the otn
 *          accordingly
 *
 * Arguments: otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
void ParseFlowArgs(char *data, OptTreeNode *otn)
{
    char *token, *str, *p;
    ClientServerData *csd;
#ifdef DETECTION_OPTION_TREE
    void *idx_dup;
#endif
    OptFpList *fpl = NULL;

    csd = (ClientServerData *)otn->ds_list[PLUGIN_CLIENTSERVER];

    str = SnortStrdup(data);

    p = str;

    /* nuke leading whitespace */
    while(isspace((int)*p)) p++;

    token = strtok(p, ",");

    while(token) 
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, 
                    "parsed %s,(%d)\n", token,strlen(token)););

        while(isspace((int)*token))
            token++;

        if(!strcasecmp(token, "to_server"))
        {
            csd->from_client = 1;
        }
        else if(!strcasecmp(token, "to_client"))
        {
            csd->from_server = 1;
        } 
        else if(!strcasecmp(token, "from_server"))
        {
            csd->from_server = 1;
        } 
        else if(!strcasecmp(token, "from_client"))
        {
            csd->from_client = 1;
        }
        else if(!strcasecmp(token, "stateless"))
        {
#ifdef DETECTION_OPTION_TREE
            csd->stateless = 1;
#endif
            otn->stateless = 1;
        }
        else if(!strcasecmp(token, "established"))
        {
#ifdef DETECTION_OPTION_TREE
            csd->established = 1;
#endif
            otn->established = 1;
        }
        else if(!strcasecmp(token, "not_established"))
        {
#ifdef DETECTION_OPTION_TREE
            csd->unestablished = 1;
#endif
            otn->unestablished = 1;
        }
        else if(!strcasecmp(token, "no_stream"))
        {
            csd->ignore_reassembled = 1;
        }
        else if(!strcasecmp(token, "only_stream"))
        {
            csd->only_reassembled = 1;
        }
        else
        {
            FatalError("%s:%d: Unknown Flow Option: '%s'\n",
                       file_name,file_line,token);

        }


        token = strtok(NULL, ",");
    }

    if(csd->from_client && csd->from_server)
    {
        FatalError("%s:%d: Can't use both from_client"
                   "and flow_from server", file_name, file_line);
    }

    if(csd->ignore_reassembled && csd->only_reassembled)
    {
        FatalError("%s:%d: Can't use no_stream and"
                   " only_stream", file_name,file_line);
    }

    if(otn->stateless && (csd->from_client || csd->from_server)) 
    {
        FatalError("%s:%d: Can't use flow: stateless option with"
                   " other options", file_name, file_line);
    }

    if(otn->stateless && otn->established)
    {
        FatalError("%s:%d: Can't specify established and stateless "
                   "options in same rule\n", file_name, file_line);
    }

    if(otn->stateless && otn->unestablished)
    {
        FatalError("%s:%d: Can't specify unestablished and stateless "
                   "options in same rule\n", file_name, file_line);
    }

    if(otn->established && otn->unestablished)
    {
        FatalError("%s:%d: Can't specify unestablished and established "
                   "options in same rule\n", file_name, file_line);
    }

#ifdef DETECTION_OPTION_TREE
    if (add_detection_option(RULE_OPTION_TYPE_FLOW, (void *)csd, &idx_dup) == DETECTION_OPTION_EQUAL)
    {
#if 0
        LogMessage("Duplicate Flow:\n%c %c %c %c\n%c %c %c %c\n\n",
            csd->from_client,
            csd->from_server,
            csd->ignore_reassembled,
            csd->only_reassembled,
            ((ClientServerData *)idx_dup)->from_client,
            ((ClientServerData *)idx_dup)->from_server,
            ((ClientServerData *)idx_dup)->ignore_reassembled,
            ((ClientServerData *)idx_dup)->only_reassembled);
#endif
        free(csd);
        csd = otn->ds_list[PLUGIN_CLIENTSERVER] = (ClientServerData *)idx_dup;
    }
#endif /* DETECTION_OPTION_TREE */

#ifdef DETECTION_OPTION_TREE
    fpl = AddOptFuncToList(CheckFlow, otn);
    if (fpl)
    {
        fpl->type = RULE_OPTION_TYPE_FLOW;
        fpl->context = (void *)csd;
    }
#else
    if(csd->from_client) 
    {
        fpl = AddOptFuncToList(CheckFromClient, otn);
    } 

    if(csd->from_server) 
    {
        fpl = AddOptFuncToList(CheckFromServer, otn);
    }

    if(csd->ignore_reassembled) 
    {
        fpl = AddOptFuncToList(CheckForNonReassembled, otn);
    }

    if(csd->only_reassembled) 
    {
        fpl = AddOptFuncToList(CheckForReassembled, otn);
    }
#endif
    
    free(str);
}

/****************************************************************************
 * 
 * Function: InitFlowData(OptTreeNode *)
 *
 * Purpose: calloc the clientserver data node
 *
 * Arguments: otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
void InitFlowData(OptTreeNode * otn)
{

    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_CLIENTSERVER] = (ClientServerData *) 
        calloc(sizeof(ClientServerData), sizeof(char));

    if(otn->ds_list[PLUGIN_CLIENTSERVER] == NULL) 
    {
        FatalError("FlowData calloc Failed!\n");
    }
}

#ifdef DETECTION_OPTION_TREE
int CheckFlow(void *option_data, Packet *p)
{
    ClientServerData *csd = (ClientServerData *)option_data;
    PROFILE_VARS;

    PREPROC_PROFILE_START(flowCheckPerfStats);

    /* Check established/unestablished first */
    if(snort_runtime.capabilities.stateful_inspection == 1)
    {
        if ((csd->established == 1) && !(p->packet_flags & PKT_STREAM_EST))
        {
            /*
            **  We check to see if this packet may have been picked up in
            **  midstream by stream4 on a timed out session.  If it was, then
            **  we'll go ahead and inspect it anyway because it might be a 
            **  packet that we dropped but the attacker has retransmitted after
            **  the stream4 session timed out.
            */
#if 0
            if(InlineMode())
            {
                switch(List->rtn->type)
                {
                    case RULE_DROP:
                    case RULE_SDROP:

                        if(stream_api && 
                           !(stream_api->get_session_flags(p->ssnptr) & SSNFLAG_MIDSTREAM))
                        {
                            return DETECTION_OPTION_NO_MATCH;
                        }
                        break;

                    default:
                        return DETECTION_OPTION_NO_MATCH;
                }
            }
            else
#endif
            {
                /* 
                ** This option requires an established connection and it isn't
                ** in that state yet, so no match.
                */
                PREPROC_PROFILE_END(flowCheckPerfStats);
                return DETECTION_OPTION_NO_MATCH;
            }
        }
        else if ((csd->unestablished == 1) && (p->packet_flags & PKT_STREAM_EST))
        {
            /*
            **  We're looking for an unestablished stream, and this is
            **  established, so don't continue processing.
            */
            PREPROC_PROFILE_END(flowCheckPerfStats);
            return DETECTION_OPTION_NO_MATCH;
        }
    }

    /* Now check from client */
    if (csd->from_client)
    {
        if(pv.stateful)
        {
            if (!(p->packet_flags & PKT_FROM_CLIENT) && 
                (p->packet_flags & PKT_FROM_SERVER))
            {
                /* No match on from_client */
                PREPROC_PROFILE_END(flowCheckPerfStats);
                return DETECTION_OPTION_NO_MATCH;
            }
        }
    }

    /* And from server */
    if (csd->from_server)
    {
        if(pv.stateful)
        {
            if (!(p->packet_flags & PKT_FROM_SERVER) && 
                (p->packet_flags & PKT_FROM_CLIENT))
            {
                /* No match on from_server */
                PREPROC_PROFILE_END(flowCheckPerfStats);
                return DETECTION_OPTION_NO_MATCH;
            }
        }
    }

    /* ...ignore_reassembled */
    if (csd->ignore_reassembled)
    {
        if (p->packet_flags & PKT_REBUILT_STREAM)
        {
            PREPROC_PROFILE_END(flowCheckPerfStats);
            return DETECTION_OPTION_NO_MATCH;
        }
    }

    /* ...only_reassembled */
    if (csd->only_reassembled)
    {
        if (!(p->packet_flags & PKT_REBUILT_STREAM))
        {
            PREPROC_PROFILE_END(flowCheckPerfStats);
            return DETECTION_OPTION_NO_MATCH;
        }
    }

    PREPROC_PROFILE_END(flowCheckPerfStats);
    return DETECTION_OPTION_MATCH;
}
#else
/****************************************************************************
 * 
 * Function: CheckFromClient(Packet *, struct _OptTreeNode *, OptFpList *)
 *
 * Purpose: Check to see if this packet came from the client side of the 
 *          connection.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: 0 on failure
 *
 ****************************************************************************/
int CheckFromClient(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(flowFromClientPerfStats);

#ifdef DEBUG_CS
    DebugMessage(DEBUG_STREAM, "CheckFromClient: entering\n");
    if(p->packet_flags & PKT_REBUILT_STREAM)
    {
        DebugMessage(DEBUG_STREAM, "=> rebuilt!\n");
    }
#endif /* DEBUG_CS */    

    if(!pv.stateful)
    {
        /* if we're not in stateful mode we ignore this plugin */
        PREPROC_PROFILE_END(flowFromClientPerfStats);
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }

    if(p->packet_flags & PKT_FROM_CLIENT || 
            !(p->packet_flags & PKT_FROM_SERVER))
    {
        PREPROC_PROFILE_END(flowFromClientPerfStats);
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }

    /* if the test isn't successful, this function *must* return 0 */
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM, "CheckFromClient: returning 0\n"););
    PREPROC_PROFILE_END(flowFromClientPerfStats);
    return 0;
}


/****************************************************************************
 * 
 * Function: CheckFromServer(Packet *, struct _OptTreeNode *, OptFpList *)
 *
 * Purpose: Check to see if this packet came from the client side of the 
 *          connection.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: 0 on failure
 *
 ****************************************************************************/
int CheckFromServer(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(flowFromServerPerfStats);

    if(!pv.stateful)
    {
        /* if we're not in stateful mode we ignore this plugin */
        PREPROC_PROFILE_END(flowFromServerPerfStats);
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }
    
    if(p->packet_flags & PKT_FROM_SERVER || 
            !(p->packet_flags & PKT_FROM_CLIENT))
    {
        PREPROC_PROFILE_END(flowFromServerPerfStats);
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }

    /* if the test isn't successful, this function *must* return 0 */
    PREPROC_PROFILE_END(flowFromServerPerfStats);
    return 0;
}


/****************************************************************************
 * 
 * Function: int CheckForReassembled(Packet *p, struct _OptTreeNode *otn,
                                    OptFpList *fp_list)
 *
 * Purpose: Check to see if this packet came from a reassembled connection
 *          connection.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: 0 on failure
 *
 ****************************************************************************/
int CheckForReassembled(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(flowReassembledPerfStats);

    /* is this a reassembled stream? */
    if(p->packet_flags & PKT_REBUILT_STREAM)
    {
        PREPROC_PROFILE_END(flowReassembledPerfStats);
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }

    /* if the test isn't successful, this function *must* return 0 */
    PREPROC_PROFILE_END(flowReassembledPerfStats);
    return 0;
}


/* 
 * Function: int CheckForNonReassembled(Packet *p, struct _OptTreeNode *otn,
                                    OptFpList *fp_list)
 *
 * Purpose: Check to see if this packet came from a reassembled connection
 *          connection.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: 0 on failure
 *
 ****************************************************************************/
int CheckForNonReassembled(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(flowNonReassembledPerfStats);

    /* is this a reassembled stream? */
    if(p->packet_flags & PKT_REBUILT_STREAM)
    {
        PREPROC_PROFILE_END(flowNonReassembledPerfStats);
        return 0;
    }

    /* if the test isn't successful, this function *must* return 0 */
    PREPROC_PROFILE_END(flowNonReassembledPerfStats);
    return fp_list->next->OptTestFunc(p, otn, fp_list->next);
}
#endif
