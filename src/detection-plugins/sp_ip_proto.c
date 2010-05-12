/* $Id$ */
/****************************************************************************
 *
 * Copyright (C) 2003-2008 Sourcefire, Inc.
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
 ****************************************************************************/

/* sp_ip_proto 
 * 
 * Purpose:
 *
 * Check the IP header's protocol field value.
 *
 * Arguments:
 *   
 *   Number, protocol name, ! for negation
 *
 * Effect:
 *
 *  Success on protocol match, failure otherwise 
 *
 * Comments:
 *
 * None.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#ifndef WIN32
#include <netdb.h>
#endif /* !WIN32 */

#include "rules.h"
#include "decode.h"
#include "plugbase.h"
#include "parser.h"
#include "debug.h"
#include "util.h"
#include "plugin_enum.h"
#include "sp_ip_proto.h"

#include "snort.h"
#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats ipProtoPerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif

#ifdef DETECTION_OPTION_TREE
#include "sfhashfcn.h"
#include "detection_options.h"
#endif /* DETECTION_OPTION_TREE */

void IpProtoInit(char *, OptTreeNode *, int);
void IpProtoRuleParseFunction(char *, IpProtoData *);
#ifdef DETECTION_OPTION_TREE
int IpProtoDetectorFunction(void *option_data, Packet *p);
#else
int IpProtoDetectorFunction(Packet *, struct _OptTreeNode *, OptFpList *);
#endif

#ifdef DETECTION_OPTION_TREE
u_int32_t IpProtoCheckHash(void *d)
{
    u_int32_t a,b,c;
    IpProtoData *data = (IpProtoData *)d;

    a = data->protocol || (data->not_flag << 8);
    b = data->comparison_flag;
    c = RULE_OPTION_TYPE_IP_PROTO;

    final(a,b,c);

    return c;
}

int IpProtoCheckCompare(void *l, void *r)
{
    IpProtoData *left = (IpProtoData *)l;
    IpProtoData *right = (IpProtoData *)r;

    if (!left || !right)
        return DETECTION_OPTION_NOT_EQUAL;

    if ((left->protocol == right->protocol) &&
        (left->not_flag == right->not_flag) &&
        (left->comparison_flag == right->comparison_flag))
    {
        return DETECTION_OPTION_EQUAL;
    }

    return DETECTION_OPTION_NOT_EQUAL;
}
#endif /* DETECTION_OPTION_TREE */



/****************************************************************************
 * 
 * Function: SetupIpProto()
 *
 * Purpose: Generic detection engine plugin ip_proto.  Registers the
 *          configuration function and links it to a rule keyword.  This is
 *          the function that gets called from InitPlugins in plugbase.c.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetupIpProto(void)
{
    /* map the keyword to an initialization/processing function */
    RegisterPlugin("ip_proto", IpProtoInit, OPT_TYPE_DETECTION);
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("ip_proto", &ipProtoPerfStats, 3, &ruleOTNEvalPerfStats);
#endif
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Plugin: IpProto Setup\n"););
}


/****************************************************************************
 * 
 * Function: IpProtoInit(char *, OptTreeNode *)
 *
 * Purpose: Generic rule configuration function.  Handles parsing the rule 
 *          information and attaching the associated detection function to
 *          the OTN.
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
void IpProtoInit(char *data, OptTreeNode *otn, int protocol)
{
    OptFpList *ofl;
    IpProtoData *ipd;
#ifdef DETECTION_OPTION_TREE
    void *ds_ptr_dup;
#endif
    
    /* multiple declaration check */ 
    /*if(otn->ds_list[PLUGIN_IP_PROTO_CHECK])
    {
        FatalError("%s(%d): Multiple ip_proto options in rule\n", file_name,
                file_line);
    }*/

    ipd = (IpProtoData *) SnortAlloc(sizeof(IpProtoData));

    /* allocate the data structure and attach it to the
       rule's data struct list */
    //otn->ds_list[PLUGIN_IP_PROTO_CHECK] = (IpProtoData *) calloc(sizeof(IpProtoData), sizeof(char));

    /* this is where the keyword arguments are processed and placed into the 
       rule option's data structure */
    IpProtoRuleParseFunction(data, ipd);

    /* finally, attach the option's detection function to the rule's 
       detect function pointer list */
    ofl = AddOptFuncToList(IpProtoDetectorFunction, otn);
#ifdef DETECTION_OPTION_TREE
    ofl->type = RULE_OPTION_TYPE_IP_PROTO;
#endif

    /*
    **  Set the ds_list for the first ip_proto check for a rule.  This
    **  is needed for the high-speed rule optimization.
    */
    if(!otn->ds_list[PLUGIN_IP_PROTO_CHECK])
        otn->ds_list[PLUGIN_IP_PROTO_CHECK] = ipd;

#ifdef DETECTION_OPTION_TREE
    if (add_detection_option(RULE_OPTION_TYPE_IP_PROTO, (void *)ipd, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
    {
        free(ipd);
        ipd = otn->ds_list[PLUGIN_IP_PROTO_CHECK] = ds_ptr_dup;
    }
#endif /* DETECTION_OPTION_TREE */
    ofl->context = ipd;
}



/****************************************************************************
 * 
 * Function: IpProtoRuleParseFunction(char *, OptTreeNode *)
 *
 * Purpose: This is the function that is used to process the option keyword's
 *          arguments and attach them to the rule's data structures.
 *
 * Arguments: data => argument data
 *            ds_ptr => pointer to the IpProtoData struct
 *
 * Returns: void function
 *
 ****************************************************************************/
void IpProtoRuleParseFunction(char *data, IpProtoData *ds_ptr)
{
    //IpProtoData *ds_ptr;  /* data struct pointer */
    struct protoent *pt;

    /* set the ds pointer to make it easier to reference the option's
       particular data struct */
    //ds_ptr = otn->ds_list[PLUGIN_IP_PROTO_CHECK];

    while(isspace((int)*data)) data++;

    if(*data == '!')
    {
        ds_ptr->not_flag = 1;
        data++;
    }

    if(*data == '>')
    {
        ds_ptr->comparison_flag = GREATER_THAN; 
        data++;
    }

    if(*data == '<')
    {
        ds_ptr->comparison_flag = LESS_THAN; 
        data++;
    }

    /* check for a number or a protocol name */
    if(isdigit((int)*data))
    {
        ds_ptr->protocol = atoi(data);
    }
    else
    {
        pt = getprotobyname(data);

        if(pt)
        {
            ds_ptr->protocol = (u_char) pt->p_proto;
        }
        else
        {
            FatalError("%s(%d) => Bad protocol name \"%s\"\n", 
                    file_name, file_line, data);
        }
    } 
}


/****************************************************************************
 * 
 * Function: IpProtoDetectorFunction(char *, OptTreeNode *)
 *
 * Purpose: Use this function to perform the particular detection routine
 *          that this rule keyword is supposed to encompass.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: If the detection test fails, this function *must* return a zero!
 *          On success, it calls the next function in the detection list 
 *
 ****************************************************************************/
#ifdef DETECTION_OPTION_TREE
int IpProtoDetectorFunction(void *option_data, Packet *p)
{
    IpProtoData *ipd = (IpProtoData *)option_data;  /* data struct pointer */
    int rval = DETECTION_OPTION_NO_MATCH;
    PROFILE_VARS;

    if(!IPH_IS_VALID(p))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Not IP\n"););
        return rval;
    }

    PREPROC_PROFILE_START(ipProtoPerfStats);

    switch(ipd->comparison_flag)
    {
        case 0:
            if((ipd->protocol == GET_IPH_PROTO(p)) ^ ipd->not_flag)
            {
                rval = DETECTION_OPTION_MATCH;
            }
            else
            {
                /* you can put debug comments here or not */
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"No match\n"););
            }

            break;

        case GREATER_THAN:
            if(GET_IPH_PROTO(p) > ipd->protocol)
            {
                rval = DETECTION_OPTION_MATCH;
            }

            break;

        default:
            if(GET_IPH_PROTO(p) < ipd->protocol)
            {
                rval = DETECTION_OPTION_MATCH;
            }

            break;
    }

    /* if the test isn't successful, this function *must* return 0 */
    PREPROC_PROFILE_END(ipProtoPerfStats);
    return rval;
}
#else
int IpProtoDetectorFunction(Packet *p, struct _OptTreeNode *otn, 
        OptFpList *fp_list)
{
    IpProtoData *ipd;  /* data struct pointer */
    PROFILE_VARS;

    //ipd = otn->ds_list[PLUGIN_IP_PROTO_CHECK];
    ipd = fp_list->context;

    if(!IPH_IS_VALID(p))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Not IP\n"););
        return 0;
    }

    PREPROC_PROFILE_START(ipProtoPerfStats);

    switch(ipd->comparison_flag)
    {
        case 0:
            if((ipd->protocol == GET_IPH_PROTO(p)) ^ ipd->not_flag)
            {
                PREPROC_PROFILE_END(ipProtoPerfStats);
                return fp_list->next->OptTestFunc(p, otn, fp_list->next);
            }
            else
            {
                /* you can put debug comments here or not */
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"No match\n"););
            }

            break;

        case GREATER_THAN:
            if(GET_IPH_PROTO(p) > ipd->protocol)
            {
                PREPROC_PROFILE_END(ipProtoPerfStats);
                return fp_list->next->OptTestFunc(p, otn, fp_list->next);
            }

            break;

        default:
            if(GET_IPH_PROTO(p) < ipd->protocol)
            {
                PREPROC_PROFILE_END(ipProtoPerfStats);
                return fp_list->next->OptTestFunc(p, otn, fp_list->next);
            }

            break;
    }

    /* if the test isn't successful, this function *must* return 0 */
    PREPROC_PROFILE_END(ipProtoPerfStats);
    return 0;
}
#endif
