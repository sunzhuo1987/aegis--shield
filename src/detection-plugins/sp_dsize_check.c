/* $Id$ */
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "rules.h"
#include "decode.h"
#include "plugbase.h"
#include "debug.h"
#include "parser.h"
#include "plugin_enum.h"
#include "util.h"

#include "snort.h"
#include "profiler.h"
#ifdef PERF_PROFILING
#ifdef DETECTION_OPTION_TREE
PreprocStats dsizePerfStats;
#else
PreprocStats dsizeEQPerfStats;
PreprocStats dsizeGTPerfStats;
PreprocStats dsizeLTPerfStats;
PreprocStats dsizeRangePerfStats;
#endif
extern PreprocStats ruleOTNEvalPerfStats;
#endif

#ifdef DETECTION_OPTION_TREE
#include "sfhashfcn.h"
#include "detection_options.h"
#endif /* DETECTION_OPTION_TREE */

#define DSIZE_EQ                   1
#define DSIZE_GT                   2
#define DSIZE_LT                   3
#define DSIZE_RANGE                4

typedef struct _DsizeCheckData
{
    int dsize;
    int dsize2;
    char operator;
} DsizeCheckData;

void DsizeCheckInit(char *, OptTreeNode *, int);
void ParseDsize(char *, OptTreeNode *);

#ifdef DETECTION_OPTION_TREE
int CheckDsize(void *option_data, Packet *p);
#else
int CheckDsizeEq(Packet *, struct _OptTreeNode *, OptFpList *);
int CheckDsizeGT(Packet *, struct _OptTreeNode *, OptFpList *);
int CheckDsizeLT(Packet *, struct _OptTreeNode *, OptFpList *);
int CheckDsizeRange(Packet *, struct _OptTreeNode *, OptFpList *);
#endif

#ifdef DETECTION_OPTION_TREE
u_int32_t DSizeCheckHash(void *d)
{
    u_int32_t a,b,c;
    DsizeCheckData *data = (DsizeCheckData *)d;

    a = data->dsize;
    b = data->dsize2;
    c = data->operator;

    mix(a,b,c);

    a += RULE_OPTION_TYPE_DSIZE;

    final(a,b,c);

    return c;
}

int DSizeCheckCompare(void *l, void *r)
{
    DsizeCheckData *left = (DsizeCheckData *)l;
    DsizeCheckData *right = (DsizeCheckData *)r;

    if (!left || !right)
        return DETECTION_OPTION_NOT_EQUAL;
                                
    if (( left->dsize == right->dsize) &&
        ( left->dsize2 == right->dsize2) &&
        ( left->operator == right->operator))
    {
        return DETECTION_OPTION_EQUAL;
    }

    return DETECTION_OPTION_NOT_EQUAL;
}
#endif /* DETECTION_OPTION_TREE */

/****************************************************************************
 * 
 * Function: SetupDsizeCheck()
 *
 * Purpose: Attach the dsize keyword to the rule parse function
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetupDsizeCheck(void)
{
    /* map the keyword to an initialization/processing function */
    RegisterPlugin("dsize", DsizeCheckInit, OPT_TYPE_DETECTION);
#ifdef PERF_PROFILING
#ifdef DETECTION_OPTION_TREE
    RegisterPreprocessorProfile("dsize_eq", &dsizePerfStats, 3, &ruleOTNEvalPerfStats);
#else
    RegisterPreprocessorProfile("dsize_eq", &dsizeEQPerfStats, 3, &ruleOTNEvalPerfStats);
    RegisterPreprocessorProfile("dsize_gt", &dsizeGTPerfStats, 3, &ruleOTNEvalPerfStats);
    RegisterPreprocessorProfile("dsize_lt", &dsizeLTPerfStats, 3, &ruleOTNEvalPerfStats);
    RegisterPreprocessorProfile("dsize_range", &dsizeRangePerfStats, 3, &ruleOTNEvalPerfStats);
#endif
#endif
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: DsizeCheck Initialized\n"););
}


/****************************************************************************
 * 
 * Function: DsizeCheckInit(char *, OptTreeNode *)
 *
 * Purpose: Parse the rule argument and attach it to the rule data struct, 
 *          then attach the detection function to the function list
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
void DsizeCheckInit(char *data, OptTreeNode *otn, int protocol)
{
    /* multiple declaration check */
    if(otn->ds_list[PLUGIN_DSIZE_CHECK])
    {
        FatalError("%s(%d): Multiple dsize options in rule\n", file_name,
                file_line);
    }

    /* allocate the data structure and attach it to the
       rule's data struct list */

    otn->ds_list[PLUGIN_DSIZE_CHECK] = (DsizeCheckData *)
        SnortAlloc(sizeof(DsizeCheckData));

    /* this is where the keyword arguments are processed and placed into the 
       rule option's data structure */
    ParseDsize(data, otn);

    /* NOTE: I moved the AddOptFuncToList call to the parsing function since
       the linking is best determined within that function */
}



/****************************************************************************
 * 
 * Function: ParseDsize(char *, OptTreeNode *)
 *
 * Purpose: Parse the dsize function argument and attach the detection
 *          function to the rule list as well.  
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
void ParseDsize(char *data, OptTreeNode *otn)
{
    DsizeCheckData *ds_ptr;  /* data struct pointer */
    char *pcEnd;
    char *pcTok;
    int  iDsize = 0;
#ifdef DETECTION_OPTION_TREE
    void *ds_ptr_dup;
#endif
    OptFpList *fpl;

    /* set the ds pointer to make it easier to reference the option's
       particular data struct */
    ds_ptr = (DsizeCheckData *)otn->ds_list[PLUGIN_DSIZE_CHECK];

    while(isspace((int)*data)) data++;

    /* If a range is specified, put min in ds_ptr->dsize and max in
       ds_ptr->dsize2 */
    
    if(isdigit((int)*data) && strchr(data, '<') && strchr(data, '>'))
    {
        pcTok = strtok(data, " <>");
        if(!pcTok)
        {
            /*
            **  Fatal
            */
            FatalError("%s(%d): Invalid 'dsize' argument.\n",
                       file_name, file_line);
        }

        iDsize = strtol(pcTok, &pcEnd, 10);
        if(iDsize < 0 || *pcEnd)
        {
            FatalError("%s(%d): Invalid 'dsize' argument.\n",
                       file_name, file_line);
        }

        ds_ptr->dsize = (unsigned short)iDsize;

        pcTok = strtok(NULL, " <>");
        if(!pcTok)
        {
            FatalError("%s(%d): Invalid 'dsize' argument.\n",
                       file_name, file_line);
        }

        iDsize = strtol(pcTok, &pcEnd, 10);
        if(iDsize < 0 || *pcEnd)
        {
            FatalError("%s(%d): Invalid 'dsize' argument.\n",
                       file_name, file_line);
        }

        ds_ptr->dsize2 = (unsigned short)iDsize;

        ds_ptr->operator = DSIZE_RANGE;

#ifdef DEBUG
        printf("min dsize: %d\n", ds_ptr->dsize);
        printf("max dsize: %d\n", ds_ptr->dsize2);
#endif
#ifdef DETECTION_OPTION_TREE
        fpl = AddOptFuncToList(CheckDsize, otn);
        fpl->type = RULE_OPTION_TYPE_DSIZE;

        if (add_detection_option(RULE_OPTION_TYPE_DSIZE, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
        {
            free(ds_ptr);
            ds_ptr = otn->ds_list[PLUGIN_DSIZE_CHECK] = ds_ptr_dup;
        }
        fpl->context = ds_ptr;
#else
        fpl = AddOptFuncToList(CheckDsizeRange, otn);
#endif /* DETECTION_OPTION_TREE */

        return;
    }
    else if(*data == '>')
    {
        data++;
#ifdef DETECTION_OPTION_TREE
        fpl = AddOptFuncToList(CheckDsize, otn);
#else
        fpl = AddOptFuncToList(CheckDsizeGT, otn);
#endif
        ds_ptr->operator = DSIZE_GT;
    }
    else if(*data == '<')
    {
        data++;
#ifdef DETECTION_OPTION_TREE
        fpl = AddOptFuncToList(CheckDsize, otn);
#else
        fpl = AddOptFuncToList(CheckDsizeLT, otn);
#endif
        ds_ptr->operator = DSIZE_LT;
    }
    else
    {
#ifdef DETECTION_OPTION_TREE
        fpl = AddOptFuncToList(CheckDsize, otn);
#else
        fpl = AddOptFuncToList(CheckDsizeEq, otn);
#endif
        ds_ptr->operator = DSIZE_EQ;
    }

#ifdef DETECTION_OPTION_TREE
    fpl->type = RULE_OPTION_TYPE_DSIZE;
#endif

    while(isspace((int)*data)) data++;

    iDsize = strtol(data, &pcEnd, 10);
    if(iDsize < 0 || *pcEnd)
    {
        FatalError("%s(%d): Invalid 'dsize' argument.\n",
                   file_name, file_line);
    }

    ds_ptr->dsize = (unsigned short)iDsize;

#ifdef DETECTION_OPTION_TREE
    if (add_detection_option(RULE_OPTION_TYPE_DSIZE, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
    {
        free(ds_ptr);
        ds_ptr = otn->ds_list[PLUGIN_DSIZE_CHECK] = ds_ptr_dup;
     }
     fpl->context = ds_ptr;
#endif /* DETECTION_OPTION_TREE */

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Payload length = %d\n", ds_ptr->dsize););

}

#ifdef DETECTION_OPTION_TREE
/****************************************************************************
 * 
 * Function: CheckDsizeEq(char *, OptTreeNode *)
 *
 * Purpose: Test the packet's payload size against the rule payload size value
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns:  0 on failure, return value of next list function on success
 ****************************************************************************/
int CheckDsize(void *option_data, Packet *p)
{
    DsizeCheckData *ds_ptr = (DsizeCheckData *)option_data;
    int rval = DETECTION_OPTION_NO_MATCH;
    PROFILE_VARS;

    if (!ds_ptr)
        return rval;

    PREPROC_PROFILE_END(dsizePerfStats);

    /* fake packet dsizes are always wrong */
    if(p->packet_flags & PKT_REBUILT_STREAM)
    {
        PREPROC_PROFILE_END(dsizePerfStats);
        return rval;
    }

    switch (ds_ptr->operator)
    {
        case DSIZE_EQ:
            if (ds_ptr->dsize == p->dsize)
                rval = DETECTION_OPTION_MATCH;
            break;
        case DSIZE_GT:
            if (ds_ptr->dsize < p->dsize)
                rval = DETECTION_OPTION_MATCH;
            break;
        case DSIZE_LT:
            if (ds_ptr->dsize > p->dsize)
                rval = DETECTION_OPTION_MATCH;
            break;
        case DSIZE_RANGE:
            if ((ds_ptr->dsize <= p->dsize) &&
                (ds_ptr->dsize2 >= p->dsize))
                rval = DETECTION_OPTION_MATCH;
            break;
        default:
            break;
    }

    PREPROC_PROFILE_END(dsizePerfStats);
    return rval;
}
#else
/****************************************************************************
 * 
 * Function: CheckDsizeEq(char *, OptTreeNode *)
 *
 * Purpose: Test the packet's payload size against the rule payload size value
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns:  0 on failure, return value of next list function on success
 *
 ****************************************************************************/
int CheckDsizeEq(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(dsizeEQPerfStats);

    /* fake packet dsizes are always wrong */
    if(p->packet_flags & PKT_REBUILT_STREAM)
    {
        PREPROC_PROFILE_END(dsizeEQPerfStats);
        return 0;
    }
    
    if(((DsizeCheckData *)otn->ds_list[PLUGIN_DSIZE_CHECK])->dsize == p->dsize)
    {
        /* call the next function in the function list recursively */
        PREPROC_PROFILE_END(dsizeEQPerfStats);
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }
    else
    {
        /* you can put debug comments here or not */
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Not equal\n"););
    }

    /* if the test isn't successful, return 0 */
    PREPROC_PROFILE_END(dsizeEQPerfStats);
    return 0;
}



/****************************************************************************
 * 
 * Function: CheckDsizeGT(char *, OptTreeNode *)
 *
 * Purpose: Test the packet's payload size against the rule payload size 
 *          value.  This test determines if the packet payload size is 
 *          greater than the rule dsize.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns:  0 on failure, return value of next list function on success
 *
 ****************************************************************************/
int CheckDsizeGT(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(dsizeGTPerfStats);

    /* fake packet dsizes are always wrong */
    if(p->packet_flags & PKT_REBUILT_STREAM)
    {
        PREPROC_PROFILE_END(dsizeGTPerfStats);
        return 0;
    }

    if(((DsizeCheckData *)otn->ds_list[PLUGIN_DSIZE_CHECK])->dsize < p->dsize)
    {
        /* call the next function in the function list recursively */
        PREPROC_PROFILE_END(dsizeGTPerfStats);
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }
    else
    {
        /* you can put debug comments here or not */
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Not equal\n"););
    }

    /* if the test isn't successful, return 0 */
    PREPROC_PROFILE_END(dsizeGTPerfStats);
    return 0;
}




/****************************************************************************
 * 
 * Function: CheckDsizeLT(char *, OptTreeNode *)
 *
 * Purpose: Test the packet's payload size against the rule payload size 
 *          value.  This test determines if the packet payload size is 
 *          less than the rule dsize.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns:  0 on failure, return value of next list function on success
 *
 ****************************************************************************/
int CheckDsizeLT(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(dsizeLTPerfStats);

    /* fake packet dsizes are always wrong */
    if(p->packet_flags & PKT_REBUILT_STREAM)
    {
        PREPROC_PROFILE_END(dsizeLTPerfStats);
        return 0;
    }
    
    if(((DsizeCheckData *)otn->ds_list[PLUGIN_DSIZE_CHECK])->dsize > p->dsize)
    {
        /* call the next function in the function list recursively */
        PREPROC_PROFILE_END(dsizeLTPerfStats);
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }
    else
    {
        /* you can put debug comments here or not */
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Not equal\n"););
    }

    /* if the test isn't successful, return 0 */
    PREPROC_PROFILE_END(dsizeLTPerfStats);
    return 0;
}


/****************************************************************************
 *
 * Function: CheckDsizeRange(char *, OptTreeNode *)
 *
 * Purpose: Test the packet's payload size against the rule payload size
 *          values.  This test determines if the packet payload size is
 *          in the range of the rule dsize min and max.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns:  0 on failure, return value of next list function on success
 *
 ****************************************************************************/
int CheckDsizeRange(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(dsizeRangePerfStats);

    /* fake packet dsizes are always wrong */
    if(p->packet_flags & PKT_REBUILT_STREAM)
    {
        PREPROC_PROFILE_END(dsizeRangePerfStats);
        return 0;
    }

    if(((DsizeCheckData *)otn->ds_list[PLUGIN_DSIZE_CHECK])->dsize <= p->dsize &&
     ((DsizeCheckData *)otn->ds_list[PLUGIN_DSIZE_CHECK])->dsize2 >= p->dsize)
    {
        /* call the next function in the function list recursively */
        PREPROC_PROFILE_END(dsizeRangePerfStats);
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,
                                "CheckDsizeRange(): not in range\n"););
    }

    PREPROC_PROFILE_END(dsizeRangePerfStats);
    return 0;
}
#endif
