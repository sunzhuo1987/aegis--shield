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
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <ctype.h>

#include "rules.h"
#include "decode.h"
#include "plugbase.h"
#include "parser.h"
#include "util.h"
#include "debug.h"
#include "plugin_enum.h"

#include "snort.h"
#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats tcpWinPerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif

#ifdef DETECTION_OPTION_TREE
#include "sfhashfcn.h"
#include "detection_options.h"
#endif /* DETECTION_OPTION_TREE */

typedef struct _TcpWinCheckData
{
    u_int16_t tcp_win;
    u_int8_t not_flag;

} TcpWinCheckData;

void TcpWinCheckInit(char *, OptTreeNode *, int);
void ParseTcpWin(char *, OptTreeNode *);
#ifdef DETECTION_OPTION_TREE
int TcpWinCheckEq(void *option_data, Packet *p);
#else
int TcpWinCheckEq(Packet *, struct _OptTreeNode *, OptFpList *);
#endif

#ifdef DETECTION_OPTION_TREE
u_int32_t TcpWinCheckHash(void *d)
{
    u_int32_t a,b,c;
    TcpWinCheckData *data = (TcpWinCheckData *)d;

    a = data->tcp_win;
    b = data->not_flag;
    c = RULE_OPTION_TYPE_TCP_WIN;

    final(a,b,c);

    return c;
}

int TcpWinCheckCompare(void *l, void *r)
{
    TcpWinCheckData *left = (TcpWinCheckData *)l;
    TcpWinCheckData *right = (TcpWinCheckData *)r;

    if (!left || !right)
        return DETECTION_OPTION_NOT_EQUAL;

    if ((left->tcp_win == right->tcp_win) &&
        (left->not_flag == right->not_flag))
    {
        return DETECTION_OPTION_EQUAL;
    }

    return DETECTION_OPTION_NOT_EQUAL;
}
#endif /* DETECTION_OPTION_TREE */



/****************************************************************************
 * 
 * Function: SetupTcpWinCheck()
 *
 * Purpose: Associate the window keyword with TcpWinCheckInit
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetupTcpWinCheck(void)
{
    /* map the keyword to an initialization/processing function */
    RegisterPlugin("window", TcpWinCheckInit, OPT_TYPE_DETECTION);
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("window", &tcpWinPerfStats, 3, &ruleOTNEvalPerfStats);
#endif
}


/****************************************************************************
 * 
 * Function: TcpWinCheckInit(char *, OptTreeNode *)
 *
 * Purpose: Setup the window data struct and link the function into option
 *          function pointer list
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *
 * Returns: void function
 *
 ****************************************************************************/
void TcpWinCheckInit(char *data, OptTreeNode *otn, int protocol)
{
    OptFpList *fpl;
    if(protocol != IPPROTO_TCP)
    {
        FatalError("%s(%d): TCP Options on non-TCP rule\n", 
                   file_name, file_line);
    }

    /* multiple declaration check */ 
    if(otn->ds_list[PLUGIN_TCP_WIN_CHECK])
    {
        FatalError("%s(%d): Multiple TCP window options in rule\n", file_name,
                file_line);
    }
        
    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_TCP_WIN_CHECK] = (TcpWinCheckData *)
            SnortAlloc(sizeof(TcpWinCheckData));

    /* this is where the keyword arguments are processed and placed into the 
       rule option's data structure */
    ParseTcpWin(data, otn);

    /* finally, attach the option's detection function to the rule's 
       detect function pointer list */
    fpl = AddOptFuncToList(TcpWinCheckEq, otn);
#ifdef DETECTION_OPTION_TREE
    fpl->type = RULE_OPTION_TYPE_TCP_WIN;
    fpl->context = otn->ds_list[PLUGIN_TCP_WIN_CHECK];
#endif
}



/****************************************************************************
 * 
 * Function: ParseTcpWin(char *, OptTreeNode *)
 *
 * Purpose: Convert the tos option argument to data and plug it into the 
 *          data structure
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
void ParseTcpWin(char *data, OptTreeNode *otn)
{
    TcpWinCheckData *ds_ptr;  /* data struct pointer */
#ifdef DETECTION_OPTION_TREE
    void *ds_ptr_dup;
#endif
    u_int16_t win_size;

    /* set the ds pointer to make it easier to reference the option's
       particular data struct */
    ds_ptr = otn->ds_list[PLUGIN_TCP_WIN_CHECK];

    /* get rid of any whitespace */
    while(isspace((int)*data))
    {
        data++;
    }

    if(data[0] == '!')
    {
        ds_ptr->not_flag = 1;
    }

    if(index(data, (int) 'x') == NULL && index(data, (int)'X') == NULL)
    {
        win_size = atoi(data);
    }
    else
    {
        if(index(data,(int)'x'))
        {
            win_size = (u_int16_t) strtol((index(data, (int)'x')+1), NULL, 16);
        }
        else
        {
            win_size = (u_int16_t) strtol((index(data, (int)'X')+1), NULL, 16);
        }
    }

    ds_ptr->tcp_win = htons(win_size);

#ifdef DEBUG
    printf("TCP Window set to 0x%X\n", ds_ptr->tcp_win);
#endif

#ifdef DETECTION_OPTION_TREE
    if (add_detection_option(RULE_OPTION_TYPE_TCP_WIN, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
    {
        otn->ds_list[PLUGIN_TCP_WIN_CHECK] = ds_ptr_dup;
        free(ds_ptr);
    }
#endif /* DETECTION_OPTION_TREE */
}


/****************************************************************************
 * 
 * Function: TcpWinCheckEq(char *, OptTreeNode *)
 *
 * Purpose: Test the TCP header's window to see if its value is equal to the
 *          value in the rule.  
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
#ifdef DETECTION_OPTION_TREE
int TcpWinCheckEq(void *option_data, Packet *p)
{
    TcpWinCheckData *tcpWinCheckData = (TcpWinCheckData *)option_data;
    int rval = DETECTION_OPTION_NO_MATCH;
    PROFILE_VARS;

    if(!p->tcph)
        return rval; /* if error occured while ip header
                   * was processed, return 0 automagically.  */

    PREPROC_PROFILE_START(tcpWinPerfStats);

    if((tcpWinCheckData->tcp_win == p->tcph->th_win) ^ (tcpWinCheckData->not_flag))
    {
        rval = DETECTION_OPTION_MATCH;
    }
#ifdef DEBUG
    else
    {
        /* you can put debug comments here or not */
        DebugMessage(DEBUG_PLUGIN,"No match\n");
    }
#endif

    /* if the test isn't successful, return 0 */
    PREPROC_PROFILE_END(tcpWinPerfStats);
    return rval;
}
#else
int TcpWinCheckEq(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    PROFILE_VARS;

    if(!p->tcph)
        return 0; /* if error occured while ip header
                   * was processed, return 0 automagically.  */

    PREPROC_PROFILE_START(tcpWinPerfStats);

    if((((TcpWinCheckData *)otn->ds_list[PLUGIN_TCP_WIN_CHECK])->tcp_win == p->tcph->th_win) ^ (((TcpWinCheckData *)otn->ds_list[PLUGIN_TCP_WIN_CHECK])->not_flag))
    {
        /* call the next function in the function list recursively */
        PREPROC_PROFILE_END(tcpWinPerfStats);
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }
#ifdef DEBUG
    else
    {
        /* you can put debug comments here or not */
        DebugMessage(DEBUG_PLUGIN,"No match\n");
    }
#endif

    /* if the test isn't successful, return 0 */
    PREPROC_PROFILE_END(tcpWinPerfStats);
    return 0;
}
#endif
