/* $Id */
/*  
** Copyright (C) 2005-2008 Sourcefire, Inc.
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
** along with this program; if nto, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Bosotn, MA 02111-1307, USA.
*/

/*
 * sp_urilen_check.c: Detection plugin to expose URI length to 
 * 			user rules.
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

#include "sp_urilen_check.h"

#include "snort.h"
#include "profiler.h"
#ifdef PERF_PROFILING
#ifdef DETECTION_OPTION_TREE
PreprocStats urilenCheckPerfStats;
#else
PreprocStats urilenEQPerfStats;
PreprocStats urilenGTPerfStats;
PreprocStats urilenLTPerfStats;
PreprocStats urilenRangePerfStats;
#endif
extern PreprocStats ruleOTNEvalPerfStats;
#endif

#ifdef DETECTION_OPTION_TREE
#include "sfhashfcn.h"
#include "detection_options.h"
#endif /* DETECTION_OPTION_TREE */

extern HttpUri UriBufs[URI_COUNT];

void UriLenCheckInit( char*, OptTreeNode*, int );
void ParseUriLen( char*, OptTreeNode* );
#ifdef DETECTION_OPTION_TREE
int CheckUriLen(void *option_data, Packet*p);
#else
int CheckUriLenGT(Packet*, struct _OptTreeNode*, OptFpList*);
int CheckUriLenLT(Packet*, struct _OptTreeNode*, OptFpList*);
int CheckUriLenEQ(Packet*, struct _OptTreeNode*, OptFpList*);
int CheckUriLenRange(Packet*, struct _OptTreeNode*, OptFpList*);
#endif

#ifdef DETECTION_OPTION_TREE
u_int32_t UriLenCheckHash(void *d)
{
    u_int32_t a,b,c;
    UriLenCheckData *data = (UriLenCheckData *)d;

    a = data->urilen;
    b = data->urilen2;
    c = data->oper;

    mix(a,b,c);

    a += RULE_OPTION_TYPE_URILEN;

    final(a,b,c);

    return c;
}

int UriLenCheckCompare(void *l, void *r)
{
    UriLenCheckData *left = (UriLenCheckData *)l;
    UriLenCheckData *right = (UriLenCheckData *)r;

    if (!left || !right)
        return DETECTION_OPTION_NOT_EQUAL;

    if ((left->urilen == right->urilen) &&
        (left->urilen2 == right->urilen2) &&
        (left->oper == right->oper))
    {
        return DETECTION_OPTION_EQUAL;
    }

    return DETECTION_OPTION_NOT_EQUAL;
}
#endif /* DETECTION_OPTION_TREE */


/* Called from plugbase to register any detection plugin keywords.
* 
 * PARAMETERS:	None.
 *
 * RETURNS:	Nothing.
 */
void 
SetupUriLenCheck()
{
	RegisterPlugin("urilen", UriLenCheckInit, OPT_TYPE_DETECTION);
#ifdef PERF_PROFILING
#ifdef DETECTION_OPTION_TREE
    RegisterPreprocessorProfile("urilen_check", &urilenCheckPerfStats, 3, &ruleOTNEvalPerfStats);
#else
    RegisterPreprocessorProfile("urilen_eq", &urilenEQPerfStats, 3, &ruleOTNEvalPerfStats);
    RegisterPreprocessorProfile("urilen_gt", &urilenGTPerfStats, 3, &ruleOTNEvalPerfStats);
    RegisterPreprocessorProfile("urilen_lt", &urilenLTPerfStats, 3, &ruleOTNEvalPerfStats);
    RegisterPreprocessorProfile("urilen_range", &urilenRangePerfStats, 3, &ruleOTNEvalPerfStats);
#endif
#endif
}

/* Parses the urilen rule arguments and attaches info to 
 * the rule data structure for later use. Attaches detection
 * function to OTN function list.
 * 
 * PARAMETERS: 
 *
 * argp:	Rule arguments
 * otnp:  	Pointer to the current rule option list node
 * protocol:    Pointer specified for the rule currently being parsed	
 *
 * RETURNS:	Nothing.
 */
void 
UriLenCheckInit( char* argp, OptTreeNode* otnp, int protocol )
{
	/* Sanity check(s) */
	if ( !otnp )
		return;

	/* Check if there have been multiple urilen options specified
 	 * in the same rule.
	 */
	if ( otnp->ds_list[PLUGIN_URILEN_CHECK] )
	{
		FatalError("%s(%d): Multiple urilen options in rule\n",
			file_name, file_line );
	}

	otnp->ds_list[PLUGIN_URILEN_CHECK] = 
		(UriLenCheckData*) SnortAlloc(sizeof(UriLenCheckData));

	ParseUriLen( argp, otnp );

}

/* Parses the urilen rule arguments and attaches the resulting
 * parameters to the rule data structure. Based on arguments, 
 * attaches the appropriate callback/processing function
 * to be used when the OTN is evaluated.
 *
 * PARAMETERS:
 *
 * argp:	Pointer to string containing the arguments to be
 *		parsed.
 * otnp:	Pointer to the current rule option list node.
 *
 * RETURNS:	Nothing.
 */
void
ParseUriLen( char* argp, OptTreeNode* otnp )
{
    OptFpList *fpl;
	UriLenCheckData* datap = NULL;
#ifdef DETECTION_OPTION_TREE
    void *datap_dup;
#endif
	char* curp = NULL; 
 	char* cur_tokenp = NULL;
	char* endp = NULL;
	int val;

	/* Get the Urilen parameter block */
	datap = (UriLenCheckData*) 
			otnp->ds_list[PLUGIN_URILEN_CHECK];

	curp = argp;

	while(isspace((int)*curp)) 
		curp++;

	/* Parse the string */
	if(isdigit((int)*curp) && strchr(curp, '<') && strchr(curp, '>'))
	{
		cur_tokenp = strtok(curp, " <>");
		if(!cur_tokenp)
		{
			FatalError("%s(%d): Invalid 'urilen' argument.\n",
	       			file_name, file_line);
		}

		val = strtol(cur_tokenp, &endp, 10);
		if(val < 0 || *endp)
		{
			FatalError("%s(%d): Invalid 'urilen' argument.\n",
	       			file_name, file_line);
		}

		datap->urilen = (unsigned short)val;

		cur_tokenp = strtok(NULL, " <>");
		if(!cur_tokenp)
		{
			FatalError("%s(%d): Invalid 'urilen' argument.\n",
	       			file_name, file_line);
		}

		val = strtol(cur_tokenp, &endp, 10);
		if(val < 0 || *endp)
		{
			FatalError("%s(%d): Invalid 'urilen' argument.\n",
	       			file_name, file_line);
		}

		datap->urilen2 = (unsigned short)val;
#ifdef DETECTION_OPTION_TREE
		fpl = AddOptFuncToList(CheckUriLen, otnp );
#else
		fpl = AddOptFuncToList(CheckUriLenRange, otnp );
#endif
        datap->oper = URILEN_CHECK_RG;
#ifdef DETECTION_OPTION_TREE
        if (add_detection_option(RULE_OPTION_TYPE_URILEN, (void *)datap, &datap_dup) == DETECTION_OPTION_EQUAL)
        {
            otnp->ds_list[PLUGIN_URILEN_CHECK] = datap_dup;
            free(datap);
        }
        fpl->type = RULE_OPTION_TYPE_URILEN;
        fpl->context = otnp->ds_list[PLUGIN_URILEN_CHECK];
#endif /* DETECTION_OPTION_TREE */

		return;
	}
	else if(*curp == '>')
	{
		curp++;
#ifdef DETECTION_OPTION_TREE
		fpl = AddOptFuncToList(CheckUriLen, otnp );
#else
		fpl = AddOptFuncToList(CheckUriLenGT, otnp);
#endif
        datap->oper = URILEN_CHECK_GT;
	}
	else if(*curp == '<')
	{
		curp++;
#ifdef DETECTION_OPTION_TREE
		fpl = AddOptFuncToList(CheckUriLen, otnp );
#else
		fpl = AddOptFuncToList(CheckUriLenLT, otnp);
#endif
        datap->oper = URILEN_CHECK_LT;
	}
	else
	{
#ifdef DETECTION_OPTION_TREE
		fpl = AddOptFuncToList(CheckUriLen, otnp );
#else
		fpl = AddOptFuncToList(CheckUriLenEQ, otnp);
#endif
        datap->oper = URILEN_CHECK_EQ;
	}

	while(isspace((int)*curp)) curp++;

	val = strtol(curp, &endp, 10);
	if(val < 0 || *endp)
	{
		FatalError("%s(%d): Invalid 'urilen' argument.\n",
	   		file_name, file_line);
	}

	datap->urilen = (unsigned short)val;
#ifdef DETECTION_OPTION_TREE
    if (add_detection_option(RULE_OPTION_TYPE_URILEN, (void *)datap, &datap_dup) == DETECTION_OPTION_EQUAL)
    {
        otnp->ds_list[PLUGIN_URILEN_CHECK] = datap_dup;
        free(datap);
    }
    fpl->type = RULE_OPTION_TYPE_URILEN;
    fpl->context = otnp->ds_list[PLUGIN_URILEN_CHECK];
#endif /* DETECTION_OPTION_TREE */
}

#ifdef DETECTION_OPTION_TREE
int 
CheckUriLen(void *option_data, Packet *p)
{
    UriLenCheckData *urilenCheckData = (UriLenCheckData *)option_data;
    int rval = DETECTION_OPTION_NO_MATCH;
    PROFILE_VARS;

    PREPROC_PROFILE_START(urilenCheckPerfStats);

    if ((p->packet_flags & PKT_REBUILT_STREAM) || ( !UriBufs[0].uri  ))
    {
        PREPROC_PROFILE_END(urilenCheckPerfStats);
        return rval;
    }

    switch (urilenCheckData->oper)
    {
        case URILEN_CHECK_EQ:
            if (urilenCheckData->urilen == UriBufs[0].length )
                rval = DETECTION_OPTION_MATCH;
            break;
        case URILEN_CHECK_GT:
            if (urilenCheckData->urilen < UriBufs[0].length )
                rval = DETECTION_OPTION_MATCH;
            break;
        case URILEN_CHECK_LT:
            if (urilenCheckData->urilen > UriBufs[0].length )
                rval = DETECTION_OPTION_MATCH;
            break;
        case URILEN_CHECK_RG:
            if ((urilenCheckData->urilen <= UriBufs[0].length ) &&
                (urilenCheckData->urilen2 >= UriBufs[0].length ))
                rval = DETECTION_OPTION_MATCH;
            break;
        default:
            break;
    }

    /* if the test isn't successful, return 0 */
    PREPROC_PROFILE_END(urilenCheckPerfStats);
    return rval;
}
#else
/* Checks the current packet for match against the Uri Len rule. 
 * 
 * PARAMETERS:
 *
 * p:		Pointer to the packet currently being inspected.
 * otn: 	Rule node
 * fp_list: 	Detection plugin callback funcs list.
 *  
 * RETURNS:	Result of a recursive call if current node matches,
 *		0 otherwise (no match)
 */
int 
CheckUriLenEQ(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(urilenEQPerfStats);

    if ((p->packet_flags & PKT_REBUILT_STREAM) || ( !UriBufs[0].uri  ))
    {
        PREPROC_PROFILE_END(urilenEQPerfStats);
        return 0;
    }

    if(((UriLenCheckData *)otn->ds_list[PLUGIN_URILEN_CHECK])->urilen == 
		UriBufs[0].length )
    {
        /* call the next function in the function list recursively */
        PREPROC_PROFILE_END(urilenEQPerfStats);
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }

    /* if the test isn't successful, return 0 */
    PREPROC_PROFILE_END(urilenEQPerfStats);
    return 0;
}

/* Checks the current packet for match against the Uri Len rule. 
 * 
 * PARAMETERS:
 *
 * p:		Pointer to the packet currently being inspected.
 * otn: 	Rule node
 * fp_list: 	Detection plugin callback funcs list.
 *  
 * RETURNS:	Result of a recursive call if current node matches,
 *		0 otherwise(no match)
 */
int 
CheckUriLenGT(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(urilenGTPerfStats);

    if ((p->packet_flags & PKT_REBUILT_STREAM) || ( !UriBufs[0].uri ))
    {
        PREPROC_PROFILE_END(urilenGTPerfStats);
        return 0;
    }

    if(((UriLenCheckData *)otn->ds_list[PLUGIN_URILEN_CHECK])->urilen < 
		UriBufs[0].length )
    {
        /* call the next function in the function list recursively */
        PREPROC_PROFILE_END(urilenGTPerfStats);
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }

    /* if the test isn't successful, return 0 */
    PREPROC_PROFILE_END(urilenGTPerfStats);
    return 0;
}
 
/* Checks the current packet for match against the Uri Len rule. 
 * 
 * PARAMETERS:
 *
 * p:		Pointer to the packet currently being inspected.
 * otn: 	Rule node
 * fp_list: 	Detection plugin callback funcs list.
 *  
 * RETURNS:	Result of a recursive call if current node matches,
 *		0 otherwise (no match)
 */
int 
CheckUriLenLT(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(urilenLTPerfStats);

    if ((p->packet_flags & PKT_REBUILT_STREAM) || ( !UriBufs[0].uri ))
    {
        PREPROC_PROFILE_END(urilenLTPerfStats);
        return 0;
    }

    if(((UriLenCheckData *)otn->ds_list[PLUGIN_URILEN_CHECK])->urilen > 
		UriBufs[0].length )
    {
        /* call the next function in the function list recursively */
        PREPROC_PROFILE_END(urilenLTPerfStats);
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }

    /* if the test isn't successful, return 0 */
    PREPROC_PROFILE_END(urilenLTPerfStats);
    return 0;
}

/* Checks the current packet for match against the Uri Len rule. 
 * 
 * PARAMETERS:
 *
 * p:		Pointer to the packet currently being inspected.
 * otn: 	Rule node
 * fp_list: 	Detection plugin callback funcs list.
 *  
 * RETURNS:	Result of a recursive call if current node matches,
 *		0 otherwise (no match)
 */
int 
CheckUriLenRange(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    PROFILE_VARS;

    PREPROC_PROFILE_START(urilenRangePerfStats);

    if ((p->packet_flags & PKT_REBUILT_STREAM) || ( !UriBufs[0].uri ))
    {
        PREPROC_PROFILE_END(urilenRangePerfStats);
        return 0;
    }

    if(((UriLenCheckData *)otn->ds_list[PLUGIN_URILEN_CHECK])->urilen <= 
		UriBufs[0].length &&
     ((UriLenCheckData *)otn->ds_list[PLUGIN_URILEN_CHECK])->urilen2 >= 
		UriBufs[0].length )
    {
        /* call the next function in the function list recursively */
        PREPROC_PROFILE_END(urilenRangePerfStats);
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }

    PREPROC_PROFILE_END(urilenRangePerfStats);
    return 0;
}
#endif
