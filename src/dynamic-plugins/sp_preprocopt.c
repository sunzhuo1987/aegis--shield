/* $Id$ */
/*
 * sp_preprocopt.c
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
 *      Supports preprocessor defined rule options.
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
 *      Returns 1 if the option matches, 0 if it doesn't.
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

#include "plugbase.h"
#include "rules.h"

#include "debug.h"
#include "util.h"

#include "sf_dynamic_engine.h"

#include "sfghash.h"
#include "sfhashfcn.h"

#include "snort.h"
#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats preprocRuleOptionPerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif

SFGHASH *preprocRulesOptions = NULL;

extern const u_int8_t *doe_ptr;


typedef struct _PreprocessorOptionInfo
{
    PreprocOptionInit optionInit;
    PreprocOptionEval optionEval;
    PreprocOptionCleanup optionCleanup;
    void             *data;
} PreprocessorOptionInfo;

void PreprocessorRuleOptionsInit()
{
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("preproc_rule_options", &preprocRuleOptionPerfStats, 3, &ruleOTNEvalPerfStats);
#endif
    preprocRulesOptions = sfghash_new(10, 0, 0, free);
}

void PreprocessorRuleOptionsFree()
{
    if (preprocRulesOptions)
    {
        sfghash_delete(preprocRulesOptions);
        preprocRulesOptions = NULL;
    }
}

int RegisterPreprocessorRuleOption(char *optionName, PreprocOptionInit initFunc,
                                   PreprocOptionEval evalFunc,
                                   PreprocOptionCleanup cleanupFunc)
{
    int ret;
    PreprocessorOptionInfo *optionInfo;
    if (!preprocRulesOptions)
    {
        FatalError("Preprocessor Rule Option storage not initialized\n");
    }

    optionInfo = sfghash_find(preprocRulesOptions, optionName);
    if (optionInfo)
    {
        FatalError("Duplicate Preprocessor Rule Option '%s'\n", optionName);
    }

    optionInfo = (PreprocessorOptionInfo *)SnortAlloc(sizeof(PreprocessorOptionInfo));
    optionInfo->optionEval = evalFunc;
    optionInfo->optionInit = initFunc;

    ret = sfghash_add(preprocRulesOptions, optionName, optionInfo);
    if (ret != SFGHASH_OK)
    {
        FatalError("Failed to initialize Preprocessor Rule Option '%s'\n");
    }

    return 0;
}

int GetPreprocessorRuleOptionFuncs(char *optionName, void **initFunc, void **evalFunc)
{
    PreprocessorOptionInfo *optionInfo;
    if (!preprocRulesOptions)
    {
        FatalError("Preprocessor Rule Option storage not initialized\n");
    }

    optionInfo = sfghash_find(preprocRulesOptions, optionName);
    if (!optionInfo)
    {
        return 0;
    }

    *initFunc = (PreprocOptionInit)optionInfo->optionInit;
    *evalFunc = (PreprocOptionEval)optionInfo->optionEval;

    return 1;
}

#ifdef DETECTION_OPTION_TREE
u_int32_t PreprocessorRuleOptionHash(void *d)
{
    u_int32_t a,b,c;
    PreprocessorOptionInfo *option_data = (PreprocessorOptionInfo *)d;
            
#if (defined(__ia64) || defined(__amd64) || defined(_LP64))
    {
        /* Cleanup warning because of cast from 64bit ptr to 32bit int
         * warning on 64bit OSs */
        UINT64 ptr; /* Addresses are 64bits */
        ptr = (UINT64)option_data->data;
        a = (ptr << 32) & 0XFFFFFFFF;
        b = (ptr & 0xFFFFFFFF);
    }
#else
    a = (u_int32_t)option_data->data;
    b = 0;
#endif
    c = RULE_OPTION_TYPE_PREPROCESSOR;

    final(a,b,c);
                                    
    return c;
}

int PreprocessorRuleOptionCompare(void *l, void *r)
{
    PreprocessorOptionInfo *left = (PreprocessorOptionInfo *)l;
    PreprocessorOptionInfo *right = (PreprocessorOptionInfo *)r;
            
    if (!left || !right)
        return DETECTION_OPTION_NOT_EQUAL;
                            
    if (left->data == right->data)
    {
        return DETECTION_OPTION_EQUAL;
    }
                                                        
    return DETECTION_OPTION_NOT_EQUAL;
}

/* Callback function for dynamic preprocessor options */
int PreprocessorOptionFunc(void *option_data, Packet *p)
{
    PreprocessorOptionInfo *optionInfo = (PreprocessorOptionInfo *)option_data;
    const u_int8_t *cursor = NULL;
    int       success;
    PROFILE_VARS;

    PREPROC_PROFILE_START(preprocRuleOptionPerfStats);

    //  Call eval function
    success = optionInfo->optionEval(p, &cursor, optionInfo->data);

    if ( cursor )
        doe_ptr = cursor;

    //  If successful, call next function in chain
    if ( success )
    {
        PREPROC_PROFILE_END(preprocRuleOptionPerfStats);
        return DETECTION_OPTION_MATCH;
    }

    PREPROC_PROFILE_END(preprocRuleOptionPerfStats);
    return DETECTION_OPTION_NO_MATCH;
}
#else
int PreprocessorOptionFunc(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    PreprocessorOptionInfo *optionInfo;
    const u_int8_t *cursor = NULL;
    int       success;
    PROFILE_VARS;

    PREPROC_PROFILE_START(preprocRuleOptionPerfStats);

    optionInfo = (PreprocessorOptionInfo *) fp_list->context;

    //  Call eval function
    success = optionInfo->optionEval(p, &cursor, optionInfo->data);

    if ( cursor )
        doe_ptr = cursor;

    //  If successful, call next function in chain
    if ( success )
    {
        PREPROC_PROFILE_END(preprocRuleOptionPerfStats);
        return fp_list->next->OptTestFunc(p, otn, fp_list->next);
    }

    PREPROC_PROFILE_END(preprocRuleOptionPerfStats);
    return 0;
}
#endif

int AddPreprocessorRuleOption(char *optionName, OptTreeNode *otn, void *data, PreprocOptionEval evalFunc)
{
    OptFpList *fpl;
    PreprocessorOptionInfo *optionInfo;
    PreprocessorOptionInfo *saveOptionInfo;
#ifdef DETECTION_OPTION_TREE
    void *option_dup;
#endif


    optionInfo = sfghash_find(preprocRulesOptions, optionName);
    
    if (!optionInfo)
        return 0;

    saveOptionInfo = (PreprocessorOptionInfo *)SnortAlloc(sizeof(PreprocessorOptionInfo));

    memcpy(saveOptionInfo, optionInfo, sizeof(PreprocessorOptionInfo));

    saveOptionInfo->data = data;

    //  Add to option chain with generic callback
    fpl = AddOptFuncToList(PreprocessorOptionFunc, otn);

    /*
     * attach custom info to the context node so that we can call each instance
     * individually
     */
    fpl->context = (void *) saveOptionInfo;

#ifdef DETECTION_OPTION_TREE
    if (add_detection_option(RULE_OPTION_TYPE_PREPROCESSOR, (void *)saveOptionInfo, &option_dup) == DETECTION_OPTION_EQUAL)
    {
        free(saveOptionInfo);
        fpl->context = saveOptionInfo = option_dup;
    }
    fpl->type = RULE_OPTION_TYPE_PREPROCESSOR;
#endif

    return 1;
}

#endif /* DYNAMIC_PLUGIN */
