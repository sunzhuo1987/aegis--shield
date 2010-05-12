/*
** Copyright (C) 2005-2008 Sourcefire, Inc.
** Author: Steven Sturges <ssturges@sourcefire.com>
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

#ifndef __PROFILER_H__
#define __PROFILER_H__

#ifdef PERF_PROFILING

#include "sf_types.h"
#include "cpuclock.h"

/* Sort preferences for rule profiling */
#define PROFILE_SORT_CHECKS 1
#define PROFILE_SORT_MATCHES 2
#define PROFILE_SORT_NOMATCHES 3
#define PROFILE_SORT_AVG_TICKS 4
#define PROFILE_SORT_AVG_TICKS_PER_MATCH 5
#define PROFILE_SORT_AVG_TICKS_PER_NOMATCH 6
#define PROFILE_SORT_TOTAL_TICKS 7

/* MACROS that handle profiling of rules and preprocessors */
#define PROFILE_VARS UINT64 ticks_start = 0, ticks_end = 0, ticks_delta

#define PROFILE_START \
    get_clockticks(ticks_start);

#define PROFILE_END \
    get_clockticks(ticks_end); \
    ticks_delta = ticks_end - ticks_start;

#ifndef PROFILING_RULES
#define PROFILING_RULES pv.profile_rules_flag
#endif

#ifdef DETECTION_OPTION_TREE
#define NODE_PROFILE_START(node) \
    if (PROFILING_RULES) { \
        node->checks++; \
        PROFILE_START; \
        node->ticks_start = ticks_start; \
    }

#define NODE_PROFILE_END_MATCH(node) \
    if (PROFILING_RULES) { \
        PROFILE_END; \
        node->ticks += ticks_end - node->ticks_start; \
        node->ticks_match += ticks_end - node->ticks_start; \
    }

#define NODE_PROFILE_END_NOMATCH(node) \
    if (PROFILING_RULES) { \
        PROFILE_END; \
        node->ticks += ticks_end - node->ticks_start; \
        node->ticks_no_match += ticks_end - node->ticks_start; \
    }

#define NODE_PROFILE_TMPSTART(node) \
    if (PROFILING_RULES) { \
        PROFILE_START; \
        node->ticks_start = ticks_start; \
    }

#define NODE_PROFILE_TMPEND(node) \
    if (PROFILING_RULES) { \
        PROFILE_END; \
        node->ticks += ticks_end - node->ticks_start; \
    }

#else
#define OTN_PROFILE_START(otn) \
    if (PROFILING_RULES) { \
        otn->checks++; \
        PROFILE_START; \
    }

#define OTN_PROFILE_END_MATCH(otn) \
    if (PROFILING_RULES) { \
        PROFILE_END; \
        otn->ticks += ticks_delta; \
        otn->ticks_match += ticks_delta; \
        otn->matches++; \
    }

#define OTN_PROFILE_NOALERT(otn) \
    if (PROFILING_RULES) { \
        otn->noalerts=1; \
    }

#define OTN_PROFILE_END_NOMATCH(otn) \
    if (PROFILING_RULES) { \
        PROFILE_END; \
        otn->ticks += ticks_delta; \
        otn->ticks_no_match += ticks_delta; \
    }
#endif

#define OTN_PROFILE_ALERT(otn) otn->alerts++;

#ifndef PROFILING_PREPROCS
#define PROFILING_PREPROCS pv.profile_preprocs_flag
#endif

#define PREPROC_PROFILE_START(ppstat) \
    if (PROFILING_PREPROCS) { \
        ppstat.checks++; \
        PROFILE_START; \
        ppstat.ticks_start = ticks_start; \
    } 

#define PREPROC_PROFILE_REENTER_START(ppstat) \
    if (PROFILING_PREPROCS) { \
        PROFILE_START; \
        ppstat.ticks_start = ticks_start; \
    } 

#define PREPROC_PROFILE_TMPSTART(ppstat) \
    if (PROFILING_PREPROCS) { \
        PROFILE_START; \
        ppstat.ticks_start = ticks_start; \
    } 

#define PREPROC_PROFILE_END(ppstat) \
    if (PROFILING_PREPROCS) { \
        PROFILE_END; \
        ppstat.exits++; \
        ppstat.ticks += ticks_end - ppstat.ticks_start; \
    } 

#define PREPROC_PROFILE_REENTER_END(ppstat) \
    if (PROFILING_PREPROCS) { \
        PROFILE_END; \
        ppstat.ticks += ticks_end - ppstat.ticks_start; \
    } 

#define PREPROC_PROFILE_TMPEND(ppstat) \
    if (PROFILING_PREPROCS) { \
        PROFILE_END; \
        ppstat.ticks += ticks_end - ppstat.ticks_start; \
    } 

/************** Profiling API ******************/
void ShowRuleProfiles(void);

/* Preprocessor stats info */
typedef struct _PreprocStats
{
    UINT64 ticks, ticks_start;
    UINT64 checks;
    UINT64 exits;
} PreprocStats;

typedef struct _PreprocStatsNode
{
    PreprocStats *stats;
    char *name;
    int layer;
    PreprocStats *parent;
    struct _PreprocStatsNode *next;
} PreprocStatsNode;

void RegisterPreprocessorProfile(char *keyword, PreprocStats *stats, int layer, PreprocStats *parent);
void ShowPreprocProfiles(void);
void ResetRuleProfiling(void);
void ResetPreprocProfiling(void);
extern PreprocStats totalPerfStats;
#else
#define PROFILE_VARS
#ifdef DETECTION_OPTION_TREE
#define NODE_PROFILE_START(node)
#define NODE_PROFILE_END_MATCH(node)
#define NODE_PROFILE_END_NOMATCH(node)
#define NODE_PROFILE_TMPSTART(node)
#define NODE_PROFILE_TMPEND(node)
#else
#define OTN_PROFILE_START(otn)
#define OTN_PROFILE_END_MATCH(otn)
#define OTN_PROFILE_END_NOMATCH(otn)
#define OTN_PROFILE_NOALERT(otn)
#endif
#define OTN_PROFILE_ALERT(otn)
#define PREPROC_PROFILE_START(ppstat)
#define PREPROC_PROFILE_REENTER_START(ppstat)
#define PREPROC_PROFILE_TMPSTART(ppstat)
#define PREPROC_PROFILE_END(ppstat)
#define PREPROC_PROFILE_REENTER_END(ppstat)
#define PREPROC_PROFILE_TMPEND(ppstat)
#endif

#endif  /* __PROFILER_H__ */
