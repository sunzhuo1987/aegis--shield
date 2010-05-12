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

#ifndef __SP_PATTERN_MATCH_H__
#define __SP_PATTERN_MATCH_H__

#include "snort.h"
#include "debug.h"
#include "rules.h" /* needed for OptTreeNode defintion */
#include <ctype.h>

#ifdef DETECTION_OPTION_TREE
#define CHECK_AND_PATTERN_MATCH 1
#define CHECK_URI_PATTERN_MATCH 2
#endif

#define HTTP_SEARCH_URI 0x01
#define HTTP_SEARCH_HEADER 0x02
#define HTTP_SEARCH_CLIENT_BODY 0x04
#define HTTP_SEARCH_METHOD 0x08
#define HTTP_SEARCH_COOKIE 0x10

/* Flags */
#define CONTENT_FAST_PATTERN 0x01

typedef struct _PatternMatchData
{
    u_int8_t exception_flag; /* search for "not this pattern" */
    int offset;             /* pattern search start offset */
    int depth;              /* pattern search depth */

    int distance;           /* offset to start from based on last match */
    int within;             /* this pattern must be found 
                               within X bytes of last match*/
    int rawbytes;           /* Search the raw bytes rather than any decoded app
                               buffer */

    int nocase;             /* Toggle case insensitity */
    int use_doe;            /* Use the doe_ptr for relative pattern searching */
    int uri_buffer;         /* Index of the URI buffer */
#ifdef DETECTION_OPTION_TREE
    int buffer_func;        /* buffer function CheckAND or CheckUri */
#endif
    u_int pattern_size;     /* size of app layer pattern */
    u_int replace_size;     /* size of app layter replace pattern */
    char *replace_buf;      /* app layer pattern to replace with */
    char *pattern_buf;      /* app layer pattern to match on */
    int (*search)(const char *, int, struct _PatternMatchData *);  /* search function */
    int *skip_stride; /* B-M skip array */
    int *shift_stride; /* B-M shift array */
    u_int pattern_max_jump_size; /* Maximum distance we can jump to search for
                                  * this pattern again. */
    struct _PatternMatchData *next; /* ptr to next match struct */
    int flags;              /* flags */
    OptFpList *fpl;         /* Pointer to the OTN FPList for this pattern */
                            /* Needed to be able to set the isRelative flag */
} PatternMatchData;

void SetupPatternMatch(void);
int SetUseDoePtr(OptTreeNode *otn);
#ifdef DETECTION_OPTION_TREE
void PatternMatchFree(void *d);
u_int32_t PatternMatchHash(void *d);
int PatternMatchCompare(void *l, void *r);
void FinalizeContentUniqueness(OptTreeNode *otn);
void PatternMatchDuplicatePmd(void *src, PatternMatchData *pmd_dup);
int PatternMatchAdjustRelativeOffsets(PatternMatchData *pmd, const u_int8_t *orig_doe_ptr, const u_int8_t *start_doe_ptr, const u_int8_t *dp);
#endif
int PatternMatchUriBuffer(void *p);

#endif /* __SP_PATTERN_MATCH_H__ */
