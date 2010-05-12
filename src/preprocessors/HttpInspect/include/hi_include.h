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
 
#ifndef __HI_INCLUDE_H__
#define __HI_INCLUDE_H__

#include "sf_types.h"
#include "debug.h"
#include "ipv6_port.h"

#define HI_UNKNOWN_METHOD 1
#define HI_POST_METHOD 2
#define HI_GET_METHOD 4

typedef struct _hi_stats {
    UINT64 unicode;
    UINT64 double_unicode;
    UINT64 non_ascii;        /* Non ASCII-representable character in URL */
    UINT64 base36;
    UINT64 dir_trav;         /* '../' */
    UINT64 slashes;          /* '//' */
    UINT64 self_ref;         /* './' */
    UINT64 post;             /* Number of POST methods encountered */
    UINT64 get;              /* Number of GETs */
    UINT64 post_params;      /* Number of successfully extract post parameters */
    UINT64 headers;          /* Number of successfully extracted headers */
#ifdef DEBUG
    UINT64 header_len;
#endif
    UINT64 cookies;          /* Number of successfully extracted cookies */
#ifdef DEBUG
    UINT64 cookie_len;
#endif
    UINT64 total;
} HIStats;

extern HIStats hi_stats;

#ifndef INLINE

#ifdef WIN32
#define INLINE __inline
#else
#define INLINE inline
#endif

#endif /* endif for INLINE */
#endif
