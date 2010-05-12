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
 
/**
 * @file   common_defs.h
 * @author Chris Green <cmg@sourcefire.com>
 * @date   Fri Jun 20 15:47:49 2003
 * 
 * @brief  common include stuff I use all the time
 * 
 * 
 */

#ifndef _COMMON_DEFS_H
#define _COMMON_DEFS_H

#include "debug.h"
#ifndef DEBUG
    #define FLOWASSERT(a)  
#else
    #include <assert.h>
    #define FLOWASSERT(a) assert(a)
#endif /* DEBUG */

#define ONE_MBYTE (1024 * 1024)
#define ONE_HOUR  3600

#define FULLBITS 0xFFFFFFFF

#ifndef IP_MAXPACKET
#define IP_MAXPACKET 65535
#endif

#ifndef WIN32
/* for inet_ntoa */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* WIN32 */

#endif /* _COMMON_DEFS_H */
