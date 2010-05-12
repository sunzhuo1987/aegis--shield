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
 
#ifndef _FLOW_HASH_H
#define _FLOW_HASH_H

#include "sfhashfcn.h"
#include "flow.h"

/**
 * @file   flow_hash.h
 * @author Chris Green <cmg@sourcefire.com>
 * @date   Thu Jun 19 11:42:49 2003
 * 
 * @brief  hash function for FLOW keys
 * 
 * We can save a bit of work in the hash stage by having a hash
 * function that understands FLOWS better than hash(sizeof(FLOWKEY))
 */

unsigned flowkey_hashfcn1( SFHASHFCN * p, unsigned char * d, int n);
unsigned flowkey_hashfcn2( SFHASHFCN * p, unsigned char * d, int n);

#endif /* _FLOW_HASH_H */
