/* $Id$ */
/****************************************************************************
 *
 * Copyright (C) 2004-2008 Sourcefire, Inc.
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
 
/* flowbits detection plugin header */

#ifndef __SP_FLOWBITS_H__
#define __SP_FLOWBITS_H__

#include "stream_api.h"
#include "sfghash.h"

/* Normally exported functions, for plugin registration. */
void SetupFlowBits();
void FlowBitsVerify();
#ifdef DETECTION_OPTION_TREE
void FlowBitsFree(void *d);
u_int32_t FlowBitsHash(void *d);
int FlowBitsCompare(void *l, void *r);
#endif

/* These functions are now exported to be used by dynamic plugins */
StreamFlowData *GetFlowbitsData(Packet *p);

/**
**  The FLOWBITS_OBJECT is used to track the different
**  flowbit names that set/unset/etc. bits.  We use these
**  so that we can verify that the rules that use flowbits
**  make sense.
**
**  The types element tracks all the different operations that
**  may occur for a given object.  This is different from how
**  the type element is used from the FLOWBITS_ITEM structure.
*/
typedef struct _FLOWBITS_OBJECT
{
    u_int32_t id;
    u_int8_t  types;
} FLOWBITS_OBJECT;

#define FLOWBITS_SET       0x01  
#define FLOWBITS_UNSET     0x02
#define FLOWBITS_TOGGLE    0x04
#define FLOWBITS_ISSET     0x08
#define FLOWBITS_ISNOTSET  0x10
#define FLOWBITS_RESET     0x20
#define FLOWBITS_NOALERT   0x40

extern u_int32_t flowbits_count;
extern SFGHASH *flowbits_hash;
extern unsigned int giFlowbitSize;

#endif  /* __SP_FLOWBITS_H__ */
