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

#ifndef __SP_IP_PROTO_H__
#define __SP_IP_PROTO_H__


#define GREATER_THAN            1
#define LESS_THAN               2

typedef struct _IpProtoData
{
    u_int8_t protocol;
    u_int8_t not_flag;
    u_int8_t comparison_flag;

} IpProtoData;

void SetupIpProto(void);
#ifdef DETECTION_OPTION_TREE
u_int32_t IpProtoCheckHash(void *d);
int IpProtoCheckCompare(void *l, void *r);
#endif

#endif  /* __SP_IP_PROTO_H__ */
