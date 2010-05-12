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
#ifndef __LOG_H__
#define __LOG_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <syslog.h>

#include "event.h"
#include "decode.h"

#if defined (SUNOS) || defined (SOLARIS) || defined (HPUX) || defined (IRIX) \
|| defined (AIX) || defined (OSF1)
    #define LOG_AUTHPRIV LOG_AUTH
#endif

#ifndef LOG_AUTHPRIV
    #define LOG_AUTHPRIV LOG_AUTH
#endif

#define FRAME_SIZE        66
#define C_OFFSET          49

/*  P R O T O T Y P E S  ******************************************************/


void PrintIPPkt(FILE *, int,Packet*);
void PrintEapolPkt(FILE *, Packet *);
void PrintEapolKey(FILE *, Packet *);
void PrintNetData(FILE *, const u_char *, const int);
void ClearDumpBuf();
void Print2ndHeader(FILE *, Packet *);
void PrintWifiPkt(FILE *, Packet *);
void PrintTrHeader(FILE *, Packet *);
void PrintEthHeader(FILE *, Packet *);
#ifdef MPLS
void PrintMPLSHeader(FILE *, Packet *);
#endif
void PrintWifiHeader(FILE *, Packet *);
void PrintSLLHeader(FILE *, Packet *);
void PrintArpHeader(FILE *, Packet *);
void PrintIPHeader(FILE *, Packet *);
void PrintEapolHeader(FILE *, Packet *);
void PrintTCPHeader(FILE *, Packet *);
void PrintTcpOptions(FILE *, Packet *);
void PrintIpOptions(FILE *, Packet *);
void PrintICMPHeader(FILE *, Packet *);
void PrintICMPEmbeddedIP(FILE *, Packet *);
void PrintEmbeddedICMPHeader(FILE *, const ICMPHdr *);
void PrintUDPHeader(FILE *, Packet *);
void PrintEAPHeader(FILE *, Packet *);
void PrintPriorityData(FILE *, int);
void PrintXrefs(FILE *, int);
void CreateTCPFlagString(Packet *, char *);

void NoLog(Packet *, char *, void *, Event *);
void NoAlert(Packet *, char *, void *, Event *);
FILE *OpenAlertFile(const char *);
int RollAlertFile(const char *);

#ifndef WIN32
void SetEvent(Event *, u_int32_t, u_int32_t, u_int32_t, u_int32_t, u_int32_t, 
        u_int32_t); 
#else
/* There is a naming conflict with a Win32 standard function, so compensate */
#define SetEvent SnortSetEvent
void SnortSetEvent(Event *, u_int32_t, u_int32_t, u_int32_t, u_int32_t, 
        u_int32_t, u_int32_t); 
#endif

#endif /* __LOG_H__ */

