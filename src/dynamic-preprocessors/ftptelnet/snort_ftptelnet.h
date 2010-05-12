/*
 * snort_ftptelnet.h
 *
 * Copyright (C) 2004-2008 Sourcefire, Inc.
 * Steven A. Sturges <ssturges@sourcefire.com>
 * Daniel J. Roelker <droelker@sourcefire.com>
 * Marc A. Norton <mnorton@sourcefire.com>
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
 * Description:
 *
 * This file defines the publicly available functions for the FTPTelnet
 * functionality for Snort.
 *
 * NOTES:
 * - 16.09.04:  Initial Development.  SAS
 *
 */
#ifndef __SNORT_FTPTELNET_H__
#define __SNORT_FTPTELNET_H__

#include "ftpp_ui_config.h"
//#include "decode.h"
#include "sf_snort_packet.h"

void FTPTelnetCleanupSnortConf(FTPTELNET_GLOBAL_CONF *GlobalConf);
int FTPTelnetSnortConf(FTPTELNET_GLOBAL_CONF *GlobalConf, char *args,
                         char *ErrorString, int ErrStrLen);
int SnortFTPTelnet(FTPTELNET_GLOBAL_CONF *GlobalConf, SFSnortPacket *p);
void FTPConfigCheck(void);

int FTPPBounceInit(char *name, char *parameters, void **dataPtr);
int FTPPBounceEval(void *p, const u_int8_t **cursor, void *dataPtr);

void FTPTelnetCleanupFTPServerConf(void *serverConf);
void FTPTelnetCleanupFTPCMDConf(void *ftpCmd);
void FTPTelnetCleanupFTPClientConf(void *clientConf);
void FTPTelnetCleanupFTPBounceTo(void *ftpBounce);

#endif
