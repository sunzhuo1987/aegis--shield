/*
** Copyright (C) 2007-2008 Sourcefire, Inc.
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

/*
 * Adam Keeton
 * spp_ssl.h
 * 10/10/07
 */

#ifndef SPP_SSLPP_H
#define SPP_SSLPP_H

#include "sf_types.h"
#include "sfcommon.h"
#include "ssl.h"

/* Prototypes for public interface */
extern void SetupSSLPP(void);

/* Configuration flags */
#define SSLPP_DISABLE_FLAG    0x0001 
#define SSLPP_TRUSTSERVER_FLAG  0x0002

typedef struct _SSLPP_config 
{
    ports_tbl_t ports;
    u_int16_t flags;

} SSLPP_config_t;

typedef struct _SSLPP_counters
{
    UINT64 stopped;
    UINT64 disabled;
    UINT64 decoded;
    UINT64 alerts;
    UINT64 cipher_change;
    UINT64 unrecognized;
    UINT64 completed_hs;
    UINT64 bad_handshakes;
    UINT64 hs_chello;
    UINT64 hs_shello;
    UINT64 hs_cert;
    UINT64 hs_skey;
    UINT64 hs_ckey;
    UINT64 hs_finished;
    UINT64 hs_sdone;
    UINT64 capp;
    UINT64 sapp;

} SSLPP_counters_t;

#define SSLPP_TRUE 1
#define SSLPP_FALSE 0

#define SSLPP_ENCRYPTED_FLAGS (SSL_HS_SDONE_FLAG | SSL_CLIENT_KEYX_FLAG | \
                               SSL_CAPP_FLAG | SSL_SAPP_FLAG)
#define SSLPP_ENCRYPTED_FLAGS2 (SSL_HS_SDONE_FLAG | SSL_CHANGE_CIPHER_FLAG | \
                                SSL_CAPP_FLAG | SSL_SAPP_FLAG)
    
#endif /* SPP_SSLPP_H */
