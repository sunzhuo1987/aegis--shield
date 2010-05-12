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
 
#ifndef SF_THRESHOLD
#define SF_THRESHOLD

#include "sfthd.h"
#include "ipv6_port.h"

void ParseThreshold2( THDX_STRUCT * thdx, char * s );
void ProcessThresholdOptions( char * args);
void ParseSFThreshold( char * rule );
void ParseSFSuppress( char * rule );

int  sfthreshold_init( void );
void sfthreshold_free( void );
void sfthreshold_reset(void);

int  sfthreshold_create( THDX_STRUCT * thdx  );
int  sfthreshold_test( unsigned gen_id,unsigned  sig_id, snort_ip_p sip, snort_ip_p dip, long  curtime );

void print_thresholding();
void sfthreshold_reset_active(void);

#endif
