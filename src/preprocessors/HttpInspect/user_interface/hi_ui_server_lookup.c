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
**  @file       hi_ui_server_lookup.c
**
**  @author     Daniel Roelker <droelker@sourcefire.com>
**
**  @brief      This file contains functions to access the SERVER_LOOKUP
**              structure.
**
**  We wrap the access to SERVER_LOOKUP so changing the lookup algorithms
**  are more modular and independent.  This is the only file that would need
**  to be changed to change the algorithmic lookup.
**
**  NOTES:
**
**  - 2.24.03:  Initial Develpoment. DJR
*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "hi_util_xmalloc.h"
#include "hi_util_kmap.h"
#include "hi_ui_config.h"
#include "hi_return_codes.h"

/*
**  NAME
**    hi_ui_server_lookup_init::
*/
/**
**  Initialize the server_lookup structure.
**
**  We need to initialize the server_lookup structure for the server
**  configuration access.  Don't want a NULL pointer flying around, when
**  we have to look for server configs.
**
**  @param ServerLookup pointer to the pointer of the server lookup structure.
**
**  @return integer
**
**  @retval HI_SUCCESS function successful.
**  @retval HI_MEM_ALLOC_FAIL memory allocation failed
*/
int hi_ui_server_lookup_init(SERVER_LOOKUP **ServerLookup)
{
    *ServerLookup = KMapNew(free); 
    if(*ServerLookup == NULL)
    {
        return HI_MEM_ALLOC_FAIL;
    }

    return HI_SUCCESS;
}

/*
**  NAME
**    hi_ui_server_lookup_add::
*/
/**
**  Add a server configuration to the list.
**
**  We add these keys like you would normally think to add them, because
**  on low endian machines the least significant byte is compared first.
**  This is what we want to compare IPs backward, doesn't work on high
**  endian machines, but oh well.  Our platform is Intel.
**
**  @param ServerLookup a pointer to the lookup structure
**  @param Ip           the IP address of the server (the key)
**  @param ServerConf   a pointer to the server configuration
**
**  @return integer
**
**  @retval HI_SUCCESS        function successful
**  @retval HI_INVALID_ARG    invalid argument, most likely NULL pointer 
**  @retval HI_MEM_ALLOC_FAIL memory allocation failed 
**  @retval HI_NONFATAL_ERR   key is already in table, don't overwrite
**                            configuration.
*/
int hi_ui_server_lookup_add(SERVER_LOOKUP *ServerLookup, snort_ip_p Ip,
                            HTTPINSPECT_CONF *ServerConf)
{
    int iRet;

    if(!ServerLookup || !ServerConf)
    {
        return HI_INVALID_ARG;
    }

#ifdef SUP_IP6
    iRet = KMapAdd(ServerLookup, (void *)Ip, sizeof(snort_ip), (void *)ServerConf);
#else
    iRet = KMapAdd(ServerLookup, (void *)&Ip, sizeof(snort_ip), (void *)ServerConf);
#endif
    if (iRet)
    {
        /*
        **  This means the key has already been added.
        */
        if(iRet == 1)
        {
            return HI_NONFATAL_ERR;
        }
        else
        {
            return HI_MEM_ALLOC_FAIL;
        }
    }

    return HI_SUCCESS;
}

/*
**  NAME
**    hi_ui_server_lookup_find::
*/
/**
**  Find a server configuration given a IP.
**
**  We look up a server configuration given an IP and return a pointer
**  to that server configuration if found.
**
**  @param ServerLookup pointer to the server lookup structure
**  @param Ip           the IP to lookup
**  @param iError       the error return code
**
**  @return integer
**
**  @retval HI_SUCCESS function sucessful
**  @retval HI_INVALID_ARG argument(s) are invalid
**  @retval HI_NOT_FOUND IP not found
*/
HTTPINSPECT_CONF  *hi_ui_server_lookup_find(SERVER_LOOKUP *ServerLookup, 
                                            snort_ip_p Ip, int *iError)
{
    HTTPINSPECT_CONF *ServerConf;

    if(!iError)
    {
        return NULL;
    }

    if(!ServerLookup)
    {
        *iError = HI_INVALID_ARG;
        return NULL;
    }

    *iError = HI_SUCCESS;

#ifdef SUP_IP6
    ServerConf = (HTTPINSPECT_CONF *)KMapFind(ServerLookup,(void *)Ip,sizeof(snort_ip));
#else
    ServerConf = (HTTPINSPECT_CONF *)KMapFind(ServerLookup,(void *)&Ip,4);
#endif
    if (!ServerConf)
    {
        *iError = HI_NOT_FOUND;
    }

    return ServerConf;
}

/*
**  NAME
**    hi_ui_server_lookup_first::
*/
/**
**  This lookups the first server configuration, so we can iterate
**  through the configurations.
**
**  @param ServerLookup pointer to the server lookup structure
**  @param iError       pointer to the integer to set for errors
**
**  @return integer
**
**  @retval HI_INVALID_ARG invalid argument
**  @retval HI_NOT_FOUND   configuration not found (no first config)
**  @retval HI_SUCCESS     function successful
*/
HTTPINSPECT_CONF *hi_ui_server_lookup_first(SERVER_LOOKUP *ServerLookup,
                                            int *iError)
{
    HTTPINSPECT_CONF *ServerConf;

    if(!iError)
    {
        return NULL;
    }

    if(!ServerLookup)
    {
        *iError = HI_INVALID_ARG;
        return NULL;
    }

    *iError = HI_SUCCESS;

    ServerConf = (HTTPINSPECT_CONF *)KMapFindFirst(ServerLookup);
    if (!ServerConf)
    {
        *iError = HI_NOT_FOUND;
    }

    return ServerConf;
}

/*
**  NAME
**    hi_ui_server_lookup_next::
*/
/**
**  Iterates to the next configuration, like a list it just returns
**  the next config in the config list.
**
**  @param ServerLookup pointer to the server lookup structure
**  @param iError       pointer to the integer to set for errors
**
**  @return integer
**
**  @retval HI_INVALID_ARG invalid argument
**  @retval HI_NOT_FOUND   configuration not found (no first config)
**  @retval HI_SUCCESS     function successful
*/
HTTPINSPECT_CONF *hi_ui_server_lookup_next(SERVER_LOOKUP *ServerLookup,
                                           int *iError)
{
    HTTPINSPECT_CONF *ServerConf;

    if(!iError)
    {
        return NULL;
    }

    if(!ServerLookup)
    {
        *iError = HI_INVALID_ARG;
        return NULL;
    }

    *iError = HI_SUCCESS;

    ServerConf = (HTTPINSPECT_CONF *)KMapFindNext(ServerLookup);
    if (!ServerConf)
    {
        *iError = HI_NOT_FOUND;
    }

    return ServerConf;
}
    

            

