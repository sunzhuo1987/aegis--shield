/*
 * spp_dcerpc.c
 *
 * Copyright (C) 2004-2008 Sourcefire,Inc
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
 * This file initializes DCERPC as a Snort preprocessor.
 *
 * This file registers the DCERPC initialization function,
 * adds the DCERPC function into the preprocessor list, reads
 * the user configuration in the snort.conf file, and prints out
 * the configuration that is read.
 *
 * In general, this file is a wrapper to DCERPC preproc functionality,
 * by interfacing with the Snort preprocessor functions.  The rest
 * of DCERPC should be separate from the preprocessor hooks.
 *
 * The DCERPC preprocessor parses DCERPC requests from remote machines by
 * layering SMB and DCERPC data structures over the data stream and extracting
 * various pieces of information.
 *
 * Arguments:
 *   
 * This plugin takes port list(s) representing the TCP ports that the
 * user is interested in having decoded.  It is of the format
 *
 * ports nbt { port1 [port2 ...] }
 * ports raw { port1 [port2 ...] }
 *
 * where nbt & raw are used to specify the ports for SMB over NetBios/TCP
 * and raw SMB, respectively.
 *
 * Effect:
 *
 * None
 *
 * NOTES:
 * - 08.12.04:  Initial Development.  SAS
 *
 */

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#ifdef HAVE_STRINGS_H	 
#include <strings.h>	 
#endif

#include "debug.h"

#include "preprocids.h"
#include "sf_snort_packet.h"

#include "profiler.h"

#include "snort_dcerpc.h"

#ifdef PERF_PROFILING
PreprocStats dcerpcPerfStats;
PreprocStats dcerpcDetectPerfStats;
#endif

/*
 * The length of the error string buffer.
 */
#define ERRSTRLEN 1000

/*
 * The definition of the configuration separators in the snort.conf
 * configure line.
 */
#define CONF_SEPARATORS " \t\n\r"
 
void DCERPCInit(char *);
void ProcessDCERPCPacket(void *, void *);
static void DCERPCCleanExitFunction(int, void *);
static void DCERPCReset(int, void *);
static void DCERPCResetStats(int, void *);


/*
 * Function: SetupDCERPC()
 *
 * Purpose: Registers the preprocessor keyword and initialization 
 *          function into the preprocessor list.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 */
void SetupDCERPC()
{
    /* link the preprocessor keyword to the init function in 
       the preproc list */
    _dpd.registerPreproc("dcerpc", DCERPCInit);

    DEBUG_WRAP(DebugMessage(DEBUG_DCERPC,"Preprocessor: DCERPC in setup...\n"););
}


/*
 * Function: DCERPCInit(char *)
 *
 * Purpose: Processes the args sent to the preprocessor, sets up the
 *          port list, links the processing function into the preproc
 *          function list
 *
 * Arguments: args => ptr to argument string
 *
 * Returns: void function
 *
 */
void DCERPCInit(char *args)
{
    char ErrorString[ERRSTRLEN];
    int  iErrStrLen = ERRSTRLEN - 1;

    /* Initialize the tokenizer */
    char *token = strtok(args, CONF_SEPARATORS);

    ErrorString[ERRSTRLEN - 1] = '\0';

    DEBUG_WRAP(DebugMessage(DEBUG_DCERPC,"Preprocessor: DCERPC Initialized\n"););

    /* parse the argument list into a list of ports to normalize */
    
    if (DCERPCProcessConf(token, ErrorString, iErrStrLen))
    {
        /*
         * Fatal Error, log error and exit.
         */
        DynamicPreprocessorFatalMessage("%s(%d) => %s\n", *_dpd.config_file, *_dpd.config_line, ErrorString);
    }

    /* Init reassembly packet */
    DCERPC_InitPacket();

    /* Set the preprocessor function into the function list */
	_dpd.addPreproc(ProcessDCERPCPacket, PRIORITY_APPLICATION, PP_DCERPC);
	_dpd.addPreprocExit(DCERPCCleanExitFunction, NULL, PRIORITY_LAST, PP_DCERPC);
	_dpd.addPreprocReset(DCERPCReset, NULL, PRIORITY_LAST, PP_DCERPC);
	_dpd.addPreprocResetStats(DCERPCResetStats, NULL, PRIORITY_LAST, PP_DCERPC);
	_dpd.addPreprocGetReassemblyPkt(DCERPC_GetReassemblyPkt, PP_DCERPC);

#ifdef PERF_PROFILING
    _dpd.addPreprocProfileFunc("dcerpc", &dcerpcPerfStats, 0, _dpd.totalPerfStats);
#endif
}

#if 0
static void DCERPC_DisableDetect(SFSnortPacket *p)
{
    _dpd.disableAllDetect(p);

    _dpd.setPreprocBit(p, PP_SFPORTSCAN);
    _dpd.setPreprocBit(p, PP_PERFMONITOR);
    _dpd.setPreprocBit(p, PP_STREAM4);
    _dpd.setPreprocBit(p, PP_STREAM5);
}
#endif

static void DCERPC_DisablePreprocessors(SFSnortPacket *p)
{
    _dpd.disablePreprocessors(p);

    _dpd.setPreprocBit(p, PP_SFPORTSCAN);
    _dpd.setPreprocBit(p, PP_PERFMONITOR);
    _dpd.setPreprocBit(p, PP_STREAM4);
    _dpd.setPreprocBit(p, PP_STREAM5);
}


/*
 * Function: ProcessDCERPCPacket(void *)
 *
 * Purpose: Inspects the packet's payload for fragment records and 
 *          converts them into one infragmented record.
 *
 * Arguments: p => pointer to the current packet data struct 
 *
 * Returns: void function
 *
 */
void ProcessDCERPCPacket(void *pkt, void *context)
{
	SFSnortPacket *p = (SFSnortPacket *)pkt;
    u_int32_t      session_flags = 0;
    PROFILE_VARS;

    /* no data to inspect */
    if (p->payload_size == 0)
        return;

    /* check to make sure we're talking TCP and that the TWH has already
       completed before processing anything */
    if(!IsTCP(p))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_DCERPC,"It isn't TCP session traffic\n"););
        return;
    }

    if ( !_dpd.streamAPI )
	{
		DEBUG_WRAP(DebugMessage(DEBUG_DCERPC, "Error: Failed to get Stream API - Stream not enabled?\n"););
        return;
	}

    if (p->stream_session_ptr == NULL)
        return;

    session_flags = _dpd.streamAPI->get_session_flags(p->stream_session_ptr);

    if (session_flags & SSNFLAG_MIDSTREAM)
        return;

    if (!(session_flags & SSNFLAG_ESTABLISHED))
        return;

    PREPROC_PROFILE_START(dcerpcPerfStats);

    if (DCERPCDecode(p))
        DCERPC_DisablePreprocessors(p);

    PREPROC_PROFILE_END(dcerpcPerfStats);
}

/* 
 * Function: DCERPCCleanExitFunction(int, void *)
 *
 * Purpose: This function gets called when Snort is exiting, if there's
 *          any cleanup that needs to be performed (e.g. closing files)
 *          it should be done here.
 *
 * Arguments: signal => the code of the signal that was issued to Snort
 *            data => any arguments or data structs linked to this 
 *                    function when it was registered, may be
 *                    needed to properly exit
 *       
 * Returns: void function
 */                   
static void DCERPCCleanExitFunction(int signal, void *data)
{    
    DCERPC_Exit();
}

static void DCERPCReset(int signal, void *data)
{
    return;
}

static void DCERPCResetStats(int signal, void *data)
{
    return;
}


