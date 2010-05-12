/****************************************************************************
 *
 * Copyright (C) 2005-2008 Sourcefire Inc.
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

/**************************************************************************
 * snort_smtp.c
 *
 * Author: Andy Mullican
 * Author: Todd Wease
 *
 * Description:
 *
 * This file handles SMTP protocol checking and normalization.
 *
 * Entry point functions:
 *
 *     SnortSMTP()
 *     SMTP_Init()
 *     SMTP_Free()
 *
 **************************************************************************/


/* Includes ***************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>

#include "sf_types.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pcre.h>

#include "snort_smtp.h"
#include "smtp_config.h"
#include "smtp_normalize.h"
#include "smtp_util.h"
#include "smtp_log.h"
#include "smtp_xlink2state.h"

#include "sf_snort_packet.h"
#include "stream_api.h"
#include "debug.h"
#include "profiler.h"
#include "bounds.h"
#include "sf_dynamic_preprocessor.h"
#include "ssl.h"

#ifdef DEBUG
#include "sf_types.h"
#endif

/**************************************************************************/


/* Externs ****************************************************************/

#ifdef PERF_PROFILING
extern PreprocStats smtpDetectPerfStats;
extern int smtpDetectCalled;
#endif

extern SMTPConfig _smtp_config;
extern SMTPCmdConfig *_smtp_cmd_config;
extern DynamicPreprocessorData _dpd;

#ifdef DEBUG
extern char smtp_print_buffer[];
#endif

/**************************************************************************/


/* Globals ****************************************************************/

SMTP          *_smtp = NULL;
SMTP           _smtp_no_session;
SMTPPcre       _mime_boundary_pcre;
char           _smtp_pkt_direction;
char           _smtp_normalizing;
SMTPSearchInfo _smtp_search_info;
int            _smtp_check_gaps = 0;
int            _smtp_reassembling = 0;
#ifdef DEBUG
UINT64 _smtp_session_counter = 0;
#endif


const SMTPToken _smtp_known_cmds[] =
{
    {"ATRN",          4, CMD_ATRN},
    {"AUTH",          4, CMD_AUTH},
    {"BDAT",          4, CMD_BDAT},
    {"DATA",          4, CMD_DATA},
    {"DEBUG",         5, CMD_DEBUG},
    {"EHLO",          4, CMD_EHLO},
    {"EMAL",          4, CMD_EMAL},
    {"ESAM",          4, CMD_ESAM},
    {"ESND",          4, CMD_ESND},
    {"ESOM",          4, CMD_ESOM},
    {"ETRN",          4, CMD_ETRN},
    {"EVFY",          4, CMD_EVFY},
    {"EXPN",          4, CMD_EXPN},
    {"HELO",          4, CMD_HELO},
    {"HELP",          4, CMD_HELP},
    {"IDENT",         5, CMD_IDENT},
    {"MAIL",          4, CMD_MAIL},
    {"NOOP",          4, CMD_NOOP},
    {"ONEX",          4, CMD_ONEX},
    {"QUEU",          4, CMD_QUEU},
    {"QUIT",          4, CMD_QUIT},
    {"RCPT",          4, CMD_RCPT},
    {"RSET",          4, CMD_RSET},
    {"SAML",          4, CMD_SAML},
    {"SEND",          4, CMD_SEND},
    {"SIZE",          4, CMD_SIZE},
    {"STARTTLS",      8, CMD_STARTTLS},
    {"SOML",          4, CMD_SOML},
    {"TICK",          4, CMD_TICK},
    {"TIME",          4, CMD_TIME},
    {"TURN",          4, CMD_TURN},
    {"TURNME",        6, CMD_TURNME},
    {"VERB",          4, CMD_VERB},
    {"VRFY",          4, CMD_VRFY},
    {"X-EXPS",        6, CMD_X_EXPS},
    {"XADR",          4, CMD_XADR},
    {"XAUTH",         5, CMD_XAUTH},
    {"XCIR",          4, CMD_XCIR},
    {"XEXCH50",       7, CMD_XEXCH50},
    {"XGEN",          4, CMD_XGEN},
    {"XLICENSE",      8, CMD_XLICENSE},
    {"X-LINK2STATE", 12, CMD_X_LINK2STATE},
    {"XQUE",          4, CMD_XQUE},
    {"XSTA",          4, CMD_XSTA},
    {"XTRN",          4, CMD_XTRN},
    {"XUSR",          4, CMD_XUSR},
    {NULL,            0, 0}
};

/* new commands can be allocated via the smtp configuration */
SMTPToken *_smtp_cmds;
SMTPSearch *_smtp_cmd_search;


const SMTPToken _smtp_resps[] =
{
	{"220",  3,  RESP_220},  /* Service ready - initial response and STARTTLS response */
	{"221",  3,  RESP_221},  /* Goodbye - response to QUIT */
	{"250",  3,  RESP_250},  /* Requested mail action okay, completed */
	{"354",  3,  RESP_354},  /* Start mail input - data response */
	{"421",  3,  RESP_421},  /* Service not availiable - closes connection */
	{"450",  3,  RESP_450},  /* Mailbox unavailable */
	{"451",  3,  RESP_451},  /* Local error in processing */
	{"452",  3,  RESP_452},  /* Insufficient system storage */
	{"500",  3,  RESP_500},  /* Command unrecognized */
	{"501",  3,  RESP_501},  /* Syntax error in parameters or arguments */
	{"502",  3,  RESP_502},  /* Command not implemented */
	{"503",  3,  RESP_503},  /* Bad sequence of commands */
	{"504",  3,  RESP_504},  /* Command parameter not implemented */
	{"550",  3,  RESP_550},  /* Action not taken - mailbox unavailable */
	{"551",  3,  RESP_551},  /* User not local; please try <forward-path> */
	{"552",  3,  RESP_552},  /* Mail action aborted: exceeded storage allocation */
	{"553",  3,  RESP_553},  /* Action not taken: mailbox name not allowed */
	{"554",  3,  RESP_554},  /* Transaction failed */
	{NULL,   0,  0}
};

SMTPSearch _smtp_resp_search[RESP_LAST];


const SMTPToken _smtp_hdrs[] =
{
    {"Content-type:", 13, HDR_CONTENT_TYPE},
    {NULL,             0, 0}
};

SMTPSearch _smtp_hdr_search[HDR_LAST];


const SMTPToken _smtp_data_end[] =
{
	{"\r\n.\r\n",  5,  DATA_END_1},
	{"\n.\r\n",    4,  DATA_END_2},
	{"\r\n.\n",    4,  DATA_END_3},
	{"\n.\n",      3,  DATA_END_4},
	{NULL,         0,  0}
};

SMTPSearch _smtp_data_end_search[DATA_END_LAST];


SMTPSearch *_smtp_current_search;

/**************************************************************************/


/* Private functions ******************************************************/

static void             SMTP_Setup(SFSnortPacket *);
static void             SMTP_ResetState(void);
static void             SMTP_SessionFree(void *);
static void             SMTP_NoSessionFree(void);
static int              SMTP_GetPacketDirection(SFSnortPacket *, int);
static void             SMTP_ProcessClientPacket(SFSnortPacket *);
static int              SMTP_ProcessServerPacket(SFSnortPacket *);
static void             SMTP_DisableDetect(SFSnortPacket *);
static const u_int8_t * SMTP_HandleCommand(SFSnortPacket *, const u_int8_t *, const u_int8_t *);
static const u_int8_t * SMTP_HandleData(SFSnortPacket *, const u_int8_t *, const u_int8_t *);
static const u_int8_t * SMTP_HandleHeader(SFSnortPacket *, const u_int8_t *, const u_int8_t *);
static const u_int8_t * SMTP_HandleDataBody(SFSnortPacket *, const u_int8_t *, const u_int8_t *);
#ifdef DETECTION_OPTION_TREE
static int              SMTP_SearchStrFound(void *, void *, int, void *);
#else
static int              SMTP_SearchStrFound(void *, int, void *);
#endif

#ifdef DETECTION_OPTION_TREE
static int              SMTP_BoundaryStrFound(void *, void *, int , void *);
#else
static int              SMTP_BoundaryStrFound(void *, int, void *);
#endif
static int              SMTP_GetBoundary(const char *, int);
static int              SMTP_IsTlsClientHello(const u_int8_t *, const u_int8_t *);
static int              SMTP_IsTlsServerHello(const u_int8_t *, const u_int8_t *);
static int              SMTP_IsSSL(const u_int8_t *, int, int);

/**************************************************************************/


void SMTP_InitCmds(void)
{
    const SMTPToken *tmp;

    /* add one to CMD_LAST for NULL entry */
    _smtp_cmds = (SMTPToken *)calloc(CMD_LAST + 1, sizeof(SMTPToken));

    if (_smtp_cmds == NULL)
    {
        DynamicPreprocessorFatalMessage("%s(%d) => failed to allocate memory for smtp "
                                        "command structure\n", 
                                        *(_dpd.config_file), *(_dpd.config_line));
    }

    for (tmp = &_smtp_known_cmds[0]; tmp->name != NULL; tmp++)
    {
        _smtp_cmds[tmp->search_id].name_len = tmp->name_len;
        _smtp_cmds[tmp->search_id].search_id = tmp->search_id;
        _smtp_cmds[tmp->search_id].name = strdup(tmp->name);

        if (_smtp_cmds[tmp->search_id].name == NULL)
        {
            DynamicPreprocessorFatalMessage("%s(%d) => failed to allocate memory for smtp "
                                            "command structure\n", 
                                            *(_dpd.config_file), *(_dpd.config_line));
        }
    }


    /* initialize memory for command searches */
    _smtp_cmd_search = (SMTPSearch *)calloc(CMD_LAST, sizeof(SMTPSearch));

    if (_smtp_cmd_search == NULL)
    {
        DynamicPreprocessorFatalMessage("%s(%d) => failed to allocate memory for smtp "
                                        "command structure\n", 
                                        *(_dpd.config_file), *(_dpd.config_line));
    }
}


/*
 * Initialize SMTP searches
 *
 * @param  none
 *
 * @return none
 */
void SMTP_SearchInit(void)
{
    const char *error;
    int erroffset;
    const SMTPToken *tmp;


    /* Initialize searches */
    _dpd.searchAPI->search_init(NUM_SEARCHES);

    /* Command search */
    for (tmp = _smtp_cmds; tmp->name != NULL; tmp++)
    {
        _smtp_cmd_search[tmp->search_id].name = tmp->name;
        _smtp_cmd_search[tmp->search_id].name_len = tmp->name_len;
        
        _dpd.searchAPI->search_add(SEARCH_CMD, tmp->name, tmp->name_len, tmp->search_id);
    }

    _dpd.searchAPI->search_prep(SEARCH_CMD);


    /* Response search */
    for (tmp = &_smtp_resps[0]; tmp->name != NULL; tmp++)
    {
        _smtp_resp_search[tmp->search_id].name = tmp->name;
        _smtp_resp_search[tmp->search_id].name_len = tmp->name_len;

        _dpd.searchAPI->search_add(SEARCH_RESP, tmp->name, tmp->name_len, tmp->search_id);
    }

    _dpd.searchAPI->search_prep(SEARCH_RESP);


    /* Header search */
    for (tmp = &_smtp_hdrs[0]; tmp->name != NULL; tmp++)
    {
        _smtp_hdr_search[tmp->search_id].name = tmp->name;
        _smtp_hdr_search[tmp->search_id].name_len = tmp->name_len;

        _dpd.searchAPI->search_add(SEARCH_HDR, tmp->name, tmp->name_len, tmp->search_id);
    }

    _dpd.searchAPI->search_prep(SEARCH_HDR);


    /* Data end search */
    for (tmp = &_smtp_data_end[0]; tmp->name != NULL; tmp++)
    {
        _smtp_data_end_search[tmp->search_id].name = tmp->name;
        _smtp_data_end_search[tmp->search_id].name_len = tmp->name_len;

        _dpd.searchAPI->search_add(SEARCH_DATA_END, tmp->name, tmp->name_len, tmp->search_id);
    }

    _dpd.searchAPI->search_prep(SEARCH_DATA_END);


    /* create regex for finding boundary string - since it can be cut across multiple
     * lines, a straight search won't do. Shouldn't be too slow since it will most
     * likely only be acting on a small portion of data */
    //"^content-type:\\s*multipart.*boundary\\s*=\\s*\"?([^\\s]+)\"?"
    //"^\\s*multipart.*boundary\\s*=\\s*\"?([^\\s]+)\"?"
    //_mime_boundary_pcre.re = pcre_compile("^.*boundary\\s*=\\s*\"?([^\\s\"]+)\"?",
    //_mime_boundary_pcre.re = pcre_compile("boundary(?:\n|\r\n)?=(?:\n|\r\n)?\"?([^\\s\"]+)\"?",
    _mime_boundary_pcre.re = pcre_compile("boundary\\s*=\\s*\"?([^\\s\"]+)\"?",
                                          PCRE_CASELESS | PCRE_DOTALL,
                                          &error, &erroffset, NULL);
    if (_mime_boundary_pcre.re == NULL)
    {
        DynamicPreprocessorFatalMessage("Failed to compile pcre regex for getting boundary "
                                        "in a multipart SMTP message: %s\n", error);
    }


    _mime_boundary_pcre.pe = pcre_study(_mime_boundary_pcre.re, 0, &error);

    if (error != NULL)
    {
        DynamicPreprocessorFatalMessage("Failed to study pcre regex for getting boundary "
                                        "in a multipart SMTP message: %s\n", error);
    }
}

/* 
 * Initialize run-time boundary search
 */
static int SMTP_BoundarySearchInit(void)
{
    if (_smtp->mime_boundary.boundary_search != NULL)
        _dpd.searchAPI->search_instance_free(_smtp->mime_boundary.boundary_search);

    _smtp->mime_boundary.boundary_search = _dpd.searchAPI->search_instance_new();

    if (_smtp->mime_boundary.boundary_search == NULL)
        return -1;

    _dpd.searchAPI->search_instance_add(_smtp->mime_boundary.boundary_search,
                                        _smtp->mime_boundary.boundary,
                                        _smtp->mime_boundary.boundary_len, BOUNDARY);

    _dpd.searchAPI->search_instance_prep(_smtp->mime_boundary.boundary_search);

    return 0;
}



/*
 * Reset SMTP session state
 *
 * @param  none
 *
 * @return none
 */
static void SMTP_ResetState(void)
{
    if (_smtp->mime_boundary.boundary_search != NULL)
    {
        _dpd.searchAPI->search_instance_free(_smtp->mime_boundary.boundary_search);
        _smtp->mime_boundary.boundary_search = NULL;
    }

    _smtp->state = STATE_COMMAND;
    _smtp->data_state = STATE_DATA_INIT;
    _smtp->state_flags = 0;
    memset(&_smtp->mime_boundary, 0, sizeof(SMTPMimeBoundary));
}


/*
 * Given a server configuration and a port number, we decide if the port is
 *  in the SMTP server port list.
 *
 *  @param  port       the port number to compare with the configuration
 *
 *  @return integer
 *  @retval  0 means that the port is not a server port
 *  @retval !0 means that the port is a server port
 */
int SMTP_IsServer(u_int16_t port)
{
    if (_smtp_config.ports[port / 8] & (1 << (port % 8)))
    {
        return 1;
    }

    return 0;
}


/*
 * Do first-packet setup
 *
 * @param   p   standard Packet structure
 *
 * @return  none
 */
static void SMTP_Setup(SFSnortPacket *p)
{
    int flags = 0;
    static char checked_reassembling = 0;

    /* reset normalization stuff */
    _smtp_normalizing = 0;
    p->normalized_payload_size = 0;
    p->flags &= ~FLAG_ALT_DECODE;

    if (p->stream_session_ptr != NULL)
    {
        /* check to see if we're doing client reassembly in stream */
        if (!checked_reassembling)
        {
            checked_reassembling = 1;

            if (_dpd.streamAPI->get_reassembly_direction(p->stream_session_ptr) & SSN_DIR_CLIENT)
                _smtp_reassembling = 1;
        }

        /* set flags to session flags */
        flags = _dpd.streamAPI->get_session_flags(p->stream_session_ptr);
    }

    /* Figure out direction of packet */
    _smtp_pkt_direction = SMTP_GetPacketDirection(p, flags);

    if ((p->stream_session_ptr == NULL) || (_smtp_config.inspection_type == SMTP_STATELESS))
    {
#ifdef DEBUG
        if (p->stream_session_ptr == NULL)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "Stream session pointer is NULL - "
                                    "treating packet as stateless\n"););
        }
#endif

        SMTP_NoSessionFree();
        memset(&_smtp_no_session, 0, sizeof(SMTP));
        _smtp = &_smtp_no_session;
        _smtp->session_flags |= SMTP_FLAG_CHECK_SSL;

        return;
    }

    _smtp = (SMTP *)_dpd.streamAPI->get_application_data(p->stream_session_ptr, PP_SMTP);

    if (_smtp == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "Creating new session data structure\n"););

        _smtp = (SMTP *)calloc(1, sizeof(SMTP));
        if (_smtp == NULL)
        {
            DynamicPreprocessorFatalMessage("Failed to allocate SMTP session data\n");
        }
        else
        {      
            _dpd.streamAPI->set_application_data(p->stream_session_ptr, PP_SMTP,
                                                 _smtp, &SMTP_SessionFree);   

            if (p->flags & SSNFLAG_MIDSTREAM)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "Got midstream packet - "
                                        "setting state to unknown\n"););
                _smtp->state = STATE_UNKNOWN;
            }

#ifdef DEBUG
            _smtp_session_counter++;
            _smtp->session_number = _smtp_session_counter;
#endif
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "Session number: "STDu64"\n", _smtp->session_number);); 

    /* reset check ssl flag for new packet */
    if (!(_smtp->session_flags & SMTP_FLAG_CHECK_SSL))
        _smtp->session_flags |= SMTP_FLAG_CHECK_SSL;

    /* Check to see if there is a reassembly gap.  If so, we won't know
     * what state we're in when we get the _next_ reassembled packet */
    if (_smtp_check_gaps &&
        (_smtp_pkt_direction != SMTP_PKT_FROM_SERVER) &&
        (p->flags & FLAG_REBUILT_STREAM))
    {
        char missing_in_rebuilt =
            _dpd.streamAPI->missing_in_reassembled(p->stream_session_ptr, SSN_DIR_CLIENT);

        if (_smtp->session_flags & SMTP_FLAG_NEXT_STATE_UNKNOWN)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "Found gap in previous reassembly buffer - "
                                    "set state to unknown\n"););
            _smtp->state = STATE_UNKNOWN;
            _smtp->session_flags &= ~SMTP_FLAG_NEXT_STATE_UNKNOWN;
        }

        if (missing_in_rebuilt == 3)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "Found missing packets before and after "
                                    "in reassembly buffer - set state to unknown and "
                                    "next state to unknown\n"););
            _smtp->state = STATE_UNKNOWN;
            _smtp->session_flags |= SMTP_FLAG_NEXT_STATE_UNKNOWN;
        }
        else if (missing_in_rebuilt == 2)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "Found missing packets before "
                                    "in reassembly buffer - set state to unknown\n"););
            _smtp->state = STATE_UNKNOWN;
        }
        else if (missing_in_rebuilt == 1)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "Found missing packets after "
                                    "in reassembly buffer - set next state to unknown\n"););
            _smtp->session_flags |= SMTP_FLAG_NEXT_STATE_UNKNOWN;
        }
    }
}

/*
 * Determine packet direction
 *
 * @param   p   standard Packet structure
 *
 * @return  none
 */
static int SMTP_GetPacketDirection(SFSnortPacket *p, int flags)
{    
    int pkt_direction = SMTP_PKT_FROM_UNKNOWN;

    if (flags & SSNFLAG_MIDSTREAM)
    {
        if (SMTP_IsServer(p->src_port) &&
            !SMTP_IsServer(p->dst_port))
        {
            pkt_direction = SMTP_PKT_FROM_SERVER;
        }
        else if (!SMTP_IsServer(p->src_port) &&
                 SMTP_IsServer(p->dst_port))
        {
            pkt_direction = SMTP_PKT_FROM_CLIENT;
        }
    }
    else
    {
        if (p->flags & FLAG_FROM_SERVER)
        {
            pkt_direction = SMTP_PKT_FROM_SERVER;
        }
        else if (p->flags & FLAG_FROM_CLIENT)
        {
            pkt_direction = SMTP_PKT_FROM_CLIENT;
        }

        /* if direction is still unknown ... */
        if (pkt_direction == SMTP_PKT_FROM_UNKNOWN)
        {
            if (SMTP_IsServer(p->src_port) &&
                !SMTP_IsServer(p->dst_port))
            {
                pkt_direction = SMTP_PKT_FROM_SERVER;
            }
            else if (!SMTP_IsServer(p->src_port) &&
                     SMTP_IsServer(p->dst_port))
            {
                pkt_direction = SMTP_PKT_FROM_CLIENT;
            }
        }
    }

    return pkt_direction;
}


/*
 * Free SMTP-specific related to this session
 *
 * @param   v   pointer to SMTP session structure
 *
 * @return  none
 */
static void SMTP_SessionFree(void *session_data)
{
    SMTP *smtp = (SMTP *)session_data;

    if (smtp != NULL)
    {
        if (smtp->mime_boundary.boundary_search != NULL)
        {
            _dpd.searchAPI->search_instance_free(smtp->mime_boundary.boundary_search);
            smtp->mime_boundary.boundary_search = NULL;
        }

        free(smtp);
    }
}


static void SMTP_NoSessionFree(void)
{
    if (_smtp_no_session.mime_boundary.boundary_search != NULL)
    {
        _dpd.searchAPI->search_instance_free(_smtp_no_session.mime_boundary.boundary_search);
        _smtp_no_session.mime_boundary.boundary_search = NULL;
    }
}


/*
 * Free anything that needs it before shutting down preprocessor
 *
 * @param   none
 *
 * @return  none
 */
void SMTP_Free(void)
{
    SMTPToken *tmp;

    _dpd.searchAPI->search_free();
    SMTP_NoSessionFree();

    for (tmp = _smtp_cmds; tmp->name != NULL; tmp++)
    {
        free(tmp->name);
    }

    if (_smtp_cmds != NULL)
        free(_smtp_cmds);
    if (_smtp_cmd_search != NULL)
        free(_smtp_cmd_search);
    if (_smtp_cmd_config != NULL)
        free(_smtp_cmd_config);

    if (_mime_boundary_pcre.re )
        pcre_free(_mime_boundary_pcre.re);
    if (_mime_boundary_pcre.pe )
        pcre_free(_mime_boundary_pcre.pe);
}


/*
 * Callback function for string search
 *
 * @param   id      id in array of search strings from _smtp_config.cmds
 * @param   index   index in array of search strings from _smtp_config.cmds
 * @param   data    buffer passed in to search function
 *
 * @return response
 * @retval 1        commands caller to stop searching
 */
#ifdef DETECTION_OPTION_TREE
static int SMTP_SearchStrFound(void *id, void *unused, int index, void *data)
#else
static int SMTP_SearchStrFound(void *id, int index, void *data)
#endif
{
    int search_id = (int)(uintptr_t)id;

    _smtp_search_info.id = search_id;
    _smtp_search_info.index = index;
    _smtp_search_info.length = _smtp_current_search[search_id].name_len;

    /* Returning non-zero stops search, which is okay since we only look for one at a time */
    return 1;
}


/*
 * Callback function for boundary search
 *
 * @param   id      id in array of search strings
 * @param   index   index in array of search strings
 * @param   data    buffer passed in to search function
 *
 * @return response
 * @retval 1        commands caller to stop searching
 */
#ifdef DETECTION_OPTION_TREE
static int SMTP_BoundaryStrFound(void *id, void *unused, int index, void *data)
#else
static int SMTP_BoundaryStrFound(void *id, int index, void *data)
#endif
{
    int boundary_id = (int)(uintptr_t)id;

    _smtp_search_info.id = boundary_id;
    _smtp_search_info.index = index;
    _smtp_search_info.length = _smtp->mime_boundary.boundary_len;

    return 1;
}

static int SMTP_GetBoundary(const char *data, int data_len)
{
    int result;
    int ovector[9];
    int ovecsize = 9;
    const char *boundary;
    int boundary_len;
    int ret;
    char *mime_boundary;
    int  *mime_boundary_len;


    mime_boundary = &_smtp->mime_boundary.boundary[0];
    mime_boundary_len = &_smtp->mime_boundary.boundary_len;
    
    /* result will be the number of matches (including submatches) */
    result = pcre_exec(_mime_boundary_pcre.re, _mime_boundary_pcre.pe,
                       data, data_len, 0, 0, ovector, ovecsize);
    if (result < 0)
        return -1;

    result = pcre_get_substring(data, ovector, result, 1, &boundary);
    if (result < 0)
        return -1;

    boundary_len = strlen(boundary);
    if (boundary_len > MAX_BOUNDARY_LEN)
    {
        /* XXX should we alert? breaking the law of RFC */
        boundary_len = MAX_BOUNDARY_LEN;
    }

    mime_boundary[0] = '-';
    mime_boundary[1] = '-';
    ret = SafeMemcpy(mime_boundary + 2, boundary, boundary_len,
                     mime_boundary + 2, mime_boundary + 2 + MAX_BOUNDARY_LEN);

    pcre_free_substring(boundary);

    if (ret != SAFEMEM_SUCCESS)
    {
        return -1;
    }

    *mime_boundary_len = 2 + boundary_len;
    mime_boundary[*mime_boundary_len] = '\0';

    return 0;
}


/*
 * Handle COMMAND state
 *
 * @param   p       standard Packet structure
 * @param   ptr     pointer into p->payload buffer to start looking at data
 * @param   end     points to end of p->payload buffer
 *
 * @return          pointer into p->payload where we stopped looking at data
 *                  will be end of line or end of packet
 */
static const u_int8_t * SMTP_HandleCommand(SFSnortPacket *p, const u_int8_t *ptr, const u_int8_t *end)
{
    const u_int8_t *eol;   /* end of line */
    const u_int8_t *eolm;  /* end of line marker */
    int cmd_line_len;
    int ret;
    int cmd_found;
    char alert_long_command_line = 0;


    /* get end of line and end of line marker */
    SMTP_GetEOL(ptr, end, &eol, &eolm);

    /* calculate length of command line */
    cmd_line_len = eol - ptr;

    /* check for command line exceeding maximum 
     * do this before checking for a command since this could overflow
     * some server's buffers without the presence of a known command */
    if ((_smtp_config.max_command_line_len != 0) &&
        (cmd_line_len > _smtp_config.max_command_line_len))
    {
        alert_long_command_line = 1;
    }

    /* TODO If the end of line marker coincides with the end of payload we can't be
     * sure that we got a command and not a substring which we could tell through
     * inpsection of the next packet. Maybe a command pending state where the first
     * char in the next packet is checked for a space and end of line marker */

    /* do not confine since there could be space chars before command */
    _smtp_current_search = &_smtp_cmd_search[0];
    cmd_found = _dpd.searchAPI->search_find(SEARCH_CMD, (const char *)ptr, eolm - ptr,
                                            0, SMTP_SearchStrFound);

    /* see if we actually found a command and not a substring */
    if (cmd_found > 0)
    {
        const u_int8_t *tmp = ptr;
        const u_int8_t *cmd_start = ptr + _smtp_search_info.index;
        const u_int8_t *cmd_end = cmd_start + _smtp_search_info.length;

        /* move past spaces up until start of command */
        while ((tmp < cmd_start) && isspace((int)*tmp))
            tmp++;

        /* if not all spaces before command, we found a 
         * substring */
        if (tmp != cmd_start)
            cmd_found = 0;
        
        /* if we're before the end of line marker and the next
         * character is not whitespace, we found a substring */
        if ((cmd_end < eolm) && !isspace((int)*cmd_end))
            cmd_found = 0;

        /* there is a chance that end of command coincides with the end of payload
         * in which case, it could be a substring, but for now, we will treat it as found */
    }

    /* if command not found, alert and move on */
    if (!cmd_found)
    {
        /* If we missed one or more packets we might not actually be in the command
         * state.  Check to see if we're encrypted */
        if (_smtp->state == STATE_UNKNOWN)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "Command not found, but state is "
                                    "unknown - checking for SSL\n"););

            /* check for encrypted */

            if ((_smtp->session_flags & SMTP_FLAG_CHECK_SSL) &&
                (SMTP_IsSSL(ptr, end - ptr, p->flags)))
            {
                DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "Packet is SSL encrypted\n"););

                _smtp->state = STATE_TLS_DATA;

                /* Ignore data */
                if (_smtp_config.ignore_tls_data)
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "Ignoring encrypted data\n"););

                    p->normalized_payload_size = 0;
                    p->flags |= FLAG_ALT_DECODE;
                }

                return end;
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "Not SSL - try data state\n"););
                /* don't check for ssl again in this packet */
                if (_smtp->session_flags & SMTP_FLAG_CHECK_SSL)
                    _smtp->session_flags &= ~SMTP_FLAG_CHECK_SSL;

                _smtp->state = STATE_DATA;
                _smtp->data_state = STATE_DATA_UNKNOWN;

                return ptr;
            }
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "No known command found\n"););

            if (_smtp_config.alert_unknown_cmds)
            {
                SMTP_GenerateAlert(SMTP_UNKNOWN_CMD, "%s", SMTP_UNKNOWN_CMD_STR);
            }

            if (alert_long_command_line)
            {
                SMTP_GenerateAlert(SMTP_COMMAND_OVERFLOW, "%s: more than %d chars",
                                   SMTP_COMMAND_OVERFLOW_STR, _smtp_config.max_command_line_len);
            }

            /* if normalizing, copy line to alt buffer */
            if (_smtp_normalizing)
            {
                ret = SMTP_CopyToAltBuffer(p, ptr, eol - ptr);
                if (ret == -1)
                    return NULL;
            }

            return eol;
        }
    }

    /* At this point we have definitely found a legitimate command */

    DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "%s\n", _smtp_cmds[_smtp_search_info.id].name););

    /* check if max command line length for a specific command is exceeded */
    if (_smtp_cmd_config[_smtp_search_info.id].max_line_len != 0)
    {
        if (cmd_line_len > _smtp_cmd_config[_smtp_search_info.id].max_line_len)
        {
            SMTP_GenerateAlert(SMTP_SPECIFIC_CMD_OVERFLOW, "%s: %s, %d chars",
                               SMTP_SPECIFIC_CMD_OVERFLOW_STR,
                               _smtp_cmd_search[_smtp_search_info.id].name, cmd_line_len);
        }
    }
    else if (alert_long_command_line)
    {
        SMTP_GenerateAlert(SMTP_COMMAND_OVERFLOW, "%s: more than %d chars",
                           SMTP_COMMAND_OVERFLOW_STR, _smtp_config.max_command_line_len);
    }

    /* Are we alerting on this command? */
    if (_smtp_cmd_config[_smtp_search_info.id].alert)
    {
        SMTP_GenerateAlert(SMTP_ILLEGAL_CMD, "%s: %s",
                           SMTP_ILLEGAL_CMD_STR, _smtp_cmds[_smtp_search_info.id].name);
    }

    switch (_smtp_search_info.id)
    {
        /* unless we do our own parsing of MAIL and RCTP commands we have to assume they
         * are ok unless we got a server error in which case we flush and if this is a
         * reassembled packet, the last command in this packet will be the command that
         * caused the error */
        case CMD_MAIL:
            _smtp->state_flags |= SMTP_FLAG_GOT_MAIL_CMD;

            break;

        case CMD_RCPT:
            if ((_smtp->state_flags & SMTP_FLAG_GOT_MAIL_CMD) ||
                _smtp->state == STATE_UNKNOWN)
            {
                _smtp->state_flags |= SMTP_FLAG_GOT_RCPT_CMD;
            }

            break;

        case CMD_RSET:
        case CMD_HELO:
        case CMD_EHLO:
        case CMD_QUIT:
            _smtp->state_flags &= ~(SMTP_FLAG_GOT_MAIL_CMD | SMTP_FLAG_GOT_RCPT_CMD);

            break;

#if 0
        case CMD_BDAT:
            {
                const u_int8_t *begin_chunk;
                const u_int8_t *end_chunk;
                const u_int8_t *last;
                const u_int8_t *tmp;
                int num_digits;
                int ten_power;
                u_int32_t bdat_chunk;

                begin_chunk = ptr + _smtp_search_info.index + _smtp_search_info.length;
                while ((begin_chunk < eolm) && isspace((int)*begin_chunk))
                    begin_chunk++;

                /* bad BDAT command - needs chunk argument */
                if (begin_chunk == eolm)
                    break;
                    
                end_chunk = begin_chunk;
                while ((end_chunk < eolm) && isdigit((int)*end_chunk))
                    end_chunk++;

                /* didn't get all digits */
                if ((end_chunk < eolm) && !isspace((int)*end_chunk))
                    break;

                /* get chunk size */
                num_digits = end_chunk - begin_chunk;

                /* more than 9 digits could potentially overflow a 32 bit integer
                 * this allows for one less than a billion bytes which most servers
                 * won't accept */
                if (num_digits > 9)
                    break;

                tmp = end_chunk;
                for (ten_power = 1, tmp--; tmp >= begin_chunk; ten_power *= 10, tmp--)
                {
                    bdat_chunk += (*tmp - '0') * ten_power;
                }

                /* bad bdat chunk size */
                if (bdat_chunk == 0)
                    break;

                /* got a valid chunk size - check to see if this is the last chunk */
                last = end_chunk;
                while ((last < eolm) && isspace((int)*last))
                    last++;

                /* TODO need an ESMTP argument search */
                if (last < eolm)
                {
                    /* must have at least 4 chars for 'last' */
                    if ((eolm - last) >= 4)
                    {
                        if (*last == 'l' || *last == 'L')
                        {
                            last++;
                            if (*last == 'a' || *last == 'A')
                            {
                                last++;
                                if (*last == 's' || *last == 'S')
                                {
                                    last++;
                                    if (*last == 't' || *last == 'T')
                                    {
                                        last++;
                                        while ((last < eolm) && isspace((int)*last))
                                            last++;

                                        if (last != eolm)
                                        {
                                            break;
                                        }
                                        
                                        _smtp->bdat_last = 1;
                                    }
                                }
                            }
                        }
                    }
                }

                _smtp->state = STATE_BDAT;
                _smtp->bdat_chunk = bdat_chunk;
            }

            break;
#endif

        case CMD_BDAT:
        case CMD_DATA:
            if ((_smtp->state_flags & SMTP_FLAG_GOT_RCPT_CMD) ||
                _smtp->state == STATE_UNKNOWN)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "Set to data state.\n"););

                _smtp->state = STATE_DATA;
                _smtp->state_flags &= ~(SMTP_FLAG_GOT_MAIL_CMD | SMTP_FLAG_GOT_RCPT_CMD);
            }
            else
            {
                 DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "Didn't get MAIL -> RCPT command sequence - "
                                                     "stay in command state.\n"););
            }

            break;

        case CMD_STARTTLS:
            /* if reassembled we flush after seeing a 220 so this should be the last
             * command in reassembled packet and if not reassembled it should be the
             * last line in the packet as you can't pipeline the tls hello */
            if (eol == end)
                _smtp->state = STATE_TLS_CLIENT_PEND;

            break;
        
        case CMD_X_LINK2STATE: 
            if (_smtp_config.alert_xlink2state)
                ParseXLink2State(p, ptr + _smtp_search_info.index);

            break;
            
        default:
            break;
    }

    /* Since we found a command, if state is still unknown,
     * set to command state */
    if (_smtp->state == STATE_UNKNOWN)
        _smtp->state = STATE_COMMAND;

    /* normalize command line */
    if (_smtp_config.normalize == NORMALIZE_ALL ||
        _smtp_cmd_config[_smtp_search_info.id].normalize)
    {
        ret = SMTP_NormalizeCmd(p, ptr, eolm, eol);
        if (ret == -1)
            return NULL;
    }                        
    else if (_smtp_normalizing) /* Already normalizing */
    {
        ret = SMTP_CopyToAltBuffer(p, ptr, eol - ptr);
        if (ret == -1)
            return NULL;
    }

    return eol;
}


static const u_int8_t * SMTP_HandleData(SFSnortPacket *p, const u_int8_t *ptr, const u_int8_t *end)
{
    const u_int8_t *data_end_marker = NULL;
    const u_int8_t *data_end = NULL;
    int data_end_found;
    int ret;


    /* if we've just entered the data state, check for a dot + end of line
     * if found, no data */
    if ((_smtp->data_state == STATE_DATA_INIT) ||
        (_smtp->data_state == STATE_DATA_UNKNOWN))
    {
        if ((ptr < end) && (*ptr == '.'))
        {
            const u_int8_t *eol = NULL;
            const u_int8_t *eolm = NULL;

            SMTP_GetEOL(ptr, end, &eol, &eolm);

            /* this means we got a real end of line and not just end of payload 
             * and that the dot is only char on line */
            if ((eolm != end) && (eolm == (ptr + 1)))
            {
                /* if we're normalizing and not ignoring data copy data end marker
                 * and dot to alt buffer */
                if (!_smtp_config.ignore_data && _smtp_normalizing)
                {
                    ret = SMTP_CopyToAltBuffer(p, ptr, eol - ptr);
                    if (ret == -1)
                        return NULL;
                }

                SMTP_ResetState();

                return eol;
            }
        }

        if (_smtp->data_state == STATE_DATA_INIT)
            _smtp->data_state = STATE_DATA_HEADER;

        /* XXX A line starting with a '.' that isn't followed by a '.' is
         * deleted (RFC 821 - 4.5.2.  TRANSPARENCY).  If data starts with
         * '. text', i.e a dot followed by white space then text, some
         * servers consider it data header and some data body.
         * Postfix and Qmail will consider the start of data:
         * . text\r\n
         * .  text\r\n
         * to be part of the header and the effect will be that of a 
         * folded line with the '.' deleted.  Exchange will put the same
         * in the body which seems more reasonable. */
    }

    /* get end of data body
     * TODO check last bytes of previous packet to see if we had a partial
     * end of data */
    _smtp_current_search = &_smtp_data_end_search[0];
    data_end_found = _dpd.searchAPI->search_find(SEARCH_DATA_END, (const char *)ptr,
                                                 end - ptr, 0, SMTP_SearchStrFound);
    if (data_end_found > 0)
    {
        data_end_marker = ptr + _smtp_search_info.index;
        data_end = data_end_marker + _smtp_search_info.length;
    }
    else
    {
        data_end_marker = data_end = end;
    }

    if ((_smtp->data_state == STATE_DATA_HEADER) ||
        (_smtp->data_state == STATE_DATA_UNKNOWN))
    {
#ifdef DEBUG
        if (_smtp->data_state == STATE_DATA_HEADER)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "DATA HEADER STATE ~~~~~~~~~~~~~~~~~~~~~~\n"););
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "DATA UNKNOWN STATE ~~~~~~~~~~~~~~~~~~~~~\n"););
        }
#endif

        ptr = SMTP_HandleHeader(p, ptr, data_end_marker);
        if (ptr == NULL)
            return NULL;
    }

    /* if we're ignoring data and not already normalizing, copy everything
     * up to here into alt buffer so detection engine doesn't have
     * to look at the data; otherwise, if we're normalizing and not
     * ignoring data, copy all of the data into the alt buffer */
    if (_smtp_config.ignore_data && !_smtp_normalizing)
    {
        ret = SMTP_CopyToAltBuffer(p, p->payload, ptr - p->payload);
        if (ret == -1)
            return NULL;
    }
    else if (!_smtp_config.ignore_data && _smtp_normalizing)
    {
        ret = SMTP_CopyToAltBuffer(p, ptr, data_end - ptr);
        if (ret == -1)
            return NULL;
    }

    /* now we shouldn't have to worry about copying any data to the alt buffer
     * only mime headers if we find them and only if we're ignoring data */

    while ((ptr != NULL) && (ptr < data_end_marker))
    {
        switch (_smtp->data_state)
        {
            case STATE_MIME_HEADER:
                DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "MIME HEADER STATE ~~~~~~~~~~~~~~~~~~~~~~\n"););
                ptr = SMTP_HandleHeader(p, ptr, data_end_marker);
                break;
            case STATE_DATA_BODY:
                DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "DATA BODY STATE ~~~~~~~~~~~~~~~~~~~~~~~~\n"););
                ptr = SMTP_HandleDataBody(p, ptr, data_end_marker);
                break;
        }
    }

    /* if we got the data end reset state, otherwise we're probably still in the data
     * to expect more data in next packet */
    if (data_end_marker != end)
    {
        SMTP_ResetState();
    }

    return data_end;
}


/*
 * Handle Headers - Data or Mime
 *
 * @param   packet  standard Packet structure
 *
 * @param   i       index into p->payload buffer to start looking at data
 *
 * @return  i       index into p->payload where we stopped looking at data
 */
static const u_int8_t * SMTP_HandleHeader(SFSnortPacket *p, const u_int8_t *ptr,
                                          const u_int8_t *data_end_marker)
{
    const u_int8_t *eol;
    const u_int8_t *eolm;
    const u_int8_t *colon;
    const u_int8_t *content_type_ptr = NULL;
    int header_line_len;
    int header_found;
    int ret;
    const u_int8_t *start_hdr;
    int header_name_len;


    start_hdr = ptr;

    /* if we got a content-type in a previous packet and are
     * folding, the boundary still needs to be checked for */
    if (_smtp->state_flags & SMTP_FLAG_IN_CONTENT_TYPE)
        content_type_ptr = ptr;

    while (ptr < data_end_marker)
    {
        SMTP_GetEOL(ptr, data_end_marker, &eol, &eolm);

        /* got a line with only end of line marker should signify end of header */
        if (eolm == ptr)
        {
            /* reset global header state values */
            _smtp->state_flags &=
                ~(SMTP_FLAG_FOLDING | SMTP_FLAG_IN_CONTENT_TYPE | SMTP_FLAG_DATA_HEADER_CONT);

            _smtp->data_state = STATE_DATA_BODY;

            /* if no headers, treat as data */
            if (ptr == start_hdr)
                return eolm;
            else
                return eol;
        }

        /* if we're not folding, see if we should interpret line as a data line 
         * instead of a header line */
        if (!(_smtp->state_flags & (SMTP_FLAG_FOLDING | SMTP_FLAG_DATA_HEADER_CONT)))
        {
            char got_non_printable_in_header_name = 0;

            /* if we're not folding and the first char is a space or
             * colon, it's not a header */
            if (isspace((int)*ptr) || *ptr == ':')
            {
                _smtp->data_state = STATE_DATA_BODY;
                return ptr;
            }

            /* look for header field colon - if we're not folding then we need
             * to find a header which will be all printables (except colon) 
             * followed by a colon */
            colon = ptr;
            while ((colon < eolm) && (*colon != ':'))
            {
                if (((int)*colon < 33) || ((int)*colon > 126))
                    got_non_printable_in_header_name = 1;

                colon++;
            }

            /* Check for Exim 4.32 exploit where number of chars before colon is greater than 64 */
            header_name_len = colon - ptr;
            if ((_smtp->data_state != STATE_DATA_UNKNOWN) &&
                (colon < eolm) && (header_name_len > MAX_HEADER_NAME_LEN))
            {
                SMTP_GenerateAlert(SMTP_HEADER_NAME_OVERFLOW, "%s: %d chars before colon",
                                   SMTP_HEADER_NAME_OVERFLOW_STR, header_name_len);
            }

            /* If the end on line marker and end of line are the same, assume
             * header was truncated, so stay in data header state */
            if ((eolm != eol) &&
                ((colon == eolm) || got_non_printable_in_header_name))
            {
                /* no colon or got spaces in header name (won't be interpreted as a header)
                 * assume we're in the body */
                _smtp->state_flags &=
                    ~(SMTP_FLAG_FOLDING | SMTP_FLAG_IN_CONTENT_TYPE | SMTP_FLAG_DATA_HEADER_CONT);

                _smtp->data_state = STATE_DATA_BODY;

                return ptr;
            }

            _smtp_current_search = &_smtp_hdr_search[0];
            header_found = _dpd.searchAPI->search_find(SEARCH_HDR, (const char *)ptr,
                                                       eolm - ptr, 1, SMTP_SearchStrFound);

            /* Headers must start at beginning of line */
            if ((header_found > 0) && (_smtp_search_info.index == 0))
            {
                switch (_smtp_search_info.id)
                {
                    case HDR_CONTENT_TYPE:
                        /* for now we're just looking for the boundary in the data
                         * header section */
                        if (_smtp->data_state != STATE_MIME_HEADER)
                        {
                            content_type_ptr = ptr + _smtp_search_info.length;
                            _smtp->state_flags |= SMTP_FLAG_IN_CONTENT_TYPE;
                        }

                        break;
                        
                    default:
                        break;
                }
            }
        }
        else
        {
            _smtp->state_flags &= ~SMTP_FLAG_DATA_HEADER_CONT;
        }
        
        /* get length of header line */
        header_line_len = eol - ptr;

        if ((_smtp_config.max_header_line_len != 0) &&
            (header_line_len > _smtp_config.max_header_line_len))
        {
            if (_smtp->data_state != STATE_DATA_UNKNOWN)
            {
                SMTP_GenerateAlert(SMTP_DATA_HDR_OVERFLOW, "%s: %d chars",
                                   SMTP_DATA_HDR_OVERFLOW_STR, header_line_len);
            }
            else
            {
                /* assume we guessed wrong and are in the body */
                _smtp->data_state = STATE_DATA_BODY;
                _smtp->state_flags &=
                    ~(SMTP_FLAG_FOLDING | SMTP_FLAG_IN_CONTENT_TYPE | SMTP_FLAG_DATA_HEADER_CONT);
                return ptr;
            }
        }

        /* XXX Does VRT want data headers normalized?
         * currently the code does not normalize headers */
        if (_smtp_normalizing)
        {
            ret = SMTP_CopyToAltBuffer(p, ptr, eol - ptr);
            if (ret == -1)
                return NULL;
        }

        /* check for folding 
         * if char on next line is a space and not \n or \r\n, we are folding */
        if ((eol < data_end_marker) && isspace((int)eol[0]) && (eol[0] != '\n'))
        {
            if ((eol < (data_end_marker - 1)) && (eol[0] != '\r') && (eol[1] != '\n'))
            {
                _smtp->state_flags |= SMTP_FLAG_FOLDING;
            }
            else
            {
                _smtp->state_flags &= ~SMTP_FLAG_FOLDING;
            }
        }
        else if (eol != eolm)
        {
            _smtp->state_flags &= ~SMTP_FLAG_FOLDING;
        }

        /* check if we're in a content-type header and not folding. if so we have the whole
         * header line/lines for content-type - see if we got a multipart with boundary
         * we don't check each folded line, but wait until we have the complete header
         * because boundary=BOUNDARY can be split across mulitple folded lines before
         * or after the '=' */
        if ((_smtp->state_flags &
             (SMTP_FLAG_IN_CONTENT_TYPE | SMTP_FLAG_FOLDING)) == SMTP_FLAG_IN_CONTENT_TYPE)
        {
            /* we got the full content-type header - look for boundary string */
            ret = SMTP_GetBoundary((const char *)content_type_ptr, eolm - content_type_ptr);
            if (ret != -1)
            {
                ret = SMTP_BoundarySearchInit();
                if (ret != -1)
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "Got mime boundary: %s\n",
                                                         _smtp->mime_boundary.boundary););

                    _smtp->state_flags |= SMTP_FLAG_GOT_BOUNDARY;
                }
            }

            _smtp->state_flags &= ~SMTP_FLAG_IN_CONTENT_TYPE;
            content_type_ptr = NULL;
        }

        /* if state was unknown, at this point assume we know */
        if (_smtp->data_state == STATE_DATA_UNKNOWN)
            _smtp->data_state = STATE_DATA_HEADER;

        ptr = eol;

        if (ptr == data_end_marker)
            _smtp->state_flags |= SMTP_FLAG_DATA_HEADER_CONT;
    }

    return ptr;
}


/*
 * Handle DATA_BODY state
 *
 * @param   packet  standard Packet structure
 *
 * @param   i       index into p->payload buffer to start looking at data
 *
 * @return  i       index into p->payload where we stopped looking at data
 */
static const u_int8_t * SMTP_HandleDataBody(SFSnortPacket *p, const u_int8_t *ptr,
                                            const u_int8_t *data_end_marker)
{
    int boundary_found = 0;
    const u_int8_t *boundary_ptr = NULL;


    /* look for boundary */
    if (_smtp->state_flags & SMTP_FLAG_GOT_BOUNDARY)
    {
        boundary_found = _dpd.searchAPI->search_instance_find(_smtp->mime_boundary.boundary_search,
                                                              (const char *)ptr, data_end_marker - ptr,
                                                              0, SMTP_BoundaryStrFound);
        if (boundary_found > 0)
        {
            boundary_ptr = ptr + _smtp_search_info.index;

            /* should start at beginning of line */
            if ((boundary_ptr == ptr) || (*(boundary_ptr - 1) == '\n'))
            {
                const u_int8_t *eol;
                const u_int8_t *eolm;
                const u_int8_t *tmp;


                /* Check for end boundary */
                tmp = boundary_ptr + _smtp_search_info.length;
                if (((tmp + 1) < data_end_marker) && (tmp[0] == '-') && (tmp[1] == '-'))
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "Mime boundary end found: %s--\n",
                                            (char *)_smtp->mime_boundary.boundary););

                    /* no more MIME */
                    _smtp->state_flags &= ~SMTP_FLAG_GOT_BOUNDARY;

                    /* free boundary search */
                    _dpd.searchAPI->search_instance_free(_smtp->mime_boundary.boundary_search);
                    _smtp->mime_boundary.boundary_search = NULL;
                }
                else
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "Mime boundary found: %s\n",
                                            (char *)_smtp->mime_boundary.boundary););

                    _smtp->data_state = STATE_MIME_HEADER;
                }

                /* get end of line - there could be spaces after boundary before eol */
                SMTP_GetEOL(boundary_ptr + _smtp_search_info.length, data_end_marker, &eol, &eolm);

                return eol;
            }
        }
    }
        
    return data_end_marker;
}


/*
 * Process client packet
 *
 * @param   packet  standard Packet structure
 *
 * @return  none
 */
static void SMTP_ProcessClientPacket(SFSnortPacket *p)
{
    const u_int8_t *ptr = p->payload;
    const u_int8_t *end = p->payload + p->payload_size;

    if (_smtp->state == STATE_CONNECT)
        _smtp->state = STATE_COMMAND;

    while ((ptr != NULL) && (ptr < end))
    {
        switch (_smtp->state)
        {
            case STATE_COMMAND:
                DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "COMMAND STATE ~~~~~~~~~~~~~~~~~~~~~~~~~~\n"););
                ptr = SMTP_HandleCommand(p, ptr, end);
                break;
            case STATE_DATA:
                DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "DATA STATE ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"););
                ptr = SMTP_HandleData(p, ptr, end);
                break;
            case STATE_UNKNOWN:
                DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "UNKNOWN STATE ~~~~~~~~~~~~~~~~~~~~~~~~~~\n"););
                /* If state is unknown try command state to see if we can
                 * regain our bearings */
                ptr = SMTP_HandleCommand(p, ptr, end);
                break;
            default:
                DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "Bad SMTP state\n"););
                return;
        }
    }

#ifdef DEBUG
    if (_smtp_normalizing)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "Normalized payload\n%s\n", SMTP_PrintBuffer(p)););
    }
#endif

    return;
}


/* very simplistic - just enough to say this is binary data - the rules will make a final 
 * judgement.  Should maybe add an option to the smtp configuration to enable the 
 * continuing of command inspection like ftptelnet. */
static int SMTP_IsTlsClientHello(const u_int8_t *ptr, const u_int8_t *end)
{
    /* at least 3 bytes of data - see below */
    if ((end - ptr) < 3)
        return 0;

    if ((ptr[0] == 0x16) && (ptr[1] == 0x03))
    {
        /* TLS v1 or SSLv3 */
        return 1;
    }
    else if ((ptr[2] == 0x01) || (ptr[3] == 0x01))
    {
        /* SSLv2 */
        return 1;
    }

    return 0;
}

/* this may at least tell us whether the server accepted the client hello by the presence
 * of binary data */
static int SMTP_IsTlsServerHello(const u_int8_t *ptr, const u_int8_t *end)
{
    /* at least 3 bytes of data - see below */
    if ((end - ptr) < 3)
        return 0;

    if ((ptr[0] == 0x16) && (ptr[1] == 0x03))
    {
        /* TLS v1 or SSLv3 */
        return 1;
    }
    else if (ptr[2] == 0x04)
    {
        /* SSLv2 */
        return 1;
    }

    return 0;
}


/*
 * Process server packet
 *
 * @param   packet  standard Packet structure
 *
 * @return  do_flush
 * @retval  1           flush queued packets on client side
 * @retval  0           do not flush queued packets on client side
 */
static int SMTP_ProcessServerPacket(SFSnortPacket *p)
{
    int resp_found;
    const u_int8_t *ptr;
    const u_int8_t *end;
    const u_int8_t *eolm;
    const u_int8_t *eol;
    int do_flush = 0; 
    int resp_line_len;
#ifdef DEBUG
    const u_int8_t *dash;
#endif

    ptr = p->payload;
    end = p->payload + p->payload_size;

    if (_smtp->state == STATE_TLS_SERVER_PEND)
    {
        if (SMTP_IsTlsServerHello(ptr, end))
        {
            _smtp->state = STATE_TLS_DATA;
        }
        else
        {
            /* revert back to command state - assume server didn't accept STARTTLS */
            _smtp->state = STATE_COMMAND;
        }
    }
        
    if (_smtp->state == STATE_TLS_DATA)
    {
        /* Ignore data */
        if (_smtp_config.ignore_tls_data)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "Ignoring Server TLS encrypted data\n"););

            p->normalized_payload_size = 0;
            p->flags |= FLAG_ALT_DECODE;
        }

        return 0;
    }
    
    while (ptr < end)
    {
        SMTP_GetEOL(ptr, end, &eol, &eolm);

        resp_line_len = eol - ptr;

        /* Check for response code */
        _smtp_current_search = &_smtp_resp_search[0];
        resp_found = _dpd.searchAPI->search_find(SEARCH_RESP, (const char *)ptr,
                                                 resp_line_len, 1, SMTP_SearchStrFound);
        
        if (resp_found > 0)
        {
            switch (_smtp_search_info.id)
            {
                case RESP_220:
                    /* This is either an initial server response or a STARTTLS response
                     * flush the client side. if we've already seen STARTTLS, no need
                     * to flush */
                    if (_smtp->state == STATE_CONNECT)
                        _smtp->state = STATE_COMMAND;
                    else if (_smtp->state != STATE_TLS_CLIENT_PEND)
                        do_flush = 1;

                    break;

                case RESP_354:
                    do_flush = 1;

                    break;

                default:
                    break;
            }

#ifdef DEBUG
            dash = ptr + _smtp_search_info.index + _smtp_search_info.length;

            /* only add response if not a dash after response code */
            if ((dash == eolm) || ((dash < eolm) && (*dash != '-')))
            {
                DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "Server sent %s response\n", 
                                                    _smtp_resps[_smtp_search_info.id].name););
            }
#endif
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "Server response not found - see if it's SSL data\n"););

            if ((_smtp->session_flags & SMTP_FLAG_CHECK_SSL) &&
                (SMTP_IsSSL(ptr, end - ptr, p->flags)))
            {
                DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "Server response is an SSL packet\n"););

                _smtp->state = STATE_TLS_DATA;

                /* Ignore data */
                if (_smtp_config.ignore_tls_data)
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "Ignoring Server TLS encrypted data\n"););

                    p->normalized_payload_size = 0;
                    p->flags |= FLAG_ALT_DECODE;
                }

                return 0;
            }
            else if (_smtp->session_flags & SMTP_FLAG_CHECK_SSL)
            {
                _smtp->session_flags &= ~SMTP_FLAG_CHECK_SSL;
            }
        }

        if ((_smtp_config.max_response_line_len != 0) &&
            (resp_line_len > _smtp_config.max_response_line_len))
        {
            SMTP_GenerateAlert(SMTP_RESPONSE_OVERFLOW, "%s: %d chars",
                               SMTP_RESPONSE_OVERFLOW_STR, resp_line_len);
        }
       
        ptr = eol;
    }

    return do_flush;
}

static int SMTP_IsSSL(const u_int8_t *ptr, int len, int pkt_flags)
{
    u_int32_t ssl_flags = SSL_decode(ptr, len, pkt_flags);

    if ((ssl_flags != SSL_ARG_ERROR_FLAG) &&
        !(ssl_flags & SMTP_SSL_ERROR_FLAGS))
    {
        return 1;
    }

    return 0;
}


/*
 * Entry point to snort preprocessor for each packet
 *
 * @param   packet  standard Packet structure
 *
 * @return  none
 */
void SnortSMTP(SFSnortPacket *p)
{
    int detected = 0;

    PROFILE_VARS;

    /* Ignore if no data */
    if (p->payload_size == 0)
    {
#ifdef DEBUG
        int pkt_dir;
        int flags = 0;

        if (p->stream_session_ptr != NULL)
            flags = _dpd.streamAPI->get_session_flags(p->stream_session_ptr);

        pkt_dir = SMTP_GetPacketDirection(p, flags);
        DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "SMTP %s packet\n",
                                pkt_dir == SMTP_PKT_FROM_SERVER ? "server" :
                                (pkt_dir == SMTP_PKT_FROM_CLIENT ? "client" : "unknown")););
        DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "No payload to inspect\n"););
#endif
        return;
    }
    
    SMTP_Setup(p);

    if (_smtp_pkt_direction == SMTP_PKT_FROM_SERVER)
    {
        int do_flush = 0;

        DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "SMTP server packet\n"););

        /* Process as a server packet */
        do_flush = SMTP_ProcessServerPacket(p);

        if (do_flush)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "Flushing stream\n"););
            _dpd.streamAPI->response_flush_stream(p);
        }
    }
    else
    {
#ifdef DEBUG
        if (_smtp_pkt_direction == SMTP_PKT_FROM_CLIENT)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "SMTP client packet\n"););
        }
        else
        {
            DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "SMTP packet NOT from client or server! "
                                    "Processing as a client packet\n"););
        }
#endif

        /* This packet should be a tls client hello */
        if (_smtp->state == STATE_TLS_CLIENT_PEND)
        {
            if (SMTP_IsTlsClientHello(p->payload, p->payload + p->payload_size))
            {
                DEBUG_WRAP(DebugMessage(DEBUG_SMTP,
                                        "TLS DATA STATE ~~~~~~~~~~~~~~~~~~~~~~~~~\n"););

                _smtp->state = STATE_TLS_SERVER_PEND;
            }
            else
            {
                /* reset state - server may have rejected STARTTLS command */
                _smtp->state = STATE_COMMAND;
            }
        }

        if ((_smtp->state == STATE_TLS_DATA) || (_smtp->state == STATE_TLS_SERVER_PEND))
        {
            /* if we're ignoring tls data, set a zero length alt buffer */
            if (_smtp_config.ignore_tls_data)
            {
                p->normalized_payload_size = 0;
                p->flags |= FLAG_ALT_DECODE;
            }
        }
        else
        {
            if (p->flags & FLAG_STREAM_INSERT)
            {
                /* Packet will be rebuilt, so wait for it */
                DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "Client packet will be reassembled\n"));
                /* Turn off detection until we get the rebuilt packet. */
                SMTP_DisableDetect(p);
                return;
            }
            else if (_smtp_reassembling && !(p->flags & FLAG_REBUILT_STREAM))
            {
                /* If this isn't a reassembled packet and didn't get 
                 * inserted into reassembly buffer, there could be a
                 * problem.  If we miss syn or syn-ack that had window
                 * scaling this packet might not have gotten inserted
                 * into reassembly buffer because it fell outside of 
                 * window, because we aren't scaling it */
                _smtp->session_flags |= SMTP_FLAG_GOT_NON_REBUILT;
                _smtp->state = STATE_UNKNOWN;
            }
            else if (_smtp_reassembling && (_smtp->session_flags & SMTP_FLAG_GOT_NON_REBUILT))
            {
                /* This is a rebuilt packet.  If we got previous packets
                 * that were not rebuilt, state is going to be messed up
                 * so set state to unknown. It's likely this was the
                 * beginning of the conversation so reset state */
                DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "Got non-rebuilt packets before "
                                        "this rebuilt packet\n"));
                _smtp->state = STATE_UNKNOWN;
                _smtp->session_flags &= ~SMTP_FLAG_GOT_NON_REBUILT;
            }

#ifdef DEBUG
            /* Interesting to see how often packets are rebuilt */
            DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "Payload: %s\n%s\n",
                                    (p->flags & FLAG_REBUILT_STREAM) ?
                                    "reassembled" : "not reassembled",
                                    SMTP_PrintBuffer(p)););
#endif

            SMTP_ProcessClientPacket(p);
        }
    }

    PREPROC_PROFILE_START(smtpDetectPerfStats);

    detected = _dpd.detect(p);

#ifdef PERF_PROFILING
    smtpDetectCalled = 1;
#endif

    PREPROC_PROFILE_END(smtpDetectPerfStats);

    /* Turn off detection since we've already done it. */
    SMTP_DisableDetect(p);
     
    if (detected)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_SMTP, "SMTP vulnerability detected\n"););
    }
}

static void SMTP_DisableDetect(SFSnortPacket *p)
{
    _dpd.disableAllDetect(p);

    _dpd.setPreprocBit(p, PP_SFPORTSCAN);
    _dpd.setPreprocBit(p, PP_PERFMONITOR);
    _dpd.setPreprocBit(p, PP_STREAM4);
    _dpd.setPreprocBit(p, PP_STREAM5);
}


