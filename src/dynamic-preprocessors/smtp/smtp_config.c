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

/***************************************************************************
 * smtp_config.c
 *
 * Author: Andy Mullican
 * Author: Todd Wease
 *
 * Description:
 *
 * Handle configuration of the SMTP preprocessor
 *
 * Entry point functions:
 *
 *    SMTP_ParseArgs()
 *
 ***************************************************************************/

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "snort_smtp.h"
#include "smtp_config.h"
#include "bounds.h"
#include "sf_dynamic_preprocessor.h"


/*  Global variable to hold configuration */
SMTPConfig     _smtp_config;
SMTPCmdConfig *_smtp_cmd_config;

extern DynamicPreprocessorData _dpd;
extern SMTPToken *_smtp_cmds;
extern SMTPSearch *_smtp_cmd_search;
extern const SMTPToken _smtp_known_cmds[];

/* Private functions */
static void PrintConfig(void);
static int  ProcessPorts(char *, int);
static int  ProcessCmds(char *, int, int);
static int  GetCmdId(char *);
static int  AddCmd(char *name);
static int  ProcessAltMaxCmdLen(char *, int);
static int  ProcessXlink2State(char *, int);



/*
 * Function: SMTP_ParseArgs(char *)
 *
 * Purpose: Process the preprocessor arguments from the rules file and 
 *          initialize the preprocessor's data struct.  This function doesn't
 *          have to exist if it makes sense to parse the args in the init 
 *          function.
 *
 * Arguments: args => argument list
 *
 * Returns: void function
 *
 */
void SMTP_ParseArgs(char *args)
{
    int ret = 0;
    char *arg;
    char *value;
    char errStr[ERRSTRLEN];
    int errStrLen = ERRSTRLEN;

    if (args == NULL)
    {
        return;
    }

    /*  Set config to defaults */
    memset(&_smtp_config, 0, sizeof(SMTPConfig));

    _smtp_config.ports[SMTP_DEFAULT_SERVER_PORT / 8]     |= 1 << (SMTP_DEFAULT_SERVER_PORT % 8);
    _smtp_config.ports[XLINK2STATE_DEFAULT_PORT / 8]     |= 1 << (XLINK2STATE_DEFAULT_PORT % 8);
    _smtp_config.ports[SMTP_DEFAULT_SUBMISSION_PORT / 8] |= 1 << (SMTP_DEFAULT_SUBMISSION_PORT % 8);
    _smtp_config.inspection_type = SMTP_STATELESS;
    _smtp_config.max_command_line_len = DEFAULT_MAX_COMMAND_LINE_LEN;
    _smtp_config.max_header_line_len = DEFAULT_MAX_HEADER_LINE_LEN;
    _smtp_config.max_response_line_len = DEFAULT_MAX_RESPONSE_LINE_LEN;
    _smtp_config.alert_xlink2state = 1;
    _smtp_config.print_cmds = 1;

    _smtp_cmd_config = (SMTPCmdConfig *)calloc(CMD_LAST, sizeof(SMTPCmdConfig));
    if (_smtp_cmd_config == NULL)
    {
        DynamicPreprocessorFatalMessage("%s(%d) => Failed to allocate memory for SMTP "
                                        "command structure\n", 
                                        *(_dpd.config_file), *(_dpd.config_line));
    }

    *errStr = '\0';

    arg = strtok(args, CONF_SEPARATORS);
    
    while ( arg != NULL )
    {
        if ( !strcasecmp(CONF_PORTS, arg) )
        {
            ret = ProcessPorts(errStr, errStrLen);
        }
        else if ( !strcasecmp(CONF_INSPECTION_TYPE, arg) )
        {
            value = strtok(NULL, CONF_SEPARATORS);
            if ( value == NULL )
            {
                return;
            }
            if ( !strcasecmp(CONF_STATEFUL, value) )
            {
                _smtp_config.inspection_type = SMTP_STATEFUL;
            }
            else
            {
                _smtp_config.inspection_type = SMTP_STATELESS;
            }
        }
        else if ( !strcasecmp(CONF_NORMALIZE, arg) )
        {
            value = strtok(NULL, CONF_SEPARATORS);
            if ( value == NULL )
            {
                return;
            }
            if ( !strcasecmp(CONF_NONE, value) )
            {
                _smtp_config.normalize = NORMALIZE_NONE;
            }
            else if ( !strcasecmp(CONF_ALL, value) )
            {
                _smtp_config.normalize = NORMALIZE_ALL;
            }
            else
            {
                _smtp_config.normalize = NORMALIZE_CMDS;
            }
        }
        else if ( !strcasecmp(CONF_IGNORE_DATA, arg) )
        {                    
            _smtp_config.ignore_data = 1;            
        }
        else if ( !strcasecmp(CONF_IGNORE_TLS_DATA, arg) )
        {
            _smtp_config.ignore_tls_data = 1;            
        }
        else if ( !strcasecmp(CONF_MAX_COMMAND_LINE_LEN, arg) )
        {
            char *endptr;

            value = strtok(NULL, CONF_SEPARATORS);
            if ( value == NULL )
            {
                return;
            }
            
            _smtp_config.max_command_line_len = strtol(value, &endptr, 10);
        }
        else if ( !strcasecmp(CONF_MAX_HEADER_LINE_LEN, arg) )
        {
            char *endptr;

            value = strtok(NULL, CONF_SEPARATORS);
            if ( value == NULL )
            {
                return;
            }
            
            _smtp_config.max_header_line_len = strtol(value, &endptr, 10);
        }
        else if ( !strcasecmp(CONF_MAX_RESPONSE_LINE_LEN, arg) )
        {
            char *endptr;

            value = strtok(NULL, CONF_SEPARATORS);
            if ( value == NULL )
            {
                return;
            }
            
            _smtp_config.max_response_line_len = strtol(value, &endptr, 10);
        }
        else if ( !strcasecmp(CONF_NO_ALERTS, arg) )
        {     
            _smtp_config.no_alerts = 1;
        }
        else if ( !strcasecmp(CONF_ALERT_UNKNOWN_CMDS, arg) )
        {
            _smtp_config.alert_unknown_cmds = 1;
        }
        else if ( !strcasecmp(CONF_INVALID_CMDS, arg) )
        {
            /* Parse disallowed commands */
            ret = ProcessCmds(errStr, errStrLen, ACTION_ALERT);
        }
        else if ( !strcasecmp(CONF_VALID_CMDS, arg) )
        {
            /* Parse allowed commands */
            ret = ProcessCmds(errStr, errStrLen, ACTION_NO_ALERT);   
        }
        else if ( !strcasecmp(CONF_NORMALIZE_CMDS, arg) )
        {
            /* Parse normalized commands */
            ret = ProcessCmds(errStr, errStrLen, ACTION_NORMALIZE);
        }
        else if ( !strcasecmp(CONF_ALT_MAX_COMMAND_LINE_LEN, arg) )
        {
            /* Parse max line len for commands */
            ret = ProcessAltMaxCmdLen(errStr, errStrLen);
        }
        else if ( !strcasecmp(CONF_XLINK2STATE, arg) )
        {
            ret = ProcessXlink2State(errStr, errStrLen);
        }

        else if ( !strcasecmp(CONF_PRINT_CMDS, arg) )
        {
            _smtp_config.print_cmds = 1;
        }
        else
        {
            DynamicPreprocessorFatalMessage("%s(%d) => Unknown SMTP configuration option %s\n", 
                                            *(_dpd.config_file), *(_dpd.config_line), arg);
        }        

        if (ret == -1)
        {
            /*
            **  Fatal Error, log error and exit.
            */
            if (*errStr)
            {
                DynamicPreprocessorFatalMessage("%s(%d) => %s\n", 
                                                *(_dpd.config_file), *(_dpd.config_line), errStr);
            }
            else
            {
                DynamicPreprocessorFatalMessage("%s(%d) => Undefined Error.\n", 
                                                *(_dpd.config_file), *(_dpd.config_line));
            }
        }

        /*  Get next token */
        arg = strtok(NULL, CONF_SEPARATORS);
    }

    PrintConfig();
}


static void PrintConfig(void)
{
    int i;
    const SMTPToken *cmd;
    char buf[8192];

    memset(&buf[0], 0, sizeof(buf));

    _dpd.logMsg("\nSMTP Config:\n");
    
    snprintf(buf, sizeof(buf) - 1, "    Ports: ");

    for (i = 0; i < 65536; i++)
    {
        if (_smtp_config.ports[i / 8] & (1 << (i % 8)))
        {
            _dpd.printfappend(buf, sizeof(buf) - 1, "%d ", i);
        }
    }

    _dpd.logMsg("%s\n", buf);

    _dpd.logMsg("    Inspection Type: %s\n",
                _smtp_config.inspection_type ? "Stateful" : "Stateless");

    snprintf(buf, sizeof(buf) - 1, "    Normalize: ");

    switch (_smtp_config.normalize)
    {
        case NORMALIZE_ALL:
            _dpd.printfappend(buf, sizeof(buf) - 1, "all");
            break;
        case NORMALIZE_NONE:
            _dpd.printfappend(buf, sizeof(buf) - 1, "none");
            break;
        case NORMALIZE_CMDS:
            if (_smtp_config.print_cmds)
            {
                for (cmd = _smtp_cmds; cmd->name != NULL; cmd++)
                {
                    if (_smtp_cmd_config[cmd->search_id].normalize)
                    {
                        _dpd.printfappend(buf, sizeof(buf) - 1, "%s ", cmd->name);
                    }
                }
            }
            else
            {
                _dpd.printfappend(buf, sizeof(buf) - 1, "cmds");
            }
            
            break;
    }

    _dpd.logMsg("%s\n", buf);

    _dpd.logMsg("    Ignore Data: %s\n", 
               _smtp_config.ignore_data ? "Yes" : "No");
    _dpd.logMsg("    Ignore TLS Data: %s\n", 
               _smtp_config.ignore_tls_data ? "Yes" : "No");
    _dpd.logMsg("    Ignore SMTP Alerts: %s\n",
               _smtp_config.no_alerts ? "Yes" : "No");

    if (!_smtp_config.no_alerts)
    {
        snprintf(buf, sizeof(buf) - 1, "    Max Command Line Length: ");

        if (_smtp_config.max_command_line_len == 0)
            _dpd.printfappend(buf, sizeof(buf) - 1, "Unlimited");
        else
            _dpd.printfappend(buf, sizeof(buf) - 1, "%d", _smtp_config.max_command_line_len);

        _dpd.logMsg("%s\n", buf);


        if (_smtp_config.print_cmds)
        {
            int max_line_len_count = 0;
            int max_line_len = 0;

            snprintf(buf, sizeof(buf) - 1, "    Max Specific Command Line Length: ");

            for (cmd = _smtp_cmds; cmd->name != NULL; cmd++)
            {
                max_line_len = _smtp_cmd_config[cmd->search_id].max_line_len;

                if (max_line_len != 0)
                {
                    if (max_line_len_count % 5 == 0)
                    {
                        _dpd.logMsg("%s\n", buf);
                        snprintf(buf, sizeof(buf) - 1, "       %s:%d ", cmd->name, max_line_len);
                    }
                    else
                    {
                        _dpd.printfappend(buf, sizeof(buf) - 1, "%s:%d ", cmd->name, max_line_len);
                    }

                    max_line_len_count++;
                }
            }

            if (max_line_len_count == 0)
                _dpd.logMsg("%sNone\n", buf);
            else
                _dpd.logMsg("%s\n", buf);
        }

        snprintf(buf, sizeof(buf) - 1, "    Max Header Line Length: ");

        if (_smtp_config.max_header_line_len == 0)
            _dpd.logMsg("%sUnlimited\n", buf);
        else
            _dpd.logMsg("%s%d\n", buf, _smtp_config.max_header_line_len);


        snprintf(buf, sizeof(buf) - 1, "    Max Response Line Length: ");

        if (_smtp_config.max_response_line_len == 0)
            _dpd.logMsg("%sUnlimited\n", buf);
        else
            _dpd.logMsg("%s%d\n", buf, _smtp_config.max_response_line_len);
    }
    
    _dpd.logMsg("    X-Link2State Alert: %s\n",
               _smtp_config.alert_xlink2state ? "Yes" : "No");
    if (_smtp_config.alert_xlink2state)
    {
        _dpd.logMsg("    Drop on X-Link2State Alert: %s\n",
                   _smtp_config.drop_xlink2state ? "Yes" : "No");
    }

    if (_smtp_config.print_cmds && !_smtp_config.no_alerts)
    {
        int alert_count = 0;
        
        snprintf(buf, sizeof(buf) - 1, "    Alert on commands: ");

        for (cmd = _smtp_cmds; cmd->name != NULL; cmd++)
        {
            if (_smtp_cmd_config[cmd->search_id].alert)
            {
                _dpd.printfappend(buf, sizeof(buf) - 1, "%s ", cmd->name);
                alert_count++;
            }
        }

        if (alert_count == 0)
        {
            _dpd.logMsg("%sNone\n", buf);
        }
        else
        {
            _dpd.logMsg("%s\n", buf);
        }
    }
}

/*
**  NAME
**    ProcessPorts::
*/
/**
**  Process the port list.
**
**  This configuration is a list of valid ports and is ended by a 
**  delimiter.
**
**  @param ErrorString error string buffer
**  @param ErrStrLen   the length of the error string buffer
**
**  @return an error code integer 
**          (0 = success, >0 = non-fatal error, <0 = fatal error)
**
**  @retval  0 successs
**  @retval -1 generic fatal error
**  @retval  1 generic non-fatal error
*/
static int ProcessPorts(char *ErrorString, int ErrStrLen)
{
    char *pcToken;
    char *pcEnd;
    int  iPort;
    int  iEndPorts = 0;

    pcToken = strtok(NULL, CONF_SEPARATORS);
    if(!pcToken)
    {
        snprintf(ErrorString, ErrStrLen,
                "Invalid port list format.");

        return -1;
    }

    if(strcmp(CONF_START_LIST, pcToken))
    {
        snprintf(ErrorString, ErrStrLen,
                "Must start a port list with the '%s' token.",
                CONF_START_LIST);

        return -1;
    }

    /* Since ports are specified, clear default ports */
    _smtp_config.ports[SMTP_DEFAULT_SERVER_PORT / 8] &= ~(1 << (SMTP_DEFAULT_SERVER_PORT % 8));
    _smtp_config.ports[XLINK2STATE_DEFAULT_PORT / 8] &= ~(1 << (XLINK2STATE_DEFAULT_PORT % 8));
    _smtp_config.ports[SMTP_DEFAULT_SUBMISSION_PORT / 8] &= ~(1 << (SMTP_DEFAULT_SUBMISSION_PORT % 8));

    while ((pcToken = strtok(NULL, CONF_SEPARATORS)) != NULL)
    {
        if(!strcmp(CONF_END_LIST, pcToken))
        {
            iEndPorts = 1;
            break;
        }

        iPort = strtol(pcToken, &pcEnd, 10);

        /*
        **  Validity check for port
        */
        if(*pcEnd)
        {
            snprintf(ErrorString, ErrStrLen,
                     "Invalid port number.");

            return -1;
        }

        if(iPort < 0 || iPort > 65535)
        {
            snprintf(ErrorString, ErrStrLen,
                     "Invalid port number.  Must be between 0 and 65535.");

            return -1;
        }

        _smtp_config.ports[iPort / 8] |= (1 << (iPort % 8));
    }

    if(!iEndPorts)
    {
        snprintf(ErrorString, ErrStrLen,
                 "Must end '%s' configuration with '%s'.",
                 CONF_PORTS, CONF_END_LIST);

        return -1;
    }

    return 0;
}

/*
**  NAME
**    ProcessCmds::
*/
/**
**  Process the command list.
**
**  This configuration is a list of valid ports and is ended by a 
**  delimiter.
**
**  @param ErrorString error string buffer
**  @param ErrStrLen   the length of the error string buffer
**
**  @return an error code integer 
**          (0 = success, >0 = non-fatal error, <0 = fatal error)
**
**  @retval  0 successs
**  @retval -1 generic fatal error
*/
static int ProcessCmds(char *ErrorString, int ErrStrLen, int action)
{
    char *pcToken;
    int   iEndCmds = 0;
    int   id;
    
    pcToken = strtok(NULL, CONF_SEPARATORS);
    if (!pcToken)
    {
        snprintf(ErrorString, ErrStrLen, "Invalid command list format.");

        return -1;
    }

    if (strcmp(CONF_START_LIST, pcToken))
    {
        snprintf(ErrorString, ErrStrLen,
                "Must start a command list with the '%s' token.",
                CONF_START_LIST);

        return -1;
    }
    
    while ((pcToken = strtok(NULL, CONF_SEPARATORS)) != NULL)
    {
        if (strcmp(CONF_END_LIST, pcToken) == 0)
        {
            iEndCmds = 1;
            break;
        }

        id = GetCmdId(pcToken);

        if (action == ACTION_ALERT)
        {
            _smtp_cmd_config[id].alert = 1;
        }
        else if (action == ACTION_NO_ALERT)
        {
            _smtp_cmd_config[id].alert = 0;
        }
        else if (action == ACTION_NORMALIZE)
        {
            _smtp_cmd_config[id].normalize = 1;
        }
    }

    if (!iEndCmds)
    {
        snprintf(ErrorString, ErrStrLen, "Must end '%s' configuration with '%s'.",
                 action == ACTION_ALERT ? CONF_INVALID_CMDS :
                 (action == ACTION_NO_ALERT ? CONF_VALID_CMDS :
                  (action == ACTION_NORMALIZE ? CONF_NORMALIZE_CMDS : "")),
                 CONF_END_LIST);

        return -1;
    }

    return 0;
}

/* Return id associated with a given command string */
static int GetCmdId(char *name)
{
    const SMTPToken *cmd;

    for (cmd = _smtp_cmds; cmd->name != NULL; cmd++)
    {
        if (strcasecmp(cmd->name, name) == 0)
        {
            return cmd->search_id;
        }
    }
    
    return AddCmd(name);
}


static int AddCmd(char *name)
{
    static int num_cmds = CMD_LAST + 1;
    static int id = CMD_LAST;
    SMTPToken *cmds, *tmp_cmds;
    SMTPSearch *cmd_search;
    SMTPCmdConfig *cmd_config;
    int ret;

    /* allocate enough memory for new commmand - alloc one extra for NULL entry */
    cmds = (SMTPToken *)calloc(num_cmds + 1, sizeof(SMTPToken));
    if (cmds == NULL)
    {
        DynamicPreprocessorFatalMessage("%s(%d) => Failed to allocate memory for SMTP "
                                        "command structure\n", 
                                        *(_dpd.config_file), *(_dpd.config_line));
    }

    cmd_search = (SMTPSearch *)calloc(num_cmds, sizeof(SMTPSearch));
    if (cmd_search == NULL)
    {
        DynamicPreprocessorFatalMessage("%s(%d) => Failed to allocate memory for SMTP "
                                        "command structure\n", 
                                        *(_dpd.config_file), *(_dpd.config_line));
    }

    cmd_config = (SMTPCmdConfig *)calloc(num_cmds, sizeof(SMTPCmdConfig));
    if (cmd_config == NULL)
    {
        DynamicPreprocessorFatalMessage("%s(%d) => Failed to allocate memory for SMTP "
                                        "command structure\n", 
                                        *(_dpd.config_file), *(_dpd.config_line));
    }


    /* copy existing commands into newly allocated memory
     * don't need to copy anything from cmd_search since this hasn't been initialized yet */
    ret = SafeMemcpy(cmds, _smtp_cmds, id * sizeof(SMTPToken), cmds, cmds + num_cmds);
    if (ret != SAFEMEM_SUCCESS)
    {
        DynamicPreprocessorFatalMessage("%s(%d) => Failed to memory copy SMTP command structure\n", 
                                        *(_dpd.config_file), *(_dpd.config_line));
    }

    ret = SafeMemcpy(cmd_config, _smtp_cmd_config, id * sizeof(SMTPCmdConfig), cmd_config, cmd_config + num_cmds);
    if (ret != SAFEMEM_SUCCESS)
    {
        DynamicPreprocessorFatalMessage("%s(%d) => Failed to memory copy SMTP command structure\n", 
                                        *(_dpd.config_file), *(_dpd.config_line));
    }


    /* add new command to cmds
     * cmd_config doesn't need anything added - this will probably be done by a calling function
     * cmd_search will be initialized when the searches are initialized */
    tmp_cmds = &cmds[id];
    tmp_cmds->name = strdup(name);
    tmp_cmds->name_len = strlen(name);
    tmp_cmds->search_id = id;

    if (tmp_cmds->name == NULL)
    {
        DynamicPreprocessorFatalMessage("%s(%d) => Failed to allocate memory for SMTP "
                                        "command structure\n", 
                                        *(_dpd.config_file), *(_dpd.config_line));
    }


    /* free global memory structures */
    if (_smtp_cmds != NULL)
        free(_smtp_cmds);
    if (_smtp_cmd_search != NULL)
        free(_smtp_cmd_search);
    if (_smtp_cmd_config != NULL)
        free(_smtp_cmd_config);


    /* set globals to new memory */
    _smtp_cmds = cmds;
    _smtp_cmd_search = cmd_search;
    _smtp_cmd_config = cmd_config;

    ret = id;

    id++;
    num_cmds++;

    return ret;
}


/*
**  NAME
**    ProcessAltMaxCmdLen::
*/
/**
**
**   alt_max_command_line_len <int> { <cmd> [<cmd>] }
**
**  @param ErrorString error string buffer
**  @param ErrStrLen   the length of the error string buffer
**
**  @return an error code integer 
**          (0 = success, >0 = non-fatal error, <0 = fatal error)
**
**  @retval  0 successs
**  @retval -1 generic fatal error
*/
static int ProcessAltMaxCmdLen(char *ErrorString, int ErrStrLen)
{
    char *pcToken;
    char *pcLen;
    char *pcLenEnd;
    int   iEndCmds = 0;
    int   id;
    int   cmd_len;
    
    /* Find number */
    pcLen = strtok(NULL, CONF_SEPARATORS);
    if (!pcLen)
    {
        snprintf(ErrorString, ErrStrLen,
                "Invalid format for alt_max_command_line_len.");

        return -1;
    }

    pcToken = strtok(NULL, CONF_SEPARATORS);
    if (!pcToken)
    {
        snprintf(ErrorString, ErrStrLen,
                "Invalid format for alt_max_command_line_len.");

        return -1;
    }
    
    cmd_len = strtoul(pcLen, &pcLenEnd, 10);
    if (pcLenEnd == pcLen)
    {
        snprintf(ErrorString, ErrStrLen,
                "Invalid format for alt_max_command_line_len (non-numeric).");

        return -1;
    }

    if (strcmp(CONF_START_LIST, pcToken))
    {
        snprintf(ErrorString, ErrStrLen,
                "Must start alt_max_command_line_len list with the '%s' token.",
                CONF_START_LIST);

        return -1;
    }
    
    while ((pcToken = strtok(NULL, CONF_SEPARATORS)) != NULL)
    {
        if (strcmp(CONF_END_LIST, pcToken) == 0)
        {
            iEndCmds = 1;
            break;
        }
        
        id = GetCmdId(pcToken);

        _smtp_cmd_config[id].max_line_len = cmd_len;
    }

    if (!iEndCmds)
    {
        snprintf(ErrorString, ErrStrLen,
                "Must end alt_max_command_line_len configuration with '%s'.", CONF_END_LIST);
     
        return -1;
    }

    return 0;
}


/*
**  NAME
**    ProcessXlink2State::
*/
/**
**
**   xlink2state { <enable/disable> <drop> }
**
**  @param ErrorString error string buffer
**  @param ErrStrLen   the length of the error string buffer
**
**  @return an error code integer 
**          (0 = success, >0 = non-fatal error, <0 = fatal error)
**
**  @retval  0 successs
**  @retval -1 generic fatal error
*/
static int ProcessXlink2State(char *ErrorString, int ErrStrLen)
{
    char *pcToken;
    int  iEnd = 0;

    pcToken = strtok(NULL, CONF_SEPARATORS);
    if(!pcToken)
    {
        snprintf(ErrorString, ErrStrLen,
                "Invalid xlink2state argument format.");

        return -1;
    }

    if(strcmp(CONF_START_LIST, pcToken))
    {
        snprintf(ErrorString, ErrStrLen,
                "Must start xlink2state arguments with the '%s' token.",
                CONF_START_LIST);

        return -1;
    }
    
    while ((pcToken = strtok(NULL, CONF_SEPARATORS)) != NULL)
    {
        if(!strcmp(CONF_END_LIST, pcToken))
        {
            iEnd = 1;
            break;
        }

        if ( !strcasecmp(CONF_DISABLE, pcToken) )
        {
            _smtp_config.alert_xlink2state = 0;
            _smtp_config.ports[XLINK2STATE_DEFAULT_PORT / 8] &= ~(1 << (XLINK2STATE_DEFAULT_PORT % 8));
        }
        else if ( !strcasecmp(CONF_ENABLE, pcToken) )
        {
            _smtp_config.alert_xlink2state = 1;
            _smtp_config.ports[XLINK2STATE_DEFAULT_PORT / 8] |= 1 << (XLINK2STATE_DEFAULT_PORT % 8);
        }
        else if ( !strcasecmp(CONF_INLINE_DROP, pcToken) )
        {
            if (!_smtp_config.alert_xlink2state)
            {
                snprintf(ErrorString, ErrStrLen,
                         "Alerting on X-LINK2STATE must be enabled to drop.");

                return -1;
            }

            if (_dpd.inlineMode())
            {
                _smtp_config.drop_xlink2state = 1;
            }
            else
            {
                snprintf(ErrorString, ErrStrLen,
                         "Cannot use 'drop' keyword in X-LINK2STATE config "
                         "if Snort is not in inline mode.");

                return -1;
            }
        }
    }

    if(!iEnd)
    {
        snprintf(ErrorString, ErrStrLen,
                "Must end '%s' configuration with '%s'.",
                CONF_XLINK2STATE, CONF_END_LIST);

        return -1;
    }

    return 0;
}

