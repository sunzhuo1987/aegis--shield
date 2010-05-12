/* $Id$ */
/*
** Copyright (C) 2002-2008 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
** Copyright (C) 2000,2001 Andrew R. Baker <andrewb@uab.edu>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <errno.h>
#include <ctype.h>
#ifndef WIN32
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <grp.h>
#include <pwd.h>
#include <fnmatch.h>
#endif /* !WIN32 */
#include <unistd.h>

#include "src/preprocessors/flow/flow_print.h"
#include "bounds.h"
#include "rules.h"
#include "parser.h"
#include "plugbase.h"
#include "plugin_enum.h"
#include "debug.h"
#include "util.h"
#include "mstring.h"
#include "detect.h"
#include "fpcreate.h"
#include "log.h"
#include "generators.h"
#include "tag.h"
#include "signature.h"
#include "strlcatu.h"
#include "strlcpyu.h"
#include "sfthreshold.h"
#include "sfutil/sfthd.h"
#include "snort.h"
#include "inline.h"
#include "event_queue.h"
#include "asn1.h"
#include "sfutil/sfghash.h"
#include "sp_preprocopt.h"
#ifdef TARGET_BASED
#include "sftarget_reader.h"
#endif
#ifdef PORTLISTS
#include "sfutil/sfrim.h"
#include "sfutil/sfportobject.h"
#endif
#include "detection-plugins/sp_icmp_type_check.h"
#include "detection-plugins/sp_ip_proto.h"
#include "detection-plugins/sp_pattern_match.h"

#include "sf_vartable.h"
#include "ipv6_port.h"
#include "sfutil/sf_ip.h"
#include "sflsq.h"
 
#include "ppm.h"

#define MAX_RULE_OPTIONS     256
#define MAX_LINE_LENGTH    32768
#define MAX_IPLIST_ENTRIES  4096 
#define DEFAULT_LARGE_RULE_GROUP 9
#define SF_IPPROTO_UNKNOWN -1

int g_nopcre=0;

static int IsInclude(char *rule);
static int IsRule(char *rule);

/* defined in signature.h */
#ifdef PORTLISTS

// Tracking the port_list_t structure for printing and debugging at this point...temporarily...
typedef struct {
    int        rule_type;
    int        proto;
    int        icmp_type;
    int        ip_proto;
    char     * protocol;
    char     * src_port;
    char     * dst_port;
    unsigned   gid;
    unsigned   sid;
    int        dir;
    char       content;
    char       uricontent;
}port_entry_t;
    
port_entry_t   pe;

#define MAX_RULE_COUNT 65535*2

typedef struct {
    int pl_max;
    int pl_cnt;
    port_entry_t pl_array[MAX_RULE_COUNT];
}port_list_t;

port_list_t port_list=
{
    MAX_RULE_COUNT,
    0,
};

int ValidateIPList(IpAddrSet *addrset, char *token);

void port_entry_init( port_entry_t * pentry )
{
   pentry->rule_type=0;
   pentry->proto=0;
   pentry->icmp_type=0;
   pentry->ip_proto=0;
   pentry->src_port=NULL;
   pentry->dst_port=NULL;
   pentry->gid=0;
   pentry->sid=0;
   pentry->dir=0;
   pentry->content=0;
   pentry->uricontent=0;
}

void port_entry_free(port_entry_t *pentry)
{
    if (pentry->src_port)
    {
        free(pentry->src_port);
        pentry->src_port = NULL;
    }
    if (pentry->dst_port)
    {
        free(pentry->dst_port);
        pentry->dst_port = NULL;
    }
    if (pentry->protocol)
    {
        free(pentry->protocol);
        pentry->protocol = NULL;
    }
}

int port_list_add_entry( port_list_t * plist, port_entry_t * pentry)
{
    if( !plist )
    {
        port_entry_free(pentry);
        return -1;
    }

    if( plist->pl_cnt >= plist->pl_max )
    {
        port_entry_free(pentry);
        return -1;
    }

    SafeMemcpy( &plist->pl_array[plist->pl_cnt], pentry, sizeof(port_entry_t),
                &plist->pl_array[plist->pl_cnt], 
                (char*)(&plist->pl_array[plist->pl_cnt]) + sizeof(port_entry_t));
    plist->pl_cnt++;

    return 0;   
}

port_entry_t * port_list_get( port_list_t * plist, int index)
{
    if( index < plist->pl_max )
    {
        return &plist->pl_array[index];
    }
    return NULL;
}

void port_list_print( port_list_t * plist)
{
    int i;
    for(i=0;i<plist->pl_cnt;i++)
    {
        LogMessage("rule %d { ", i);
        LogMessage(" gid %u sid %u",plist->pl_array[i].gid,plist->pl_array[i].sid );
        LogMessage(" protocol %s", plist->pl_array[i].protocol);
        LogMessage(" dir %d",plist->pl_array[i].dir);
        LogMessage(" src_port %s dst_port %s ",
                plist->pl_array[i].src_port,
                plist->pl_array[i].dst_port );
        LogMessage(" content %d", 
                plist->pl_array[i].content);
        LogMessage(" uricontent %d", 
                plist->pl_array[i].uricontent);
        LogMessage(" }\n");
    }
}

void port_list_free( port_list_t * plist)
{
    int i;
    for(i=0;i<plist->pl_cnt;i++)
    {
        port_entry_free(&plist->pl_array[i]);
    }
    plist->pl_cnt = 0;
}

// end of port_list_t tracking - temporary data 

/*
 * rule counts for port lists
 */
typedef struct 
{
    int src;
    int dst;
    int aa; /* any-any */
    int sd; /* src+dst ports specified */
    int nc; /* no content */
} rule_count_t;

rule_count_t tcpCnt = {0,0,0,0,0},
             udpCnt = {0,0,0,0,0},
             icmpCnt= {0,0,0,0,0},
             ipCnt  = {0,0,0,0,0} ;

rule_index_map_t * ruleIndexMap = 0; /* rule index -> sid:gid map */
PortVarTable     * portVarTable = 0; /* named entryes, uses a hash table */
PortTable        * nonamePortVarTable = 0; /* un-named entries */

rule_port_tables_t portTables; /* master port list table */

int PortVarDefine( char * name, char * data);

void rule_index_map_print_index( int index, char *buf, int bufsize )
{
  if( index < ruleIndexMap->num_rules )
  {
      SnortSnprintfAppend(buf, bufsize, "%u:%u ",
         ruleIndexMap->map[index].gid,
         ruleIndexMap->map[index].sid);
  }
}
void print_rule_counts()
{
    LogMessage(
     "+-------------------[Rule Port Counts]---------------------------------------\n"
     "|%8s%8s%8s%8s%8s\n"
     "|%8s%8u%8u%8u%8u\n"
     "|%8s%8u%8u%8u%8u\n"
     "|%8s%8u%8u%8u%8u\n"
     "|%8s%8u%8u%8u%8u\n" 
     "|%8s%8u%8u%8u%8u\n"
     "+----------------------------------------------------------------------------\n"
     ," ","tcp","udp","icmp","ip" ,"src" ,tcpCnt.src ,udpCnt.src ,icmpCnt.src
     ,ipCnt.src ,"dst" ,tcpCnt.dst ,udpCnt.dst ,icmpCnt.dst ,ipCnt.dst ,"any"
     ,tcpCnt.aa ,udpCnt.aa ,icmpCnt.aa ,ipCnt.aa ,"nc" ,tcpCnt.nc ,udpCnt.nc
     ,icmpCnt.nc ,ipCnt.nc ,"s+d" ,tcpCnt.sd ,udpCnt.sd ,icmpCnt.sd ,ipCnt.sd
    );
}
#endif


ListHead Alert;         /* Alert Block Header */
ListHead Log;           /* Log Block Header */
ListHead Pass;          /* Pass Block Header */
ListHead Activation;    /* Activation Block Header */
ListHead Dynamic;       /* Dynamic Block Header */
ListHead Drop;
ListHead SDrop;
ListHead Reject;

RuleTreeNode *rtn_tmp;      /* temp data holder */
OptTreeNode *otn_tmp;       /* OptTreeNode temp ptr */
ListHead *head_tmp = NULL;  /* ListHead temp ptr */

RuleListNode *RuleLists;
RuleListNode *nonDefaultRules;

#ifdef SUP_IP6
vartable_t *vartable = NULL;
#endif
struct VarEntry *VarHead = NULL;

char *file_name;         /* current rules file being processed */
int file_line;           /* current line being processed in the rules
                          * file */
int rule_count=0;        /* number of rules generated */
int detect_rule_count=0; /* number of rules generated */
int decode_rule_count=0; /* number of rules generated */
int preproc_rule_count=0;/* number of rules generated */
int head_count;          /* number of header blocks (chain heads?) */
int opt_count;           /* number of chains */

int dynamic_rules_present;
int active_dynamic_nodes;

extern unsigned int giFlowbitSize; /** size of flowbits tracking */

extern SNORT_EVENT_QUEUE g_event_queue;

extern KeywordXlateList *KeywordList;   /* detection/response plugin keywords */
extern PreprocessKeywordList *PreprocessKeywords;   /* preprocessor plugin
                             * keywords */

extern SFGHASH *preprocRulesOptions;

extern OutputFuncNode *AlertList;   /* Alert function list */
extern OutputFuncNode *LogList; /* log function list */

extern OutputFuncNode *DropList;
#ifdef GIDS
extern OutputFuncNode *SDropList;
extern OutputFuncNode *RejectList;
#endif /* GIDS */

/* Local Function Declarations */
void ProcessHeadNode(RuleTreeNode *, ListHead *, int);
void ParseMetadata(char *, OptTreeNode *);
void ParseSID(char *, OptTreeNode *);
void ParseGID(char *, OptTreeNode *);
void ParseRev(char *, OptTreeNode *);
void XferHeader(RuleTreeNode *, RuleTreeNode *);
void DumpChain(RuleTreeNode *, char *, char *);
void IntegrityCheck(RuleTreeNode *, char *, char *);
void SetLinks(RuleTreeNode *, RuleTreeNode *);
int ProcessIP(char *, RuleTreeNode *, int, int);
IpAddrSet *AllocAddrNode(RuleTreeNode *, int );
int TestHeader(RuleTreeNode *, RuleTreeNode *);
RuleTreeNode *GetDynamicRTN(int, RuleTreeNode *);
OptTreeNode *GetDynamicOTN(int, RuleTreeNode *);
void FreeRuleTreeNode(RuleTreeNode *rtn);
void DestroyRuleTreeNode(RuleTreeNode *rtn);
void AddrToFunc(RuleTreeNode *, int);
void PortToFunc(RuleTreeNode *, int, int, int);
void SetupRTNFuncList(RuleTreeNode *);
static void ParsePortList(char *args);
static void ParseRuleState(char *args);
void DisallowCrossTableDuplicateVars( char *name, int rule_type); 
#ifdef DYNAMIC_PLUGIN
static void ParseDynamicEngine(char *args);
static void ParseDynamicDetection(char *args);
static void ParseDynamicPreprocessor(char *args);
static int IsInclude(char *);
static int IsRule(char *);

typedef struct _DynamicPreprocConfig
{
    char *file;
    int line_num;
    char *preproc;
    char *preproc_args;
    struct _DynamicPreprocConfig *next;
} DynamicPreprocConfig;
DynamicPreprocConfig *dynamicConfigListHead = NULL;
DynamicPreprocConfig *dynamicConfigListTail = NULL;

#endif

#ifdef PORTLISTS
/*
 *  Finish processing/setup Port Tables
 */
static
void finish_portlist_table( char * s, PortTable * pt )
{ 
       if( fpDetectGetDebugPrintRuleGroupsUnCompiled() )
       {
         LogMessage("***\n***Port-Table : %s Ports/Rules-UnCompiled\n",s);
         PortTablePrintInputEx( pt, rule_index_map_print_index );
       }
       
       PortTableCompile( pt );
  
       if( fpDetectGetDebugPrintRuleGroupsCompiled() )
       {
          LogMessage("***\n***Port-Table : %s Ports/Rules-Compiled\n",s);
          PortTablePrintCompiledEx( pt, rule_index_map_print_index ); 
          LogMessage("*** End of Compiled Group\n");
       }   
}
#endif

/****************************************************************************
 *
 * Function: ParseRulesFile(char *, int)
 *
 * Purpose:  Read the rules file a line at a time and send each rule to
 *           the rule parser
 *
 * Arguments: file => rules file filename
 *            inclevel => nr of stacked "include"s
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParseRulesFile(char *file, int inclevel, int parse_rule_lines)
{
    FILE  * thefp;        /* file pointer for the rules file */
    char  * index;        /* buffer indexing pointer */
    char  * stored_file_name = file_name;
    int     stored_file_line = file_line;
    char  * saved_line = NULL;
    int     continuation = 0;
    char  * new_line = NULL;
    struct  stat file_stat; /* for include path testing */
    char  * rule;
    char  * buf;

    if (file == NULL)
        return;
    
    rule = (char *)SnortAlloc(PARSERULE_SIZE * sizeof(char));
    buf = (char *)SnortAlloc((MAX_LINE_LENGTH + 1) * sizeof(char));

    if(inclevel == 0)
    {
#ifdef PORTLISTS
        if(!ruleIndexMap )
        {
          ruleIndexMap = RuleIndexMapCreate( MAX_RULE_COUNT );
          if(!ruleIndexMap)
          {
             FatalError("ParseRulesFile RuleIndexMapCreate() failed\n");
          }
        }
    
        /* Create the PortList Table */
        if(!portVarTable )
        {
          portVarTable=PortVarTableCreate();
          if(!portVarTable)
          {
            FatalError("ParseRulesFile PortVarTableCreate() failed\n");
          }
        }
        
        if( !nonamePortVarTable )
        {
          nonamePortVarTable = PortTableNew();
          if( !nonamePortVarTable )
          {
            FatalError("ParseRulesFile unnamed port var table creation failed\n");
          }
        }
#endif
    }

    if((inclevel == 0) && parse_rule_lines )
    {
        if(!pv.quiet_flag)
        {
            LogMessage("\n+++++++++++++++++++++++++++++++++++++++++++++++++++\n");
            LogMessage("Initializing rule chains...\n");
        }
#ifdef PORTLISTS
        /* No content rule objects */ 
        if( !portTables.tcp_nocontent )
        {
          portTables.tcp_nocontent = PortObjectNew();
          if( !portTables.tcp_nocontent )
          {
              FatalError("ParseRulesFile nocontent PortObjectNew() failed\n");
          }
          PortObjectAddPortAny( portTables.tcp_nocontent );
        }
        if( !portTables.udp_nocontent )
        {
          portTables.udp_nocontent = PortObjectNew();
          if( !portTables.udp_nocontent )
          {
              FatalError("ParseRulesFile nocontent PortObjectNew() failed\n");
          }
          PortObjectAddPortAny( portTables.udp_nocontent );
        }
        if( !portTables.icmp_nocontent )
        {
          portTables.icmp_nocontent = PortObjectNew();
          if( !portTables.icmp_nocontent )
          {
              FatalError("ParseRulesFile nocontent PortObjectNew() failed\n");
          }
          PortObjectAddPortAny( portTables.icmp_nocontent );
        }
        if( !portTables.ip_nocontent )
        {
          portTables.ip_nocontent = PortObjectNew();
          if( !portTables.ip_nocontent )
          {
              FatalError("ParseRulesFile nocontent PortObjectNew() failed\n");
          }
          PortObjectAddPortAny( portTables.ip_nocontent );
        }
        
        /* Create the Any-Any Port Objects for each protocol */
        if( !portTables.tcp_anyany )
        {
          portTables.tcp_anyany = PortObjectNew();
          if( !portTables.tcp_anyany )
          {
            FatalError("ParseRulesFile tcp any-any PortObjectNew() failed\n");
          }
         PortObjectAddPortAny( (PortObject*)portTables.tcp_anyany);
        }
        if( !portTables.udp_anyany )
        {
          portTables.udp_anyany = PortObjectNew();
          if( !portTables.udp_anyany )
          {
            FatalError("ParseRulesFile udp any-any PortObjectNew() failed\n");
          }
         PortObjectAddPortAny( (PortObject*)portTables.udp_anyany);
        }
        if( !portTables.icmp_anyany )
        {
          portTables.icmp_anyany = PortObjectNew();
          if( !portTables.icmp_anyany )
          {
            FatalError("ParseRulesFile icmp any-any PortObjectNew() failed\n");
          }
         PortObjectAddPortAny( (PortObject*) portTables.icmp_anyany);
        }
        if( !portTables.ip_anyany )
        {
          portTables.ip_anyany = PortObjectNew();
          if( !portTables.ip_anyany )
          {
            FatalError("ParseRulesFile ip PortObjectNew() failed\n");
          }
         PortObjectAddPortAny( (PortObject*)portTables.ip_anyany);
        }
        
        
        /* Create the tcp Rules PortTables */
        if( !portTables.tcp_src )
        {
          portTables.tcp_src = PortTableNew();
          if(!portTables.tcp_src)
          {
            FatalError("ParseRulesFile tcp-src PortTableNew() failed\n");
          }
        }
        if( !portTables.tcp_dst )
        {
          portTables.tcp_dst = PortTableNew();
          if(!portTables.tcp_dst)
          {
            FatalError("ParseRulesFile tcp-dst PortTableNew() failed\n");
          }
        }
        
        /* Create the udp Rules PortTables */
        if( !portTables.udp_src )
        {
          portTables.udp_src = PortTableNew();
          if(!portTables.udp_src)
          {
            FatalError("ParseRulesFile udp-src PortTableNew() failed\n");
          }
        }
        if( !portTables.udp_dst )
        {
          portTables.udp_dst = PortTableNew();
          if(!portTables.udp_dst)
          {
            FatalError("ParseRulesFile udp-dst PortTableNew() failed\n");
          }
        }
        
        /* Create the icmp Rules PortTables */
        if( !portTables.icmp_src )
        {
          portTables.icmp_src = PortTableNew();
          if(!portTables.icmp_src)
          {
            FatalError("ParseRulesFile icmp-src PortTableNew() failed\n");
          }
        }
        if( !portTables.icmp_dst )
        {
          portTables.icmp_dst = PortTableNew();
          if(!portTables.icmp_dst)
          {
            FatalError("ParseRulesFile icmp-dst PortTableNew() failed\n");
          }
        }

        /* Create the ip Rules PortTables */
        if( !portTables.ip_src )
        {
          portTables.ip_src = PortTableNew();
          if(!portTables.ip_src)
          {
            FatalError("ParseRulesFile ip-src PortTableNew() failed\n");
          }
        }
        if( !portTables.ip_dst )
        {
          portTables.ip_dst = PortTableNew();
          if(!portTables.ip_dst)
          {
            FatalError("ParseRulesFile ip-dst PortTableNew() failed\n");
          }
        }

        /*
        * someday these could be read from snort.conf, something like...
        * 'config portlist: large-rule-count <val>'
        */
        portTables.tcp_src->pt_lrc = DEFAULT_LARGE_RULE_GROUP; 
        portTables.tcp_dst->pt_lrc = DEFAULT_LARGE_RULE_GROUP; 
        portTables.udp_src->pt_lrc = DEFAULT_LARGE_RULE_GROUP; 
        portTables.udp_dst->pt_lrc = DEFAULT_LARGE_RULE_GROUP; 
        portTables.icmp_src->pt_lrc= DEFAULT_LARGE_RULE_GROUP; 
        portTables.icmp_dst->pt_lrc= DEFAULT_LARGE_RULE_GROUP; 
        portTables.ip_src->pt_lrc  = DEFAULT_LARGE_RULE_GROUP; 
        portTables.ip_dst->pt_lrc  = DEFAULT_LARGE_RULE_GROUP; 
#endif
    }

    stored_file_line = file_line;
    stored_file_name = file_name;
    file_line = 0;

    /* Init sid-gid -> otn map */
    if(  soid_otn_lookup_init() )
    {
         FatalError("ParseRulesFile soid_sg_otn_map sfghash_new failed: %s\n", 
                    strerror(errno));
    }

    /* Init sid-gid -> otn map */
    if( otn_lookup_init() )
    {
        FatalError("ParseRulesFile sg_rule_otn_map sfghash_new failed: %s\n", 
                   strerror(errno));
    }
    
    /* Changed to
     *  stat the file relative to the  current directory
     *  if that fails - stat it relative to the directory
     *  that the configuration file was in
     */ 

    file_name = SnortStrdup(file);

    /* Well the file isn't the one that we thought it was - lets
       try the file relative to the current directory
     */
    
    if(stat(file_name, &file_stat) < 0) 
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"ParseRulesFile: stat "
                                "on %s failed - going to config_dir\n", file_name););
        
        free(file_name);

        file_name = (char *)SnortAlloc((strlen(file) + strlen(pv.config_dir) + 1) * sizeof(char));

        strlcpy(file_name, pv.config_dir, strlen(file) + strlen(pv.config_dir) + 1);

        strlcat(file_name, file, strlen(file) + strlen(pv.config_dir) + 1);

        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"ParseRulesFile: Opening "
                    "and parsing %s\n", file_name););
    }

    /* open the rules file */
    if((thefp = fopen(file_name, "r")) == NULL)
    {
        FatalError("Unable to open rules file: %s or %s\n", file, 
                   file_name);
    }

    /* loop thru each file line and send it to the rule parser */
    while((fgets(buf, MAX_LINE_LENGTH, thefp)) != NULL)
    {

        /*
         * inc the line counter so the error messages know which line to
         * bitch about
         */
        file_line++;

        /* fgets always appends a null, so doing a strlen should be safe */
        if( strlen(buf)+1 == MAX_LINE_LENGTH )
        {
            FatalError("ParseRuleFile : Line %d too long, '%.*s...'\n",file_line,30,buf);
        }
        
        index = buf;

#ifdef DEBUG2
        LogMessage("Got line %s (%d): %s\n", file_name, file_line, buf);
#endif
        /* advance through any whitespace at the beginning of the line */
        while(*index == ' ' || *index == '\t')
            index++;

        if(index && 
           ( (*index == 0x0d && (strlen(index) > 1) && *(index+1) != 0x0a) ||
             (*index == 0x0d && (strlen(index) == 1))) ) 
        {
            FatalError("Carriage return ('\\\\r') found without a trailing"
                       " newline. Corrupt file?\n");
        }
          
        /* if it's not a comment or a <CR>, send it to the parser */
        if(index && (*index != '#') && (*index != 0x0a) && 
           (*index != 0x0d) && (*index != ';') )
        {
            if(continuation == 1)
            {
                if( (strlen(saved_line) + strlen(index)) > PARSERULE_SIZE )
                {
                    FatalError("ParseRuleFile : VAR/RULE too long '%.*s...' \n",30,saved_line);
                }

                new_line = (char *)SnortAlloc((strlen(saved_line) + strlen(index) + 1) * sizeof(char)); 

                strncat(new_line, saved_line, strlen(saved_line));
                strncat(new_line, index, strlen(index));
                free(saved_line);
                saved_line = NULL;
                index = new_line;

                if(strlen(index) > PARSERULE_SIZE)
                {
                    FatalError("Please don't try to overflow the parser, "
                            "that's not very nice of you... (%d-byte "
                            "limit on rule size)\n", PARSERULE_SIZE);
                }

                DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"concat rule: %s\n", 
                            new_line););
            }

            /* check for a '\' continuation character at the end of the line
             * if it's there we need to get the next line in the file
             */
            if(ContinuationCheck(index) == 0) 
            {
                DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,
                            "[*] Processing rule: %s\n", index););

                if ( IsInclude(index) )
                    ParseRule(thefp, index, inclevel, parse_rule_lines);
                else if ( parse_rule_lines && IsRule(index) )
                    ParseRule(thefp, index, inclevel, parse_rule_lines);
                else if ( !parse_rule_lines && !IsRule(index) )
                    ParseRule(thefp, index, inclevel, parse_rule_lines);

                if(new_line != NULL)
                {
                    free(new_line);
                    new_line = NULL;
                    continuation = 0;
                }
            }
            else
            {
                /* save the current line */
                saved_line = SnortStrdup(index);

                /* current line was a continuation itself... */
                if (new_line != NULL)
                {
                    free(new_line);
                    new_line = NULL;
                }

                /* set the flag to let us know the next line is 
                 * a continuation line
                 */ 
                continuation = 1;
            }   
        }

        bzero((char *)buf, MAX_LINE_LENGTH + 1);
    }

    if(file_name)
        free(file_name);

    file_name = stored_file_name;
    file_line = stored_file_line;

    /* Only print this when parsing the rule lines, not the rest of conf file */
    if(inclevel == 0 && !pv.quiet_flag && parse_rule_lines)
    {
        LogMessage("%d Snort rules read\n", rule_count);
        LogMessage("    %d detection rules\n", detect_rule_count);
        LogMessage("    %d decoder rules\n", decode_rule_count);
        LogMessage("    %d preprocessor rules\n", preproc_rule_count);
        LogMessage("%d Option Chains linked into %d Chain Headers\n",
                opt_count, head_count);
        LogMessage("%d Dynamic rules\n", dynamic_rules_present);
        LogMessage("+++++++++++++++++++++++++++++++++++++++++++++++++++\n\n");
    }

    fclose(thefp);

    /* plug all the dynamic rules together */
    if(dynamic_rules_present)
    {
        LinkDynamicRules();
    }

    if((inclevel == 0) && parse_rule_lines)
    {
#ifdef DEBUG
        DumpRuleChains();
#endif

        IntegrityCheckRules();
        /*FindMaxSegSize();*/

#ifdef PORTLISTS
       /*
        *  Compile/Finish and Print the PortList Tables
        */
       
       print_rule_counts();
       
       ///print_rule_index_map( ruleIndexMap );
       ///port_list_print( &port_list );

       /* TCP-SRC */
       if(  fpDetectGetDebugPrintRuleGroupsCompiled() )
       {
         LogMessage("***\n***TCP-Any-Any Port List\n");
         PortObjectPrintEx(portTables.tcp_anyany, rule_index_map_print_index );
       }
       finish_portlist_table("tcp src",portTables.tcp_src);
       finish_portlist_table("tcp dst",portTables.tcp_dst);
       
       /* UDP-SRC */   
       if(  fpDetectGetDebugPrintRuleGroupsCompiled() )
       {
         LogMessage("***\n***UDP-Any-Any Port List\n");
         PortObjectPrintEx(portTables.udp_anyany, rule_index_map_print_index );
       }
       finish_portlist_table( "udp src", portTables.udp_src);
       finish_portlist_table( "udp dst", portTables.udp_dst);
       
       /* ICMP-SRC */   
       if(  fpDetectGetDebugPrintRuleGroupsCompiled() )
       {
         LogMessage("ICMP-Any-Any Port List\n");
         PortObjectPrintEx(portTables.icmp_anyany, rule_index_map_print_index );
       }
       finish_portlist_table( "icmp src", portTables.icmp_src);
       finish_portlist_table( "icmp dst", portTables.icmp_dst);
       
       /* IP-SRC */   
       if(  fpDetectGetDebugPrintRuleGroupsCompiled() )
       {
         LogMessage("IP-Any-Any Port List\n");
         PortObjectPrintEx(portTables.ip_anyany, rule_index_map_print_index );
       }
       finish_portlist_table("ip src", portTables.ip_src);
       finish_portlist_table("ip dst", portTables.ip_dst);
#endif /* PORTLISTS */
    }

    otn_tmp = NULL;

    free( buf );
    free( rule );

    return;
}

int ContinuationCheck(char *rule)
{
    char *idx;  /* indexing var for moving around on the string */

    idx = rule + strlen(rule) - 1;

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"initial idx set to \'%c\'\n", 
                *idx););

    while(isspace((int)*idx))
    {
        idx--;
    }

    if(*idx == '\\')
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Got continuation char, "
                    "clearing char and returning 1\n"););

        /* clear the '\' so there isn't a problem on the appended string */
        *idx = '\x0';
        return 1;
    }

    return 0;
}


int CheckRule(char *str)
{
    int len;
    int got_paren = 0;
    int got_semi = 0;
    char *index;

    len = strlen(str);

    index = str + len - 1; /* go to the end of the string */

    while((isspace((int)*index)))
    {
        if(index > str)
            index--;
        else
            return 0;
    }

    /* the last non-whitspace character should be a ')' */
    if(*index == ')')
    {
        got_paren = 1;
        index--;
    }

    while((isspace((int)*index)))
    {
        if(index > str)
            index--;
        else
            return 0;
    }

    /* the next to last char should be a semicolon */
    if(*index == ';')
    {
        got_semi = 1;
    }

    if(got_semi && got_paren)
    {
        return 1;
    }
    else
    {
        /* check for a '(' to make sure that rule options are being used... */
        for(index = str; index < str+len; index++)
        {
            if(*index == '(')
            {
                return 0;
            }
        }

        return 1;
    }

}

void DumpRuleChains()
{
    RuleListNode *rule;

    rule = RuleLists;

    while(rule != NULL)
    {
        DumpChain(rule->RuleList->IpList, rule->name, "IP Chains");
        DumpChain(rule->RuleList->TcpList, rule->name, "TCP Chains");
        DumpChain(rule->RuleList->UdpList, rule->name, "UDP Chains");
        DumpChain(rule->RuleList->IcmpList, rule->name, "ICMP Chains");
        rule = rule->next;
    }
}

void IntegrityCheckRules()
{
    RuleListNode *rule;

    rule = RuleLists;

    if(!pv.quiet_flag)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Performing Rule "
                    "List Integrity Tests...\n"););
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"----------------"
                    "-----------------------\n"););
    }

    while(rule != NULL)
    {
        IntegrityCheck(rule->RuleList->IpList, rule->name, "IP Chains");
        IntegrityCheck(rule->RuleList->TcpList, rule->name, "TCP Chains");
        IntegrityCheck(rule->RuleList->UdpList, rule->name, "UDP Chains");
        IntegrityCheck(rule->RuleList->IcmpList, rule->name, "ICMP Chains");
        rule = rule->next;
    }

    if(!pv.quiet_flag)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,
                    "---------------------------------------\n\n"););
    }
}
#ifdef PORTLISTS

/*
 * Extract the IP Protocol field.  
*/
int GetOtnIpProto( OptTreeNode * otn )
{
   IpProtoData * IpProto;
   int           protocol = SF_IPPROTO_UNKNOWN;
       
   IpProto = (IpProtoData *)otn->ds_list[PLUGIN_IP_PROTO_CHECK];
   
   if( IpProto )
   {
      protocol = IpProto->protocol;

      if(IpProto->comparison_flag == GREATER_THAN ||
         IpProto->comparison_flag == LESS_THAN ||
         IpProto->not_flag)
          protocol = SF_IPPROTO_UNKNOWN;
   }

   return protocol;
}
/*
 * Finish adding the rule to the port tables
 *
 * 1) find the table this rule should belong to (src/dst/any-any tcp,udp,icmp,ip or nocontent)
 * 2) find an index for the sid:gid pair 
 * 3) add all no content rules to a single no content port object, the ports are irrelevant so 
 *    make it a any-any port object.
 * 4) if it's an any-any rule with content, add to an any-any port object
 * 5) find if we have a port object with these ports defined, if so get it, otherwise create it.
 *    a)do this for src and dst port 
 *    b)add the rule index/id to the portobject(s)
 *    c)if the rule is bidir add the rule and port-object to both src and dst tables
 * 
 */
int FinishPortListRule(RuleTreeNode * rtn, OptTreeNode * otn, int proto )
{
    int            rim_index;
    PortTable    * dstTable;
    PortTable    * srcTable;
    PortObject   * aaObject;
    PortObject   * ncObject;
    PortObject   * pox;
    rule_count_t * prc;
    int large_port_group=0;
    int src_cnt,dst_cnt;
    
    /* 
    * Select the Target PortTable for this rule, based on protocol, src/dst dir, 
    * and if there is rule content
    */
    if( proto == IPPROTO_TCP)
    {
        dstTable = portTables.tcp_dst;
        srcTable = portTables.tcp_src;
        aaObject = portTables.tcp_anyany;
        ncObject = portTables.tcp_nocontent;
        prc=&tcpCnt;
    }
    else if( proto == IPPROTO_UDP)
    {
        dstTable = portTables.udp_dst;
        srcTable = portTables.udp_src;
        aaObject = portTables.udp_anyany;
        ncObject = portTables.udp_nocontent;
        prc=&udpCnt;
    }
    else if( proto == IPPROTO_ICMP )
    {
        dstTable = portTables.icmp_dst;
        srcTable = portTables.icmp_src;
        aaObject = portTables.icmp_anyany;
        ncObject = portTables.icmp_nocontent;
        prc=&icmpCnt;
    }
    else if( proto ==  ETHERNET_TYPE_IP )
    {
        dstTable = portTables.ip_dst;
        srcTable = portTables.ip_src;
        aaObject = portTables.ip_anyany;
        ncObject = portTables.ip_nocontent;
        prc=&ipCnt;
    }
    else
    {
        return -1;
    }
    
    /* Count rules with both src and dst specific ports */
    if( !(rtn->flags & ANY_DST_PORT) && !(rtn->flags & ANY_SRC_PORT) ) 
    {
        DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,
                   "***\n***Info:  src & dst ports are both specific"
                   " >> gid=%u sid=%u src=%s dst=%s\n***\n",
                   otn->sigInfo.generator, otn->sigInfo.id, 
                   pe.src_port, pe.dst_port ););
        prc->sd++;
    }

    /* 
    * Create/find an index to store this rules sid and gid at,
    * and use as reference in Port Objects 
    */
    rim_index = RuleIndexMapAdd( ruleIndexMap, otn->sigInfo.generator, otn->sigInfo.id );
 
    /* 
    *  Add up the nocontent rules
    */
    if( !OtnHasContent(otn) && !OtnHasUriContent(otn) )
    {
        prc->nc++;
    }
    
    /* 
     * If not an any-any rule test for port bleedover, 
     * if we are using a single rule group, don't bother
     */
    if( !fpDetectGetSingleRuleGroup() &&
        (rtn->flags & (ANY_DST_PORT|ANY_SRC_PORT)) != (ANY_DST_PORT|ANY_SRC_PORT) ) 
    {
      src_cnt=dst_cnt=0;
      large_port_group=0;
      
      if( !(rtn->flags & ANY_SRC_PORT) ) 
      {
         src_cnt = PortObjectPortCount( rtn->src_portobject );
         if( src_cnt >= fpDetectGetBleedOverPortLimit() )
             large_port_group=1;
      } 
      if( !(rtn->flags & ANY_DST_PORT) ) 
      {
         dst_cnt = PortObjectPortCount( rtn->dst_portobject );
         if( dst_cnt >= fpDetectGetBleedOverPortLimit() )
             large_port_group=1;
      }

      if( large_port_group && fpDetectGetBleedOverWarnings() )
      {
          
          LogMessage("***Bleedover Port Limit(%d) Exceeded for rule %u:%u (%d)ports: ",
                      fpDetectGetBleedOverPortLimit(),
                      otn->sigInfo.generator,otn->sigInfo.id,
                      (src_cnt > dst_cnt) ? src_cnt : dst_cnt
                    );
          fflush(stdout);fflush(stderr);
          PortObjectPrintPortsRaw(rtn->src_portobject);
          LogMessage(" -> ");
          PortObjectPrintPortsRaw(rtn->dst_portobject);
          LogMessage(" adding to any-any group\n"); 
          fflush(stdout);fflush(stderr);
      }
    }
    
    /* 
    * If an any-any rule add rule index to any-any port object
    * both content and no-content type rules go here if they are 
    * any-any port rules...
    * If we have an any-any rule or a large port group or 
    * were using a single rule group we make it an any-any rule.
    */
    if( ((rtn->flags & (ANY_DST_PORT|ANY_SRC_PORT))==(ANY_DST_PORT|ANY_SRC_PORT)) ||
        large_port_group ||
        fpDetectGetSingleRuleGroup() )
    {
        if( proto ==  ETHERNET_TYPE_IP )
        {
            /* Add the IP rules to the higher level app protocol groups, if they apply 
             * to those protocols.  All IP rules should have any-any port descriptors
             * and fall into this test.  IP rules that are not tcp/udp/icmp go only into the 
             * IP table
             */
            int ip_proto;

            ip_proto = GetOtnIpProto(otn);

            DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,
                       "Finishing IP any-any rule %u:%u\n",
                       otn->sigInfo.generator,otn->sigInfo.id););

            /* Add to TCP-anyany*/
            if( ip_proto == IPPROTO_TCP  || ip_proto == -1  )
            {
                PortObjectAddRule(portTables.tcp_anyany,rim_index);
                tcpCnt.aa++;
            }
            
            /* Add to UDP-anyany*/
            if( ip_proto == IPPROTO_UDP || ip_proto == -1  )  
            {
                PortObjectAddRule(portTables.udp_anyany,rim_index);
                udpCnt.aa++;
            }
            
            /* Add to ICMP-anyany*/
            if( ip_proto == IPPROTO_ICMP || ip_proto == -1  )  
            {
                PortObjectAddRule(portTables.icmp_anyany,rim_index);
                icmpCnt.aa++;
            }

            /* Add to the IP ANY ANY */
            PortObjectAddRule( (PortObject*)aaObject, rim_index );
            prc->aa++;
        }
        else
        {
           /* For other protocols-tcp/udp/icmp add to the any any group */
           PortObjectAddRule( (PortObject*)aaObject, rim_index );
           prc->aa++;
        }
        
        return 0; /* done */
    }

    /* add rule index to dst table if we have a specific dst port or port list */
    if( !(rtn->flags & ANY_DST_PORT)  ) 
    {
        prc->dst++;
        DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,
                   "Finishing rule: dst port rule\n"););

        /* find the proper port object */
        pox = PortTableFindInputPortObjectPorts( dstTable, rtn->dst_portobject );
        if( !pox )
        {
            /* Create a permanent port object */
            pox = PortObjectDupPorts(rtn->dst_portobject); 
            if( !pox )
                FatalError("Could not dup a port object - out of memory!\n");
            /* Add the port object to the table, and add the rule to the port object */
            PortTableAddObject( dstTable, pox);
        }
        PortObjectAddRule( (PortObject*)pox, rim_index );

        /* if bidir, add this rule and port group to the src table */
        if( rtn->flags & BIDIRECTIONAL ) 
        {
           pox = PortTableFindInputPortObjectPorts( srcTable, rtn->dst_portobject );
           if( !pox )
           {
              pox = PortObjectDupPorts(rtn->dst_portobject); 
              if( !pox )
                FatalError("Could not dup a bidir-port object - out of memory!\n");
              PortTableAddObject( srcTable, pox );
           }
           PortObjectAddRule( (PortObject*)pox, rim_index );
        }
    }

    /* add rule index to src table if we have a specific src port or port list */
    if( !(rtn->flags & ANY_SRC_PORT)  ) 
    {
        prc->src++;

        pox = PortTableFindInputPortObjectPorts( srcTable, rtn->src_portobject );
        if( !pox )
        {
            pox = PortObjectDupPorts(rtn->src_portobject); 
            if( !pox )
                FatalError("Could not dup a port object - out of memory!\n");
            PortTableAddObject( srcTable, pox);
        }
        PortObjectAddRule( (PortObject*)pox, rim_index );

        /* if bidir, add this rule and port group to the dst table */
        if( rtn->flags & BIDIRECTIONAL ) 
        {
           pox = PortTableFindInputPortObjectPorts( dstTable, rtn->src_portobject );
           if(! pox )
           {
             pox = PortObjectDupPorts(rtn->src_portobject); 
             if( !pox )
                FatalError("Could not dup a bidir-port object - out of memory!\n");
             PortTableAddObject( dstTable, pox);
           }
           PortObjectAddRule( (PortObject*)pox, rim_index );
        }
    }

    
    return 0;
}
/*
*  Parse a port string as a port var, and create or find a port object for it, 
*  and add it to the port var table. These are used by the rtn's
*  as src and dst port lists for final rtn/otn processing.
*
*  These should not be confused with the port objects used to merge ports and rules
*  to build PORT_GROUP objects. Those are generated after the otn processing.
*  
*/
PortObject * ParsePortListTcpUdpPort( char * port_str )
{
    PortObject * portobject;
    //PortObject * pox;
    char       * errstr=0;
    POParser     poparser;
    
    /* 1st - check if we have an any port */
    if( strcasecmp(port_str,"any")== 0 ) 
    {
        portobject = PortVarTableFind( portVarTable, "any" );
        if(!portobject)
        {
            FatalError("%s(%d) PortVarTable missing an 'any' variable\n",
                file_name, file_line);
        }
        return portobject;
    }

    /* 2nd - check if we have a PortVar */
    else if( port_str[0]=='$' ) 
    { 
      /*||isalpha(port_str[0])*/ /*TODO: interferes with protocol names for ports*/
      char * name = port_str;

      if( name[0]=='$' ) name++; /* in case this is allowed */
      
      DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"PortVarTableFind: finding '%s'\n", port_str););

      /* look it up  in the port var table */
      portobject = PortVarTableFind( portVarTable, name );
      if( !portobject )
      {
          FatalError("%s(%d) ***Src PortVar Lookup failed on '%s'\n",
            file_name, file_line, name);
      }
      DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"PortVarTableFind: '%s' found!\n", port_str););
    }
    
    /* 3rd -  and finally process a raw port list */
    else  
    {   
       /* port list = [p,p,p:p,p,...] or p or p:p , no embedded spaces due to tokenizer */ 
       PortObject * pox;
       
       DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,
                 "parser.c->PortObjectParseString: parsing '%s'\n",port_str););
      
       portobject = PortObjectParseString( portVarTable, &poparser, 0, port_str, 0 );
      
       DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,
                 "parser.c->PortObjectParseString: '%s' done.\n",port_str););
       
       if( !portobject )
       {
          errstr = PortObjectParseError( &poparser );
          FatalError("%s(%d) ***Rule--PortVar Parse error: (pos=%d,error=%s)\n>>%s\n>>%*s\n",
                file_name, file_line,
                poparser.pos,errstr,port_str,poparser.pos,"^");
       }

       /* check if we already have this port object in the un-named port var table  ... */
       pox = PortTableFindInputPortObjectPorts( nonamePortVarTable, portobject ); 
       if( pox )
       {
         DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,
                    "parser.c: already have '%s' as a PortObject - "
                    "calling PortObjectFree(portbject) line=%d\n",port_str,__LINE__ ););
         PortObjectFree( portobject );
         portobject = pox;
       }
       else
       {
           DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS, 
                "parser.c: adding '%s' as a PortObject line=%d\n",port_str,__LINE__ ););
           /* Add to the un-named port var table */
           if( PortTableAddObject( nonamePortVarTable, portobject ) )
           {
               FatalError("unable to add raw port object to unnamed port var table, out of memory!");
           }
       }
    }
    return portobject;
}
#ifdef XXXXX
/*
* Extract the Icmp Type field to determine the PortGroup.  
*/
PortObject * GetPortListIcmpPortObject( OptTreeNode * otn, PortTable *  rulesPortTable, PortObject * anyAnyPortObject )
{
   PortObject        * portobject=0;
   int                 type;
   IcmpTypeCheckData * IcmpType;
       
   IcmpType = (IcmpTypeCheckData *)otn->ds_list[PLUGIN_ICMP_TYPE];
   
   if( IcmpType && (IcmpType->operator == ICMP_TYPE_TEST_EQ) )
   {
       type = IcmpType->icmp_type;
   } 
   else
   {
       return anyAnyPortObject;
   }

   /* TODO: optimize */
   return anyAnyPortObject;
}
/*
 * Extract the IP Protocol field to determine the PortGroup.  
*/
PortObject * GetPortListIPPortObject( OptTreeNode * otn,PortTable *  rulesPortTable, PortObject * anyAnyPortObject )
{
   PortObject  * portobject=0;
   IpProtoData * IpProto;
   int           protocol;
       
   IpProto = (IpProtoData *)otn->ds_list[PLUGIN_IP_PROTO_CHECK];
   
   if( IpProto )
   {
      protocol = IpProto->protocol;

      if( IpProto->comparison_flag == GREATER_THAN )
          protocol=-1;
                                                                                                   
      if( IpProto->comparison_flag == LESS_THAN )
          protocol=-1;

      if( IpProto->not_flag )
          protocol=-1;
   }
   else
   {
      protocol = -1;
   }

   if( protocol == -1 )
       return anyAnyPortObject;
       
   /* TODO: optimize */
   return anyAnyPortObject;
}
/*
* Extract the Icmp Type field to determine the PortGroup.  
*/
static 
int GetOtnIcmpType(OptTreeNode * otn )
{
   int                 type;
   IcmpTypeCheckData * IcmpType;
       
   IcmpType = (IcmpTypeCheckData *)otn->ds_list[PLUGIN_ICMP_TYPE];
   
   if( IcmpType && (IcmpType->operator == ICMP_TYPE_TEST_EQ) )
   {
       type = IcmpType->icmp_type;
   } 
   else
   {
       return -1;
   }

   return -1;
}

#endif /*  XXXX - PORTLISTS */
/*
 *   Process the rule, add it to the appropriate PortObject
 *   and add the PortObject to the rtn.
 *
 *   TCP/UDP rules use ports/portlists, icmp uses the icmp type field and ip uses the protocol
 *   field as a dst port for the purposes of looking up a rule group as packets are being
 *   processed.
 * 
 *   TCP/UDP- use src/dst ports
 *   ICMP   - use icmp type as dst port,src=-1
 *   IP     - use protocol as dst port,src=-1
 *
 *   rtn - proto_node
 *   port_str - port list string or port var name
 *   proto - protocol
 *   dst_flag - dst or src port flag, true = dst, false = src
 *
 */
int ParsePortListPort( RuleTreeNode * rtn,  char * port_str, int proto, int dst_flag )
{
    PortObject  * portobject=0;/* src or dst */

    /* Get the protocol specific port object */
    if( proto == IPPROTO_TCP || proto == IPPROTO_UDP )
    {
        portobject = ParsePortListTcpUdpPort( port_str ); 
    }
    else /* ICMP, IP  - no real ports just Type and Protocol */
    {
        portobject = PortVarTableFind( portVarTable, "any" );
        if(!portobject)
        {
            FatalError("PortVarTable missing an 'any' variable\n");
        }
    }
    DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"Rule-PortVar Parsed: %s \n",port_str););
    
    /* !ports - port lists can be mixed 80:90,!82, 
    * so the old NOT flag is depracated for port lists 
    */

    /* set up any any flags */
    if( PortObjectHasAny(portobject) )
    {
         if( dst_flag )
             rtn->flags |= ANY_DST_PORT;
         else
             rtn->flags |= ANY_SRC_PORT;
    }

    /* check for a pure not rule - fatal if we find one */ 
    if( PortObjectIsPureNot( portobject ) )
    {
      FatalError("Pure NOT ports are not allowed!\n");
      /*
      if( dst_flag )
        rtn->flags |= EXCEPT_DST_PORT;
      else
        rtn->flags |= EXCEPT_SRC_PORT;
      */
    }
        
    
    /* 
    * set to the port object for this rules src/dst port,
    * these are used during rtn/otn port verification of the rule.
    */
    if( dst_flag )
         rtn->dst_portobject = portobject;
    else
         rtn->src_portobject = portobject;
    
    return 0;
}

#endif /* PORTLISTS */


/****************************************************************************
 *
 * Function: CheckForIPListConflicts
 *
 * Purpose:  Checks For IP List Conflicts in a RuleTreeNode.  Such as
 *           negations that are overlapping and more general are not allowed.
 *
 *             For example, the following is not allowed: 
 *
 *                  [1.1.0.0/16,!1.0.0.0/8]
 *
 *             The following is allowed though (not overlapping):
 *
 *                  [1.1.0.0/16,!2.0.0.0/8]
 *
 * Arguments: addrset -- IpAddrSet pointer.
 *
 * Returns: -1 if IP is empty, 1 if a conflict exists and 0 otherwise.
 *
 ***************************************************************************/
int CheckForIPListConflicts(IpAddrSet *addrset)
{
#ifdef SUP_IP6
    /* Conflict checking takes place inside the SFIP library */
    return 0;
#else
    IpAddrNode *idx = NULL, *neg_idx = NULL;
    
    if( !addrset ) return( -1 );
  
    if(!addrset->iplist || !addrset->neg_iplist)
        return 0;
    
    for(idx = addrset->iplist; idx; idx = idx->next) 
    {
        for(neg_idx = addrset->neg_iplist; neg_idx; neg_idx = neg_idx->next)
        {
            /* A smaller netmask means "less specific" */
            if(neg_idx->netmask <= idx->netmask &&
                /* Verify they overlap */
                ((neg_idx->ip_addr & neg_idx->netmask) == 
                 (idx->ip_addr & neg_idx->netmask)))
            {
                return 1;
            }
        }
    }
    
    return 0;
#endif
}

#ifdef SHUTDOWN_MEMORY_CLEANUP
void DeleteHeadNode(ListHead *list)
{
    RuleTreeNode *rtn_idx, *rtn_tmp;

    rtn_idx = list->TcpList;
    while (rtn_idx)
    {
        rtn_tmp = rtn_idx;
        rtn_idx = rtn_tmp->right;
        DestroyRuleTreeNode(rtn_tmp);
    }

    rtn_idx = list->UdpList;
    while (rtn_idx)
    {
        rtn_tmp = rtn_idx;
        rtn_idx = rtn_tmp->right;
        DestroyRuleTreeNode(rtn_tmp);
    }

    rtn_idx = list->IcmpList;
    while (rtn_idx)
    {
        rtn_tmp = rtn_idx;
        rtn_idx = rtn_tmp->right;
        DestroyRuleTreeNode(rtn_tmp);
    }

    rtn_idx = list->IpList;
    while (rtn_idx)
    {
        rtn_tmp = rtn_idx;
        rtn_idx = rtn_tmp->right;
        DestroyRuleTreeNode(rtn_tmp);
    }
}

void DeleteRuleTreeNodes()
{
    RuleListNode *tmpNode, *node = RuleLists;

    DeleteHeadNode(&Drop);
#ifdef GIDS
    DeleteHeadNode(&SDrop);
    DeleteHeadNode(&Reject);
#endif /* GIDS */         
    DeleteHeadNode(&Alert);
    DeleteHeadNode(&Log);
    DeleteHeadNode(&Pass);
    DeleteHeadNode(&Activation);
    DeleteHeadNode(&Dynamic);

    /* Iterate through the user-defined types */
    while (node)
    {
        tmpNode = node->next;
        if ((node->RuleList != &Drop) &&
#ifdef GIDS
            (node->RuleList != &SDrop) &&
            (node->RuleList != &Reject) &&
#endif /* GIDS */
            (node->RuleList != &Alert) &&
            (node->RuleList != &Log) &&
            (node->RuleList != &Pass) &&
            (node->RuleList != &Activation) &&
            (node->RuleList != &Dynamic))
        {
            DeleteHeadNode(node->RuleList);
        }
        if (node->name)
            free(node->name);
        free(node);
        node = tmpNode;
    }
    RuleLists = NULL;
}
#endif

/****************************************************************************
 *
 * Function: ParseRule(FILE*, char *, int)
 *
 * Purpose:  Process an individual rule and add it to the rule list
 *
 * Arguments: rule => rule string
 *            inclevel => nr of stacked "include"s
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParseRule(FILE *rule_file, char *prule, int inclevel, int parse_rule_lines)
{
    char **toks;        /* dbl ptr for mSplit call, holds rule tokens */
    int num_toks;       /* holds number of tokens found by mSplit */
    int rule_type;      /* rule type enumeration variable */
    int protocol = 0;
    char *tmp;
    RuleTreeNode proto_node;
    RuleListNode *node = RuleLists;
    char *  rule=0;
#ifndef PORTLISTS
    int ret;
#endif
    
#define PREPROCESOR_RULES    
#ifdef  PREPROCESOR_RULES    
    int preprocessor_rule=0;
#endif
    if( !prule)
      return;
  
    /* chop off the <CR/LF> from the string */
    strip(prule);

    rule = SnortStrdup( ExpandVars(prule) );

    if( !rule )
    {
        FatalError(" ParseRule : ran out of 'rule' memory\n");
    }

    /* break out the tokens from the rule string */
    if( (toks = mSplit(rule, " ", 10, &num_toks, 0)) == NULL )
        return;

    /* clean house */
    bzero((char *) &proto_node, sizeof(RuleTreeNode));

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"[*] Rule start\n"););

    /* figure out what we're looking at */
    rule_type = RuleType(toks[0]);

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Rule type: "););

#ifdef PORTLISTS
    port_entry_init(&pe);
#endif
    /* 
     * PortVars do their expansion and PortVar referencing, so we disable expansion 
     * of the VARs in macro definitions and for rules when we use port lists.
     */ 
    switch(rule_type)
    {
        case RULE_VAR:
#ifdef PORTLISTS
        case RULE_PORTVAR:
#endif
#ifdef SUP_IP6
        case RULE_IPVAR:
#endif
            
        case RULE_DROP:
        case RULE_SDROP:
        case RULE_REJECT:
        case RULE_PASS:
        case RULE_ALERT:
        case RULE_LOG:
        case RULE_UNKNOWN: /* in case it's declared */
            /* clean up rule and toks */
            free(rule);
            mSplitFree(&toks, num_toks);

            /* Don't do early expansion in PortLists for Rules */
            DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"ParseRule:: unknown rule=%s\n",prule););
            rule = strdup(prule);
            if( !rule )
            {
               FatalError(" ParseRule : ran out of 'rule' memory\n");
            }
            DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"ParseRule:: expanded unknown rule=%s\n",rule););

            /* break out the tokens from the rule string */
            toks = mSplit(rule, " ", 10, &num_toks, 0);
            break;
        default:
            break;
    }

    /* handle non-rule entries */
    switch(rule_type)
    {
        case RULE_DROP:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Drop\n"););

            /* if we are not listening to iptables, let's ignore
             * any drop rules in the configuration file */
            if (!InlineMode())
            {
                mSplitFree(&toks, num_toks);
                free(rule);
                return;
            }
            break;
                
#ifdef GIDS
        case RULE_SDROP:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"SDrop\n"););
              
            /* if we are not listening to iptables, let's ignore
             * any sdrop rules in the configuration file */
            if (!InlineMode())
            {
                mSplitFree(&toks, num_toks);
                free(rule);
                return;
            }
            break;
                
        case RULE_REJECT:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Reject\n"););
              
            /* if we are not listening to iptables, let's ignore
             * any reject rules in the configuration file */
            if (!InlineMode())
            {
                mSplitFree(&toks, num_toks);
                free(rule);
                return;
            }
            break;
#endif /* GIDS */
                
        case RULE_PASS:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Pass\n"););
            break;

        case RULE_LOG:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Log\n"););
            break;
        case RULE_ALERT:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Alert\n"););
            break;

        case RULE_INCLUDE:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Include\n"););
            if(*toks[1] == '$')
            {
                if((tmp = VarGet(toks[1]+1)) == NULL)
                {
                    FatalError("%s(%d) => Undefined variable %s\n", 
                               file_name, file_line, toks[1]);
                }
            }
            else
            {
                tmp = toks[1];
            }

            ParseRulesFile(tmp, inclevel + 1, parse_rule_lines);
            mSplitFree(&toks, num_toks);
            free(rule);
            return;

#ifdef PORTLISTS
        case RULE_PORTVAR:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"PortVar\n"););
            if(num_toks < 3) 
            {
                FatalError("%s(%d) => Missing argument to %s\n", 
                           file_name, file_line, toks[1]);
                return;
            }
            PortVarDefine(toks[1],toks[2] );
            mSplitFree(&toks, num_toks);
            free(rule);
            return;
#endif

#ifdef SUP_IP6
       case RULE_IPVAR:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"IpVar\n"););
            if(num_toks < 3) 
            {
                FatalError("%s(%d) => Missing argument to %s\n", 
                           file_name, file_line, toks[1]);
                return;
            }
            DisallowCrossTableDuplicateVars(toks[1], rule_type);
            sfvt_define(vartable, toks[1], toks[2] );
            mSplitFree(&toks, num_toks);
            free(rule);
            return;
#endif
            
        case RULE_VAR:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Variable\n"););
            if(num_toks < 3) 
            {
                FatalError("%s(%d) => Missing argument to %s\n", 
                           file_name, file_line, toks[1]);
                return;
            }

#ifdef PORTLISTS
           //TODO: snort.cfg and rules should use PortVar instead ...this allows compatability for now.
            if( strstr(toks[1],"_PORT") || strstr(toks[1],"PORT_") )
            {
              DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"PortVar\n"););
              PortVarDefine( toks[1],toks[2] );
            }
            else
#endif
            VarDefine(toks[1], toks[2]);
            mSplitFree(&toks, num_toks);
            free(rule);
            return;

        case RULE_PREPROCESS:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Preprocessor\n"););
            ParsePreprocessor(rule);
            mSplitFree(&toks, num_toks);
            free(rule);
            return;

        case RULE_OUTPUT:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Output Plugin\n"););
            ParseOutputPlugin(rule);
            mSplitFree(&toks, num_toks);
            free(rule);
            return;

        case RULE_ACTIVATE:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Activation rule\n"););
            break;

        case RULE_DYNAMIC:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Dynamic rule\n"););
            break;

        case RULE_CONFIG:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Rule file config\n"););
            ParseConfig(rule);
            mSplitFree(&toks, num_toks);
            free(rule);
            return;

        case RULE_DECLARE:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Rule type declaration\n"););
            ParseRuleTypeDeclaration(rule_file, rule);
            mSplitFree(&toks, num_toks);
            free(rule);
            return;
 
        case RULE_THRESHOLD:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Threshold\n"););
            ParseSFThreshold(rule);
            mSplitFree(&toks, num_toks);
            free(rule);
            return;
        
        case RULE_SUPPRESS:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Suppress\n"););
            ParseSFSuppress(rule);
            mSplitFree(&toks, num_toks);
            free(rule);
            return;
 
        case RULE_UNKNOWN:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Unknown rule type, might be declared\n"););

            /* find out if this ruletype has been declared */
            while(node != NULL)
            {
                if(!strcasecmp(node->name, toks[0]))
                    break;
                node = node->next;
            }

            if(node == NULL)
            {
                 FatalError("%s(%d) => Unknown rule type: %s\n",
                            file_name, file_line, toks[0]);
            }

            break; 

        case RULE_STATE:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"RuleState\n"););
            if (num_toks == 2)
                ParseRuleState(toks[1]);
            else
                FatalError("%s(%d) => Missing parameters for rule_state\n", 
                           file_name, file_line);

            mSplitFree(&toks, num_toks);
            free(rule);
            return;

#ifdef DYNAMIC_PLUGIN
        case RULE_DYNAMICENGINE:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"DynamicEngine\n"););
            ParseDynamicEngine(rule);
            mSplitFree(&toks, num_toks);
            free(rule);
            return;

        case RULE_DYNAMICDETECTION:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"DynamicDetection\n"););
            ParseDynamicDetection(rule);
            mSplitFree(&toks, num_toks);
            free(rule);
            return;

        case RULE_DYNAMICPREPROCESSOR:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"DynamicPreprocessor\n"););
            ParseDynamicPreprocessor(rule);
            mSplitFree(&toks, num_toks);
            free(rule);
            return;
#endif

#ifdef TARGET_BASED
        case RULE_ATTRIBUTE_TABLE:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"AttributeTable\n"););
            SFAT_ParseAttributeTable(rule);
            mSplitFree(&toks, num_toks);
            free(rule);
            return;
#endif
        default:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Invalid input: %s\n", prule););
            mSplitFree(&toks, num_toks);
            free(rule);
            return;
    }

#ifdef PREPROCESOR_RULES    
    if ( toks[1][0] == '(')
    {
        /* We have a preproc or decoder rule - we assume a header of 'tcp any any -> any any ' */
        preprocessor_rule=1;
    }
    else
    {
        preprocessor_rule=0;
    }
        
    if( preprocessor_rule && (num_toks < 2))
    {
        FatalError("%s(%d): Bad rule in rules file\n", file_name, file_line);
    }
    else
#endif 
    if( num_toks < 7 )
    {
        FatalError("%s(%d): Bad rule in rules file\n", file_name, file_line);
    }
    
    if(!CheckRule(prule))
    {
        FatalError("Unterminated rule in file %s, line %d\n" 
                   "   (Snort rules must be contained on a single line or\n"
                   "    on multiple lines with a '\\' continuation character\n"
                   "    at the end of the line,  make sure there are no\n"
                   "    carriage returns before the end of this line)\n",
                   file_name, file_line);
        return;
    }
    
    if (rule_type == RULE_UNKNOWN)
        proto_node.type = node->mode;
    else
        proto_node.type = rule_type;
    
#ifdef PREPROCESOR_RULES    
    if( preprocessor_rule )
    {
        proto_node.flags |= ANY_DST_PORT;
        proto_node.flags |= ANY_SRC_PORT;
        proto_node.flags |= ANY_DST_IP;
        proto_node.flags |= ANY_SRC_IP;
        protocol = IPPROTO_TCP;
        proto_node.flags |= BIDIRECTIONAL;

        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES, "Preprocessor Rule detected\n"););
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES, "Non-Preprocessor Rule detected\n"););
#endif        
   
    /* set the rule protocol */
    protocol = WhichProto(toks[1]);
    
    // PORTLISTS
    proto_node.proto = protocol;

    /* Process the IP address and CIDR netmask */
    /* changed version 1.2.1 */
    /*
     * "any" IP's are now set to addr 0, netmask 0, and the normal rules are
     * applied instead of checking the flag
     */
    /*
     * if we see a "!<ip number>" we need to set a flag so that we can
     * properly deal with it when we are processing packets
     */
    /* we found a negated address */
    /* if( *toks[2] == '!' )    
       {
       proto_node.flags |= EXCEPT_SRC_IP;
       ProcessIP(&toks[2][1], &proto_node, SRC);
       }
       else
       {*/
    ProcessIP(toks[2], &proto_node, SRC, 0);

    /* Make sure the IP lists provided by the user are valid */
    ValidateIPList(proto_node.sip, toks[2]);
    /*}*/

    /* check to make sure that the user entered port numbers */
    /* sometimes they forget/don't know that ICMP rules need them */
    if(!strcasecmp(toks[3], "->") ||
       !strcasecmp(toks[3], "<>"))
    {
        FatalError("%s:%d => Port value missing in rule!\n", 
                   file_name, file_line);
    }

#ifdef PORTLISTS
    DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"Src-Port: %s\n",toks[3]););
   
    if( ParsePortListPort( &proto_node, toks[3], protocol,  0 /* =src port */ ) )
    {
        FatalError("ParsePortListPort error src-port: '%s'\n",toks[3]);
    }
#else
    /* do the same for the port */
    ret = ParsePort(toks[3], (u_short *) & proto_node.hsp,
                (u_short *) & proto_node.lsp, toks[1],
                (int *) &proto_node.not_sp_flag);
    if(ret > 0)
    {
        proto_node.flags |= ANY_SRC_PORT;
    } 
    else if(ret < 0) 
    {
        mSplitFree(&toks, num_toks);
        FreeRuleTreeNode(&proto_node);
        free(rule);
        return;
    }

    if(proto_node.not_sp_flag)
        proto_node.flags |= EXCEPT_SRC_PORT;
#endif

    /* New in version 1.3: support for bidirectional rules */
    /*
     * this checks the rule "direction" token and sets the bidirectional flag
     * if the token = '<>'
     */
    if(!strncmp("<>", toks[4], 2))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Bidirectional rule!\n"););
        proto_node.flags |= BIDIRECTIONAL;
    }
    
    /* changed version 1.8.4
     * Die when someone has tried to define a rule character other than
       -> or <>
    */
    if(strcmp("->", toks[4]) && strcmp("<>", toks[4]))
    {
        FatalError("%s(%d): Illegal direction specifier: %s\n", file_name, 
                file_line, toks[4]);
    }


    /* changed version 1.2.1 */
    /*
     * "any" IP's are now set to addr 0, netmask 0, and the normal rules are
     * applied instead of checking the flag
     */
    /*
     * if we see a "!<ip number>" we need to set a flag so that we can
     * properly deal with it when we are processing packets
     */
    /* we found a negated address */
    ProcessIP(toks[5], &proto_node, DST, 0);

    /* Make sure the IP lists provided by the user are valid */
    ValidateIPList(proto_node.dip, toks[5]);

#ifdef PORTLISTS
    DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,"Dst-Port: %s\n",toks[6]););

    if( ParsePortListPort( &proto_node, toks[6], protocol, 1 /* =dst port */ ) )
    {
        FatalError("ParsePortListPort error dst-port: '%s'\n",toks[6]);
    }
#else
    ret = ParsePort(toks[6], (u_short *) & proto_node.hdp,
                (u_short *) & proto_node.ldp, toks[1],
                (int *) &proto_node.not_dp_flag);
    if(ret > 0)
    {
        proto_node.flags |= ANY_DST_PORT;
    } 
    else if(ret < 0)
    {
        mSplitFree(&toks, num_toks);
        FreeRuleTreeNode(&proto_node);
        free(rule);
        return;
    }
    if(proto_node.not_dp_flag)
        proto_node.flags |= EXCEPT_DST_PORT;
#endif

    /* if there is anything beyond the dst port, it must begin with "(" */
    if (num_toks > 7 && toks[7][0] != '(')
    {
        FatalError("%s(%d): The rule option section (starting with a '(') must "
                   "follow immediately after the destination port.  "
                   "This means port lists are not supported.\n",
                   file_name, file_line);
    }


#ifdef PREPROCESOR_RULES    
    } /* if ( !preprocessor_rule */
#endif

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"proto_node.flags = 0x%X\n", proto_node.flags););
    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Processing Head Node....\n"););

    switch(rule_type)
    {
        case RULE_DROP:
            if (InlineMode())
            {
                ProcessHeadNode(&proto_node, &Drop, protocol);
            }
            break;
             
#ifdef GIDS
        case RULE_SDROP:
            if (InlineMode())
            {
                ProcessHeadNode(&proto_node, &SDrop, protocol);
            }
            break;
             
        case RULE_REJECT:
            if (InlineMode())
            {
                ProcessHeadNode(&proto_node, &Reject, protocol);
            }
            break;
#endif /* GIDS */         
         
        case RULE_ALERT:
            ProcessHeadNode(&proto_node, &Alert, protocol);
            break;

        case RULE_LOG:
            ProcessHeadNode(&proto_node, &Log, protocol);
            break;

        case RULE_PASS:
            ProcessHeadNode(&proto_node, &Pass, protocol);
            break;

        case RULE_ACTIVATE:
            ProcessHeadNode(&proto_node, &Activation, protocol);
            break;

        case RULE_DYNAMIC:
            ProcessHeadNode(&proto_node, &Dynamic, protocol);
            break;

        case RULE_UNKNOWN:
            ProcessHeadNode(&proto_node, node->RuleList, protocol);
            break;

        default:
            FatalError("Unable to determine rule type (%s) for processing, exiting!\n", toks[0]);
    }

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Parsing Rule Options...\n"););

    if (rule_type == RULE_UNKNOWN)
    {
        if(!ParseRuleOptions(rule, node->mode, protocol))
        {
            mSplitFree(&toks, num_toks);
            free(rule);
            return;
        }
    }
    else
    {
        if(!ParseRuleOptions(rule, rule_type, protocol))
        {
            mSplitFree(&toks, num_toks);
            free(rule);
            return;
        }
    }

    rule_count++;
    
#ifdef PORTLISTS
    /* Get rule option info */
    pe.gid = otn_tmp->sigInfo.generator;
    pe.sid = otn_tmp->sigInfo.id;
    
    if(toks[3]) 
      pe.src_port = strdup(toks[3]);

    if(toks[6]) 
      pe.dst_port = strdup(toks[6]);
    
    if ( OtnHasContent( otn_tmp) )
         pe.content=1;
    
    if ( OtnHasUriContent( otn_tmp) )
         pe.uricontent=1;

    if(  proto_node.flags & BIDIRECTIONAL )
         pe.dir = 1;

    if(toks[1]) 
       pe.protocol = strdup(toks[1]);
    
    pe.proto = protocol;
    pe.rule_type = rule_type;
    
    port_list_add_entry( &port_list, &pe );
 
   /* 
   * The src/dst port parsing must be done before the Head Nodes are processed, since they must
   * compare the ports/port_objects to find the right rtn list to add the otn rule to.
   * 
   * After otn processing we can finalize port object processing for this rule
   */
   if( FinishPortListRule( rtn_tmp, otn_tmp, protocol ) )
   {
       FatalError("Failed to finish a port list rule\n");
   }
#endif

    mSplitFree(&toks, num_toks);
    free(rule);
    return;
}

/****************************************************************************
 *
 * Function: ProcessHeadNode(RuleTreeNode *, ListHead *, int)
 *
 * Purpose:  Process the header block info and add to the block list if
 *           necessary
 *
 * Arguments: test_node => data generated by the rules parsers
 *            list => List Block Header refernece
 *            protocol => ip protocol
 *
 * Returns: void function
 *
 ***************************************************************************/
void ProcessHeadNode(RuleTreeNode * test_node, ListHead * list, int protocol)
{
    int match = 0;
    RuleTreeNode *rtn_idx;
    RuleTreeNode *rtn_prev=NULL;
    RuleTreeNode *rtn_head_ptr;
    int count = 0;
    int insert_complete = 0;
#ifdef DEBUG
    int i;
    char buf[STD_BUF];
#endif

    /* select the proper protocol list to attach the current rule to */
    switch(protocol)
    {
        case IPPROTO_TCP:
            rtn_idx = list->TcpList;
            break;

        case IPPROTO_UDP:
            rtn_idx = list->UdpList;
            break;

        case IPPROTO_ICMP:
            rtn_idx = list->IcmpList;
            break;

        case ETHERNET_TYPE_IP:
            rtn_idx = list->IpList;
            break;

        default:
            rtn_idx = NULL;
            break;
    }

    /* 
     * save which list we're on in case we need to do an insertion
     * sort on a new node
     */
    rtn_head_ptr = rtn_idx;

    /*
     * if the list head is NULL (empty), make a new one and attach the
     * ListHead to it
     */
    if(rtn_idx == NULL)
    {
        head_count++;

        switch(protocol)
        {
            case IPPROTO_TCP:
                list->TcpList = (RuleTreeNode *)SnortAlloc(sizeof(RuleTreeNode));
                rtn_tmp = list->TcpList;
                break;

            case IPPROTO_UDP:
                list->UdpList = (RuleTreeNode *)SnortAlloc(sizeof(RuleTreeNode));
                rtn_tmp = list->UdpList;
                break;

            case IPPROTO_ICMP:
                list->IcmpList = (RuleTreeNode *)SnortAlloc(sizeof(RuleTreeNode));
                rtn_tmp = list->IcmpList;
                break;

            case ETHERNET_TYPE_IP:
                list->IpList = (RuleTreeNode *)SnortAlloc(sizeof(RuleTreeNode));
                rtn_tmp = list->IpList;
                break;

        }

        /* copy the prototype header data into the new node */
        XferHeader(test_node, rtn_tmp);

        rtn_tmp->head_node_number = head_count;

        /* null out the down (options) pointer */
        rtn_tmp->down = NULL;

        /* add the function list to the new rule */
        SetupRTNFuncList(rtn_tmp);

        /* add link to parent listhead */
        rtn_tmp->listhead = list;

        return;
    }

    /* see if this prototype node matches any of the existing header nodes */
    match = TestHeader(rtn_idx, test_node);

    while((rtn_idx->right != NULL) && !match)
    {
        count++;
        match = TestHeader(rtn_idx, test_node);

        if(!match)
            rtn_idx = rtn_idx->right;
        else
            break;
    }

    /*
     * have to check this twice since my loop above exits early, which sucks
     * but it's not performance critical
     */
    match = TestHeader(rtn_idx, test_node);

    /*
     * if it doesn't match any of the existing nodes, make a new node and
     * stick it at the end of the list
     */
    if(!match)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Building New Chain head node\n"););

        head_count++;

        /* build a new node */
        //rtn_idx->right = (RuleTreeNode *) calloc(sizeof(RuleTreeNode), 
        rtn_tmp = (RuleTreeNode *)SnortAlloc(sizeof(RuleTreeNode));

        /* set the global ptr so we can play with this from anywhere */
        //rtn_tmp = rtn_idx->right;

        /* uh oh */
        if(rtn_tmp == NULL)
        {
            FatalError("Unable to allocate Rule Head Node!!\n");
        }

        /* copy the prototype header info into the new header block */
        XferHeader(test_node, rtn_tmp);

        rtn_tmp->head_node_number = head_count;
        rtn_tmp->down = NULL;

        /* initialize the function list for the new RTN */
        SetupRTNFuncList(rtn_tmp);

        /* add link to parent listhead */
        rtn_tmp->listhead = list;
        
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,
                "New Chain head flags = 0x%X\n", rtn_tmp->flags););

        /* we do an insertion sort of new RTNs for TCP/UDP traffic */
        if(protocol == IPPROTO_TCP || protocol == IPPROTO_UDP)
        {
            /* 
             * insert the new node into the RTN chain, order by destination
             * port
             */
            rtn_idx = rtn_head_ptr;
            rtn_prev = NULL;
            insert_complete = 0;

            /* 
             * Loop thru the RTN list and check to see of the low dest port
             * of the new node is greater than the low dest port of the 
             * new node.  If it is, insert the new node ahead of (to the 
             * left) of the existing node.
             */
#ifdef PORTLISTS
            /* just insert at head of list when using port lists */
           switch(protocol)
           {
             case IPPROTO_TCP:
             rtn_tmp->right = list->TcpList;
             list->TcpList = rtn_tmp;
             break;

             case IPPROTO_UDP:
             rtn_tmp->right = list->UdpList;
             list->UdpList = rtn_tmp;
             break;
           }

           rtn_head_ptr = rtn_tmp;
           insert_complete = 1;
#else
            if(rtn_tmp->flags & EXCEPT_DST_PORT)
            {
                switch(protocol)
                {
                    case IPPROTO_TCP:
                        rtn_tmp->right = list->TcpList;
                        list->TcpList = rtn_tmp;
                        break;

                    case IPPROTO_UDP:
                        rtn_tmp->right = list->UdpList;
                        list->UdpList = rtn_tmp;
                        break;
                }

                rtn_head_ptr = rtn_tmp;
                insert_complete = 1;
            }
            else
            {
                while(rtn_idx != NULL)
                {
                    if(rtn_idx->flags & EXCEPT_DST_PORT || 
                       rtn_idx->ldp < rtn_tmp->ldp)
                    {
                        rtn_prev = rtn_idx;
                        rtn_idx = rtn_idx->right;
                    }
                    else if(rtn_idx->ldp == rtn_tmp->ldp)
                    {
                        rtn_tmp->right = rtn_idx->right;
                        rtn_idx->right = rtn_tmp;
                        insert_complete = 1;
                        break;
                    }
                    else
                    {
                        rtn_tmp->right = rtn_idx;

                        if(rtn_prev != NULL)
                        {
                            rtn_prev->right = rtn_tmp;
                        }
                        else 
                        {
                            switch(protocol)
                            {
                                case IPPROTO_TCP:
                                    list->TcpList = rtn_tmp;
                                    break;

                                case IPPROTO_UDP:
                                    list->UdpList = rtn_tmp;
                                    break;
                            }

                            rtn_head_ptr = rtn_tmp;
                        }

                        insert_complete = 1;

                        break;
                    }
                } 
            }
#endif

            if(!insert_complete)
            {
                if(rtn_prev)
                rtn_prev->right = rtn_tmp;   
            }
            
            rtn_idx = rtn_head_ptr;

            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES, 
                    "New %s node inserted, new order:\n", 
                    protocol == IPPROTO_TCP?"TCP":"UDP"););
            
#ifdef DEBUG
            i = 0;

            SnortSnprintf(buf, STD_BUF, "%s", "    ");

            while (rtn_idx != NULL)
            {
                if (rtn_idx->flags & EXCEPT_DST_PORT)
                {
                    SnortSnprintfAppend(buf, STD_BUF, "!");
                }

                SnortSnprintfAppend(buf, STD_BUF, "%d ", rtn_idx->ldp);

                rtn_idx = rtn_idx->right;

                if (i == 15)
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES, "%s\n", buf););

                    i = 0;

                    SnortSnprintf(buf, STD_BUF, "%s", "     ");
                }

                i++;
            }

            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES, "%s\n", buf););
#endif
        }
        else
        {
            rtn_idx->right = rtn_tmp;
        }
    }
    else
    {
        rtn_tmp = rtn_idx;

        /* Free the list data from the incoming node, to avoid
         * leaking memory */
        if (test_node->sip)
        {
#ifdef SUP_IP6
            /* Free the IP src that was created from parsing.  Its
               duplicated in an existing RTN */
            sfvar_free(test_node->sip);
#else
            IpAddrSetDestroy(test_node->sip);
            free(test_node->sip);
            test_node->sip = NULL;
#endif
        }

        if (test_node->dip)
        {
            /* Free the IP dst that was created from parsing.  Its
               duplicated in an existing RTN */
#ifdef SUP_IP6
            sfvar_free(test_node->dip);
#else
            IpAddrSetDestroy(test_node->dip);
            free(test_node->dip);
            test_node->dip = NULL;
#endif
        }

        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,
                "Chain head %d  flags = 0x%X\n", count, rtn_tmp->flags););

        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,
                    "Adding options to chain head %d\n", count););
    }
}


/****************************************************************************
 *
 * Function: AddRuleFuncToList(int (*func)(), RuleTreeNode *)
 *
 * Purpose:  Adds RuleTreeNode associated detection functions to the
 *          current rule's function list
 *
 * Arguments: *func => function pointer to the detection function
 *            rtn   => pointer to the current rule
 *
 * Returns: void function
 *
 ***************************************************************************/
void AddRuleFuncToList(int (*func) (Packet *, struct _RuleTreeNode *, struct _RuleFpList *), RuleTreeNode * rtn)
{
    RuleFpList *idx;

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Adding new rule to list\n"););

    idx = rtn->rule_func;

    if(idx == NULL)
    {
        rtn->rule_func = (RuleFpList *)SnortAlloc(sizeof(RuleFpList));

        rtn->rule_func->RuleHeadFunc = func;
    }
    else
    {
        while(idx->next != NULL)
            idx = idx->next;

        idx->next = (RuleFpList *)SnortAlloc(sizeof(RuleFpList));

        idx = idx->next;
        idx->RuleHeadFunc = func;
    }
}


/****************************************************************************
 *
 * Function: SetupRTNFuncList(RuleTreeNode *)
 *
 * Purpose: Configures the function list for the rule header detection
 *          functions (addrs and ports)
 *
 * Arguments: rtn => the pointer to the current rules list entry to attach to
 *
 * Returns: void function
 *
 ***************************************************************************/
void SetupRTNFuncList(RuleTreeNode * rtn)
{
    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Initializing RTN function list!\n"););
    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Functions: "););

    if(rtn->flags & BIDIRECTIONAL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"CheckBidirectional->\n"););
        AddRuleFuncToList(CheckBidirectional, rtn);
    }
    else
    {
        /* Attach the proper port checking function to the function list */
        /*
         * the in-line "if's" check to see if the "any" or "not" flags have
         * been set so the PortToFunc call can determine which port testing
         * function to attach to the list
         */
        PortToFunc(rtn, (rtn->flags & ANY_DST_PORT ? 1 : 0),
                   (rtn->flags & EXCEPT_DST_PORT ? 1 : 0), DST);

        /* as above */
        PortToFunc(rtn, (rtn->flags & ANY_SRC_PORT ? 1 : 0),
                   (rtn->flags & EXCEPT_SRC_PORT ? 1 : 0), SRC);

        /* link in the proper IP address detection function */
        AddrToFunc(rtn, SRC);

        /* last verse, same as the first (but for dest IP) ;) */
        AddrToFunc(rtn, DST);
    }

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"RuleListEnd\n"););

    /* tack the end (success) function to the list */
    AddRuleFuncToList(RuleListEnd, rtn);
}



/****************************************************************************
 *
 * Function: AddrToFunc(RuleTreeNode *, u_long, u_long, int, int)
 *
 * Purpose: Links the proper IP address testing function to the current RTN
 *          based on the address, netmask, and addr flags
 *
 * Arguments: rtn => the pointer to the current rules list entry to attach to
 *            ip =>  IP address of the current rule
 *            mask => netmask of the current rule
 *            exception_flag => indicates that a "!" has been set for this
 *                              address
 *            mode => indicates whether this is a rule for the source
 *                    or destination IP for the rule
 *
 * Returns: void function
 *
 ***************************************************************************/
void AddrToFunc(RuleTreeNode * rtn, int mode)
{
    /*
     * if IP and mask are both 0, this is a "any" IP and we don't need to
     * check it
     */
    switch(mode)
    {
        case SRC:
            if((rtn->flags & ANY_SRC_IP) == 0)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"CheckSrcIP -> "););
                AddRuleFuncToList(CheckSrcIP, rtn);
            }

            break;

        case DST:
            if((rtn->flags & ANY_DST_IP) == 0)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"CheckDstIP -> "););
                AddRuleFuncToList(CheckDstIP, rtn);
            }

            break;
    }
}



/****************************************************************************
 *
 * Function: PortToFunc(RuleTreeNode *, int, int, int)
 *
 * Purpose: Links in the port analysis function for the current rule
 *
 * Arguments: rtn => the pointer to the current rules list entry to attach to
 *            any_flag =>  accept any port if set
 *            except_flag => indicates negation (logical NOT) of the test
 *            mode => indicates whether this is a rule for the source
 *                    or destination port for the rule
 *
 * Returns: void function
 *
 ***************************************************************************/
void PortToFunc(RuleTreeNode * rtn, int any_flag, int except_flag, int mode)
{
    /*
     * if the any flag is set we don't need to perform any test to match on
     * this port
     */
    if(any_flag)
        return;

    /* if the except_flag is up, test with the "NotEq" funcs */
    if(except_flag)
    {
        switch(mode)
        {
            case SRC:
                DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"CheckSrcPortNotEq -> "););
                AddRuleFuncToList(CheckSrcPortNotEq, rtn);
                break;


            case DST:
                DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"CheckDstPortNotEq -> "););
                AddRuleFuncToList(CheckDstPortNotEq, rtn);
                break;
        }

        return;
    }
    /* default to setting the straight test function */
    switch(mode)
    {
        case SRC:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"CheckSrcPortEqual -> "););
            AddRuleFuncToList(CheckSrcPortEqual, rtn);
            break;

        case DST:
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"CheckDstPortEqual -> "););
            AddRuleFuncToList(CheckDstPortEqual, rtn);
            break;
    }

    return;
}

/****************************************************************************
 *
 * Function: ParsePreprocessor(char *)
 *
 * Purpose: Walks the preprocessor function list looking for the user provided
 *          keyword.  Once found, call the preprocessor's initialization
 *          function.
 *
 * Arguments: rule => the preprocessor initialization string from the rules file
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParsePreprocessor(char *rule)
{
    char **toks;        /* pointer to the tokenized array parsed from
                         * the rules list */
    char **pp_head;     /* parsed keyword list, with preprocessor
                         * keyword being the 2nd element */
    char *funcname;     /* the ptr to the actual preprocessor keyword */
    char *pp_args = NULL;   /* parsed list of arguments to the
                             * preprocessor */
    int num_arg_toks;   /* number of argument tokens returned by the mSplit function */
    int num_head_toks;  /* number of head tokens returned by the mSplit function */
    int found = 0;      /* flag var */
    PreprocessKeywordList *pl_idx;  /* index into the preprocessor
                                     * keyword/func list */
#ifdef DYNAMIC_PLUGIN
    DynamicPreprocConfig *dynamicConfig;
#endif

    /* break out the arguments from the keywords */
    toks = mSplit(rule, ":", 2, &num_arg_toks, '\\');

    if(num_arg_toks > 1)
    {
        /*
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"toks[1] = %s\n", toks[1]););
        */
        /* the args are everything after the ":" */
        pp_args = toks[1];
    }

    /* split the head section for the preprocessor keyword */
    pp_head = mSplit(toks[0], " ", 2, &num_head_toks, '\\');

    /* set a pointer to the actual keyword */
    funcname = pp_head[1];

    /* set the index to the head of the keyword list */
    pl_idx = PreprocessKeywords;

    /* walk the keyword list */
    while(pl_idx != NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,
                "comparing: \"%s\" => \"%s\"\n",
                funcname, pl_idx->entry.keyword););
        /* compare the keyword against the current list element's keyword */
        if(!strcasecmp(funcname, pl_idx->entry.keyword))
        {
            pl_idx->entry.func(pp_args);
            found = 1;
        }
        if(!found)
        {
            pl_idx = pl_idx->next;
        }
        else
        {
            break;
        }
    }

    if(!found)
    {
#ifdef DYNAMIC_PLUGIN
        dynamicConfig = (DynamicPreprocConfig *)SnortAlloc(sizeof(DynamicPreprocConfig));

        dynamicConfig->file = SnortStrdup(file_name);
        dynamicConfig->line_num = file_line;
        dynamicConfig->preproc = SnortStrdup(funcname);
        if (pp_args)
            dynamicConfig->preproc_args = SnortStrdup(pp_args);
        else
            dynamicConfig->preproc_args = NULL;
        dynamicConfig->next = NULL;
        if (!dynamicConfigListHead)
            dynamicConfigListHead = dynamicConfig;
        if (dynamicConfigListTail)
        {
            dynamicConfigListTail->next = dynamicConfig;
        }
        dynamicConfigListTail = dynamicConfig;
#else
        FatalError("%s(%d) unknown preprocessor \"%s\"\n",
                   file_name, file_line, funcname);
#endif
    }

    mSplitFree(&toks, num_arg_toks);
    mSplitFree(&pp_head, num_head_toks);
}

#ifdef DYNAMIC_PLUGIN
void ConfigureDynamicPreprocessors()
{
    int found;      /* flag var */
    PreprocessKeywordList *pl_idx;  /* index into the preprocessor
                                     * keyword/func list */
    DynamicPreprocConfig *dynamicConfig = dynamicConfigListHead;
    DynamicPreprocConfig *prevDynamicConfig;
    char *stored_file_name = file_name;
    int stored_file_line = file_line;
    int errors = 0;
    while (dynamicConfig)
    {
        /* set the index to the head of the keyword list */
        pl_idx = PreprocessKeywords;

        found = 0;

        /* walk the keyword list */
        while(pl_idx != NULL)
        {
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,
                    "comparing: \"%s\" => \"%s\"\n",
                    dynamicConfig->preproc, pl_idx->entry.keyword););
            /* compare the keyword against the current list element's keyword */
            if(!strcasecmp(dynamicConfig->preproc, pl_idx->entry.keyword))
            {
                file_name = dynamicConfig->file;
                file_line = dynamicConfig->line_num;
                pl_idx->entry.func(dynamicConfig->preproc_args);
                found = 1;
            }
            if(!found)
            {
                pl_idx = pl_idx->next;
            }
            else
            {
                break;
            }
        }

        if(!found)
        {
            ErrorMessage("%s(%d) unknown dynamic preprocessor \"%s\"\n",
                       dynamicConfig->file, dynamicConfig->line_num,
                       dynamicConfig->preproc);
            errors = 1;
        }

        prevDynamicConfig = dynamicConfig;
        dynamicConfig = dynamicConfig->next;

        /* Clean up the memory... don't need that one around anymore */
        free(prevDynamicConfig->file);
        free(prevDynamicConfig->preproc);
        free(prevDynamicConfig->preproc_args);
        free(prevDynamicConfig);
    }
    if (errors)
    {
        FatalError("Misconfigured dynamic preprocessor(s)\n");
    }

    /* Reset these since we're done with configuring dynamic preprocessors */
    file_name = stored_file_name;
    file_line = stored_file_line;
}
#endif

void ParseOutputPlugin(char *rule)
{
    char **toks;
    char **pp_head;
    char *plugin_name = NULL;
    char *pp_args = NULL;
    int num_arg_toks;
    int num_head_toks;
    OutputKeywordNode *plugin;

    toks = mSplit(rule, ":", 2, &num_arg_toks, '\\');

    if(num_arg_toks > 1)
    {
        pp_args = toks[1];
    }
    pp_head = mSplit(toks[0], " ", 2, &num_head_toks, '\\');

    plugin_name = pp_head[1];

    if(plugin_name == NULL)
    {
        FatalError("%s (%d): Output directive missing output plugin name!\n", 
                file_name, file_line);
    }

    plugin = GetOutputPlugin(plugin_name);
    if( plugin != NULL )
    {
        switch(plugin->node_type)
        {
            case NT_OUTPUT_SPECIAL:
                if(pv.alert_cmd_override)
                    ErrorMessage("command line overrides rules file alert "
                            "plugin!\n");

                if(pv.log_cmd_override)
                    ErrorMessage("command line overrides rules file login "
                            "plugin!\n");

                if(!pv.log_cmd_override && !pv.alert_cmd_override)
                    plugin->func(pp_args);
                break;

            case NT_OUTPUT_ALERT:
                if(!pv.alert_cmd_override)
                {
                    /* call the configuration function for the plugin */
                    plugin->func(pp_args);
                }
                else
                {
                    ErrorMessage("command line overrides rules file alert "
                            "plugin!\n");
                }

                break;

            case NT_OUTPUT_LOG:
                if(!pv.log_cmd_override)
                {
                    /* call the configuration function for the plugin */
                    plugin->func(pp_args);
                }
                else
                {
                    ErrorMessage("command line overrides rules file logging "
                            "plugin!\n");
                }

                break;
        }

    }

    mSplitFree(&toks, num_arg_toks);
    mSplitFree(&pp_head, num_head_toks);
}

void FreeRuleTreeNode(RuleTreeNode *rtn)
{
    RuleFpList *idx, *tmp;
    if (!rtn)
        return;

    if (rtn->sip)
    {
#ifdef SUP_IP6
        sfvar_free(rtn->sip);
#else
        IpAddrSetDestroy(rtn->sip);
        free(rtn->sip);
        rtn->sip = NULL;
#endif
    }

    if (rtn->dip)
    {
#ifdef SUP_IP6
        sfvar_free(rtn->dip);
#else
        IpAddrSetDestroy(rtn->dip);
        free(rtn->dip);
        rtn->dip = NULL;
#endif
    }

    idx = rtn->rule_func;
    while (idx)
    {
        tmp = idx;
        idx = idx->next;
        free(tmp);
    }
}

void DestroyRuleTreeNode(RuleTreeNode *rtn)
{
    if (!rtn)
        return;

    FreeRuleTreeNode(rtn);

    free(rtn);
}

/****************************************************************************
 *
 * Function: RemoveDuplicateOtn(otn_dup, rtn, rule, type) 
 *
 * Purpose:  Conditionally removes duplicate SID/GIDs. Keeps duplicate with 
 *           higher revision.  If revision is the same, keeps newest rule.
 *
 * Arguments: otn_dup => The existing duplicate
 *            rtn => the RTN chain to check
 *            char => String describing the rule
 *            rule_type => enumerated rule type (alert, pass, log)
 *
 * Returns: 0 if original rule stays, 1 if new rule stays
 *
 ***************************************************************************/

int RemoveDuplicateOtn(OptTreeNode *otn_dup, OptTreeNode *otn_new, 
                       RuleTreeNode *rtn, char *rule, int type, int proto) 
{
    RuleTreeNode *rtn_idx, *rtn_prev, **list;
    OptTreeNode *otn_idx;

    if (otn_dup->proto != proto)
    {
        FatalError("%s(%d): GID %d SID %d in rule: \"%s\""
                   " duplicates previous rule, with different protocol.\n",
                   file_name, file_line, otn_new->sigInfo.generator, 
                   otn_new->sigInfo.id, rule);
    }

    if(otn_dup->type != otn_new->type) 
    {
        FatalError("%s(%d): GID %d SID %d in rule: \"%s\""
                   " duplicates previous rule, with different type.\n",
                   file_name, file_line, otn_new->sigInfo.generator, 
                   otn_new->sigInfo.id, rule);
    }

    switch(proto) 
    {
        case IPPROTO_TCP: 
            list = &rtn->listhead->TcpList; break;
        case IPPROTO_UDP: 
            list = &rtn->listhead->UdpList; break;
        case IPPROTO_ICMP: 
            list = &rtn->listhead->IcmpList; break;
        case ETHERNET_TYPE_IP: 
            list = &rtn->listhead->IpList; break;
        default:
            /* This should never happen */
            return 0;
    };

    /* Check if we need to delete the new rule, and keep the original */
    if(
        /* If both rules are shared rules, take highest revision or newest rule */
        ( otn_new->sigInfo.shared && otn_dup->sigInfo.shared &&
          (otn_new->sigInfo.rev < otn_dup->sigInfo.rev) )           ||
        /* If new rule is not an SO rule, but the old is, keep the old */
        ( !otn_new->sigInfo.shared && otn_dup->sigInfo.shared )     ||
        /* If neither rules are SO rules, take highest revision */
        ( (!otn_new->sigInfo.shared && !otn_dup->sigInfo.shared) && 
          (otn_new->sigInfo.rev < otn_dup->sigInfo.rev) ) 
        )
    {
        LogMessage("%s(%d): GID %d SID %d in rule: \"%s\""
                   " duplicates previous rule. Using %s\n", 
                   file_name, file_line, otn_new->sigInfo.generator, 
                   otn_new->sigInfo.id, rule, 
                   otn_dup->sigInfo.shared ? "SO rule.":"higher revision" );
        //free(otn_new);
        otn_free(otn_new);
        otn_tmp = NULL;

        /* Check if it's necessary to remove this RTN */
        if(!rtn->down) 
        {
            if(*list == rtn) 
            {
                *list = rtn->right;
                DestroyRuleTreeNode(rtn);
                //free(rtn);
                return 0;
            }
                
            for(rtn_idx = *list; rtn_idx && rtn_idx->right != rtn; 
                rtn_idx = rtn_idx->right) 
                ; /* empty loop */
           
            /* This should never happen, but just in case .. */
            assert(rtn_idx);

            /* rtn_idx->right == rtn */

            rtn_idx->right = rtn->right;
            DestroyRuleTreeNode(rtn);
            //free(rtn);
            rtn_tmp = rtn_idx;
        }

        return 0;
    }
    
    if(pv.conf_error_out)
    {
        FatalError("%s(%d): GID %d SID %d in rule: \"%s\" duplicates"
                   " previous rule.\n", 
                   file_name, file_line, otn_new->sigInfo.generator, 
                   otn_new->sigInfo.id, rule);
    }
    else 
    {
    	LogMessage("%s(%d): GID %d SID %d in rule: \"%s\" duplicates"
    	               " previous rule. Ignoring old rule.\n", 
    	               file_name, file_line, otn_new->sigInfo.generator, 
    	               otn_new->sigInfo.id, rule);
    }
    
    for(rtn_idx = *list, rtn_prev = NULL;  rtn_idx;
        rtn_idx = rtn_idx->right)
    {
        if(otn_dup == rtn_idx->down) 
        {
            rtn_idx->down = otn_dup->next;
            otn_new->nextSoid = otn_dup->nextSoid;
        }
        else if(rtn_idx->down)
        {
            /* Find the node before the duplicate */
            for(otn_idx = rtn_idx->down ; 
                otn_idx->next && otn_idx->next != otn_dup;
                otn_idx = otn_idx->next) 
                ; /* (Empty loop) */
        
            if(!otn_idx->next) {
                rtn_prev = rtn_idx;
                continue;
            }

            otn_idx->next = otn_dup->next;
            otn_new->nextSoid = otn_dup->nextSoid;
        }
        else 
        {
            /* There's no rtn_idx->down; No match here. Go right and traverse down. */
            rtn_prev = rtn_idx;
            continue;
        }

        otn_remove(otn_dup);

        if( type == SI_RULE_TYPE_DETECT  ) detect_rule_count--;
        if( type == SI_RULE_TYPE_DECODE  ) decode_rule_count--;
        if( type == SI_RULE_TYPE_PREPROC ) preproc_rule_count--;
    
        opt_count--;

        /* Check if it's necessary to remove this RTN */
        if(!rtn_idx->down && rtn_idx != rtn) 
        {
            if(rtn_prev)
            {
                rtn_prev->right = rtn_idx->right;
                DestroyRuleTreeNode(rtn_idx);
                //free(rtn_idx);
            }
            else
            {
                *list = rtn_idx->right;
                DestroyRuleTreeNode(rtn_idx);
                //free(rtn_idx); 
            }
        }

        break;
    }

    return 1;
}


/****************************************************************************
 *
 * Function: ParseRuleOptions(char *, int)
 *
 * Purpose:  Process an individual rule's options and add it to the
 *           appropriate rule chain
 *
 * Arguments: rule => rule string
 *            rule_type => enumerated rule type (alert, pass, log)
 *
 * Returns: 0 on failure, 1 on success
 *
 ***************************************************************************/
int ParseRuleOptions(char *rule, int rule_type, int protocol)
{
    char **toks = NULL;
    char **opts = NULL;
    char *idx;
    char *aux;
    int num_toks, original_num_toks=0;
    int i;
    int num_opts;
    int found = 0;
    OptTreeNode *otn_idx, *otn_dup;
    OptFpList *fpl = NULL;
    KeywordXlateList *kw_idx;
    THDX_STRUCT thdx;
    int one_threshold = 0;
    int snort_rule_type = SI_RULE_TYPE_DETECT;

    // unsupported keywords:  (detect_keyword && non_detect_rule) => failure
    const char* detect_keyword = NULL;   // 1st detection only keyword | null
    const char* non_detect_rule = NULL;  // rule is preproc | decode | null

    otn_tmp = (OptTreeNode *)SnortAlloc(sizeof(OptTreeNode));

    otn_tmp->next = NULL;
    otn_tmp->chain_node_number = opt_count;
    otn_tmp->type = rule_type;
    otn_tmp->proto = protocol;
    otn_tmp->proto_node = rtn_tmp;
    otn_tmp->event_data.sig_generator = GENERATOR_SNORT_ENGINE;
    otn_tmp->sigInfo.generator        = GENERATOR_SNORT_ENGINE;
    otn_tmp->sigInfo.rule_type        = SI_RULE_TYPE_DETECT; /* standard rule */
    otn_tmp->sigInfo.rule_flushing    = SI_RULE_FLUSHING_ON; /* usually just standard rules cause a flush*/

        /* Set the default rule state */
    otn_tmp->rule_state = pv.default_rule_state;

    /* find the start of the options block */
    idx = strchr(rule, '(');
    i = 0;

    if(idx != NULL)
    {
        int one_msg = 0;
        int one_logto = 0;
        int one_activates = 0;
        int one_activated_by = 0;
        int one_count = 0;
        int one_tag = 0;
        int one_sid = 0;
        int one_gid = 0;
        int one_rev = 0;
        int one_priority = 0;
        int one_classtype = 0;
        
        idx++;

        /* find the end of the options block */
        aux = strrchr(idx, ')');

        /* get rid of the trailing ")" */
        if(aux == NULL)
        {
            FatalError("%s(%d): Missing trailing ')' in rule: %s.\n",
                       file_name, file_line, rule);
        }
        *aux = 0;

        /* check for extraneous semi-colon */
        if (strstr(idx, ";;"))
        {
            FatalError("%s(%d): Extraneous semi-colon in rule:\n%s)\n", file_name, file_line, rule);
        }

        /* seperate all the options out, the seperation token is a semicolon */
        /*
         * NOTE: if you want to include a semicolon in the content of your
         * rule, it must be preceeded with a '\'
         */
        /* Ask for max + 1.  If we get that many back, scream and jump
         * up and down. */
        toks = mSplit(idx, ";", MAX_RULE_OPTIONS+1, &num_toks, '\\');

        if (num_toks > MAX_RULE_OPTIONS)
        {
            /* don't allow more than MAX_RULE_OPTIONS */
            FatalError("%s(%d): More than %d options in rule: %s.\n",
                       file_name, file_line, MAX_RULE_OPTIONS, rule);
        }
        original_num_toks = num_toks;  /* so we can properly deallocate toks later */

        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"   Got %d tokens\n", num_toks););
        /* decrement the number of toks */
        num_toks--;

        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Parsing options list: "););

    
        while(num_toks)        
        {
            char* option_name = NULL;
            char* option_args = NULL;

            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"   option: %s\n", toks[i]););

            /* break out the option name from its data */
            opts = mSplit(toks[i], ":", 2, &num_opts, '\\');

            /* We got nothing but space in between semi-colons */
            if (num_opts == 0)
            {
                FatalError("%s(%d): Empty option (extraneous semi-colon?) in rule:\n%s)\n", file_name, file_line, rule);
            }

            /* can't free opts[0] later if it has been incremented, so
             * must use another variable here */
            option_name = opts[0];
            DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"   option name: %s\n", option_name););
            if (num_opts > 1)
            {
                option_args = opts[1];
                DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"   option args: %s\n", option_args););
            }

            /* advance to the beginning of the data (past the whitespace) */
            while(isspace((int) *option_name))
                option_name++;
        
            /* figure out which option tag we're looking at */
            if(!strcasecmp(option_name, "msg"))
            {
                ONE_CHECK (one_msg, option_name);
                if(num_opts == 2)
                {
                    ParseMessage(option_args);
                }
                else
                {
                    FatalError("\n%s(%d) => No argument passed to "
                            "keyword \"%s\"\nMake sure you didn't forget a ':' "
                            "or the argument to this keyword!\n", file_name, 
                            file_line, option_name);
                }
            }
            /* metadata */
            else if(!strcasecmp(option_name, "metadata"))
            {
                if(num_opts <= 2)
                {
                    ParseMetadata(option_args,otn_tmp);
                }
                else
                {
                    FatalError("\n%s(%d) => No argument passed to "
                            "keyword \"%s\"\nMake sure you didn't forget a ':' "
                            "or the argument to this keyword!\n", file_name, 
                            file_line, option_name);
                }

                snort_rule_type = otn_tmp->sigInfo.rule_type;
                
                switch ( snort_rule_type ) {
					case SI_RULE_TYPE_PREPROC:
                        non_detect_rule = "preproc";
                        break;
                    case SI_RULE_TYPE_DECODE:
                	    non_detect_rule = "decode";
                	    break;
                }                
            }
            else if(!strcasecmp(option_name, "logto"))
            {
                ONE_CHECK (one_logto, option_name);
                if(num_opts == 2)
                {
                    ParseLogto(option_args);
                }
                else
                {
                    FatalError("\n%s(%d) => No argument passed to "
                            "keyword \"%s\"\nMake sure you didn't forget a ':' "
                            "or the argument to this keyword!\n", file_name, 
                            file_line, option_name);
                }
            }
            else if(!strcasecmp(option_name, "activates"))
            {
                ONE_CHECK (one_activates, option_name);
                if(num_opts == 2)
                {
                    ParseActivates(option_args);
                    dynamic_rules_present++;
                }
                else
                {
                    FatalError("\n%s(%d) => No argument passed to "
                            "keyword \"%s\"\nMake sure you didn't forget a ':' "
                            "or the argument to this keyword!\n", file_name, 
                            file_line, option_name);
                }
            }
            else if(!strcasecmp(option_name, "activated_by"))
            {
                ONE_CHECK (one_activated_by, option_name);
                if(num_opts == 2)
                {
                    ParseActivatedBy(option_args);
                    dynamic_rules_present++;
                }
                else
                {
                    FatalError("\n%s(%d) => No argument passed to "
                            "keyword \"%s\"\nMake sure you didn't forget a ':' "
                            "or the argument to this keyword!\n", file_name, 
                            file_line, opts[0]);
                }
            }
            else if(!strcasecmp(option_name, "count"))
            {
                ONE_CHECK (one_count, option_name);
                if(num_opts == 2)
                {
                    if(otn_tmp->type != RULE_DYNAMIC)
                        FatalError("%s(%d) => The \"count\" option may only "
                                "be used with the dynamic rule type!\n",
                                file_name, file_line);
                    ParseCount(opts[1]);
                }
                else
                {
                    FatalError("\n%s(%d) => No argument passed to "
                            "keyword \"%s\"\nMake sure you didn't forget a ':' "
                            "or the argument to this keyword!\n", file_name, 
                            file_line, opts[0]);
                }
            }
            else if(!strcasecmp(option_name, "tag"))
            {
                ONE_CHECK (one_tag, opts[0]);
                if(num_opts == 2)
                {
                    ParseTag(opts[1], otn_tmp);
                }
                else
                {
                    FatalError("\n%s(%d) => No argument passed to "
                            "keyword \"%s\"\nMake sure you didn't forget a ':' "
                            "or the argument to this keyword!\n", file_name, 
                            file_line, opts[0]);
                }
            }
            else if(!strcasecmp(option_name, "threshold"))
            {
                ONE_CHECK (one_threshold, opts[0]);
                if(num_opts == 2)
                {
                    ParseThreshold2(&thdx, opts[1]);
                }
                else
                {
                    FatalError("\n%s(%d) => No argument passed to "
                            "keyword \"%s\"\nMake sure you didn't forget a ':' "
                            "or the argument to this keyword!\n", file_name, 
                            file_line, opts[0]);
                }
            }
            else if(!strcasecmp(option_name, "sid"))
            {
                ONE_CHECK (one_sid, opts[0]);
                if(num_opts == 2)
                {
                    ParseSID(opts[1], otn_tmp);
                }
                else
                {
                    FatalError("\n%s(%d) => No argument passed to "
                            "keyword \"%s\"\nMake sure you didn't forget a ':' "
                            "or the argument to this keyword!\n", file_name, 
                            file_line, opts[0]);
                }
            }
            else if(!strcasecmp(option_name, "gid"))
            {
                ONE_CHECK (one_gid, opts[0]);
                if(num_opts == 2)
                {
                    ParseGID(opts[1], otn_tmp);
                }
                else
                {
                    FatalError("\n%s(%d) => No argument passed to "
                            "keyword \"%s\"\nMake sure you didn't forget a ':' "
                            "or the argument to this keyword!\n", file_name, 
                            file_line, opts[0]);
                }
               
               //otn_tmp->sigInfo.rule_type  = SI_RULE_TYPE_DECODE; /* standard rule */
               //if( gid == 1 || gid == 3 )
               //    otn_tmp->sigInfo.rule_type  = SI_RULE_TYPE_DETECT; /* standard rule */
               //else
               //    otn_tmp->sigInfo.rule_type  = SI_RULE_TYPE_PREPROC; /* standard rule */
            }
            else if(!strcasecmp(option_name, "rev"))
            {
                ONE_CHECK (one_rev, opts[0]);
                if(num_opts == 2)
                {
                    ParseRev(opts[1], otn_tmp);
                }
                else
                {
                    FatalError("\n%s(%d) => No argument passed to "
                            "keyword \"%s\"\nMake sure you didn't forget a ':' "
                            "or the argument to this keyword!\n", file_name, 
                            file_line, opts[0]);
                }
            }
            else if(!strcasecmp(option_name, "reference"))
            {
                if(num_opts == 2)
                {
                    ParseReference(opts[1], otn_tmp);
                }
                else
                {
                    FatalError("\n%s(%d) => No argument passed to "
                            "keyword \"%s\"\nMake sure you didn't forget a ':' "
                            "or the argument to this keyword!\n", file_name, 
                            file_line, opts[0]);
                }
            }
            else if(!strcasecmp(option_name, "priority"))
            {
                ONE_CHECK (one_priority, opts[0]);
                if(num_opts == 2)
                {
                    ParsePriority(opts[1], otn_tmp);
                }
                else
                {
                    FatalError("\n%s(%d) => No argument passed to "
                            "keyword \"%s\"\nMake sure you didn't forget a ':' "
                            "or the argument to this keyword!\n", file_name, 
                            file_line, opts[0]);
                }
            }
            else if(!strcasecmp(option_name, "classtype"))
            {
                ONE_CHECK (one_classtype, opts[0]);
                if(num_opts == 2)
                {
                    ParseClassType(opts[1], otn_tmp);
                }
                else
                {
                    FatalError("\n%s(%d) => No argument passed to "
                            "keyword \"%s\"\nMake sure you didn't forget a ':' "
                            "or the argument to this keyword!\n", file_name, 
                            file_line, option_name);
                }
            }
            else
            {
                kw_idx = KeywordList;
                found = 0;

                while(kw_idx != NULL)
                {
                    DEBUG_WRAP(DebugMessage(DEBUG_INIT, "comparing: \"%s\" => \"%s\"\n", 
                        option_name, kw_idx->entry.keyword););

                    /* Check detection plugins */
                    if(!strcasecmp(option_name, kw_idx->entry.keyword))
                    {
                        if(num_opts == 2) 
                        {
                            kw_idx->entry.func(option_args, otn_tmp, protocol);
                        } 
                        else 
                        {
                            kw_idx->entry.func(NULL, otn_tmp, protocol);
                        }
                        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "%s->", kw_idx->entry.keyword););
                        found = 1;
                        
                        if ( !detect_keyword && kw_idx->entry.type == OPT_TYPE_DETECTION )
                        {
                        	detect_keyword = kw_idx->entry.keyword;
                        }
                        break;
                    }
                    kw_idx = kw_idx->next;
                }

#ifdef DYNAMIC_PLUGIN
                /* Check dynamic preprocessor options */
                if ( !found )
                {
                    PreprocOptionInit initFunc;
                    PreprocOptionEval evalFunc;
                    void *opt_data;

                    int ret = GetPreprocessorRuleOptionFuncs(option_name,  (void **) &initFunc, (void **) &evalFunc);

                    if ( ret && initFunc)
                    {
                        initFunc(option_name, option_args, &opt_data);
                        AddPreprocessorRuleOption(option_name, otn_tmp, opt_data, evalFunc);
                        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "%s->", option_name););
                        found = 1;
                    }
                }
#endif

                if(!found)
                {
                    /* Unrecognized rule option, complain */
                    FatalError("Warning: %s(%d) => Unknown keyword '%s' in "
                               "rule!\n", file_name, file_line, opts[0]);
                }
            }

            if ( detect_keyword && non_detect_rule )
            {
                /* incompatible keywords - fatal error */
                FatalError("\n%s(%d) => %s rules don't support %s option\n",
                    file_name, file_line, non_detect_rule, detect_keyword);
            }
            mSplitFree(&opts,num_opts);

            --num_toks;
            i++;
        }

        if ( !one_sid && !pv.test_mode_flag)
        {
            FatalError("%s(%d) => Each rule must contain a Rule-sid\n",
                file_name, file_line);
        }

        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"OptListEnd\n"););

        /* Check for duplicate SID */
        if ( (otn_dup = otn_lookup(otn_tmp->sigInfo.generator, otn_tmp->sigInfo.id)) != NULL )
        {
            if(!RemoveDuplicateOtn(otn_dup, otn_tmp, rtn_tmp, 
                                   rule, snort_rule_type, protocol))
            {
                mSplitFree(&toks,original_num_toks);
                return 0;
            }
        }

        fpl = AddOptFuncToList(OptListEnd, otn_tmp);
#ifdef DETECTION_OPTION_TREE
        fpl->type = RULE_OPTION_TYPE_LEAF_NODE;
#endif
    }
    else
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"OptListEnd\n"););
        fpl = AddOptFuncToList(OptListEnd, otn_tmp);
#ifdef DETECTION_OPTION_TREE
        fpl->type = RULE_OPTION_TYPE_LEAF_NODE;
#endif
    }

#ifdef DETECTION_OPTION_TREE
    FinalizeContentUniqueness(otn_tmp);
#endif

    /* Place new OTN in list */
    otn_idx = rtn_tmp->down;

    /* add link to parent RuleTreeNode */
    otn_tmp->rtn = rtn_tmp;

    if(otn_idx != NULL)
    {
        /* loop to the end of the list */
        while(otn_idx->next != NULL)
        {
            otn_idx = otn_idx->next;
        }

        /* setup the new node */
        otn_idx->next = otn_tmp; 

        otn_tmp->next = NULL;
        opt_count++;
    }
    else
    {
        rtn_tmp->down = otn_tmp;
        opt_count++;
    }

    if( one_threshold )
    {
        int rstat;
        thdx.sig_id = otn_tmp->sigInfo.id;
        thdx.gen_id = otn_tmp->sigInfo.generator;
        rstat = sfthreshold_create( &thdx );
        if( rstat )
        {
            if( rstat == THD_TOO_MANY_THDOBJ )
            {
                FatalError("Rule-Threshold-Parse: could not create a threshold object -- only one per sid, sid = %u\n",thdx.sig_id);
            }
            else
            {
                FatalError("Unable to add Threshold object for Rule-sid =  %u\n",thdx.sig_id);
            }
        }
    }
   
    /* Count various rule types */
    if( snort_rule_type == SI_RULE_TYPE_DETECT  ) detect_rule_count++;
    if( snort_rule_type == SI_RULE_TYPE_DECODE  ) decode_rule_count++;
    if( snort_rule_type == SI_RULE_TYPE_PREPROC ) preproc_rule_count++;

    /* setup gid,sid->otn mapping */
    soid_otn_lookup_add( otn_tmp );  
    otn_lookup_add( otn_tmp );  

    /* cleanup */ 
    if(idx != NULL)
        mSplitFree(&toks,original_num_toks);

    return 1;
}


/****************************************************************************
 *
 * Function: RuleType(char *)
 *
 * Purpose:  Determine what type of rule is being processed and return its
 *           equivalent value
 *
 * Arguments: func => string containing the rule type
 *
 * Returns: The rule type designation
 *
 ***************************************************************************/
int RuleType(char *func)
{
    if(func == NULL)
    {
        FatalError("%s(%d) => NULL rule type\n", file_name, file_line);
    }
    
    if(func[0] == '$') 
    {
        char *tok;
        char *end = func;
        int type;

        for(; *end && !isspace((int)*end); end++)
            ;

        tok = SnortStrndup(func + 1, end - func - 1);
        
        type = RuleType(VarGet(tok));

        free(tok);

        return type;
    }   

    if (!strncasecmp(func, "drop", 4))
    {
        if( pv.treat_drop_as_alert )
            return RULE_ALERT;
        else
            return RULE_DROP;
    }

#ifdef GIDS
    if (!strncasecmp(func, "sdrop", 5))
    {
        if( pv.treat_drop_as_alert )
            return RULE_ALERT;
        else
            return RULE_SDROP;
    }
    if (!strncasecmp(func, "reject", 6))
    {
        if( pv.treat_drop_as_alert )
            return RULE_ALERT;
        else
            return RULE_REJECT;
    }
#endif /* GIDS */ 
     
    if(!strncasecmp(func, "log", 3))
        return RULE_LOG;

    if(!strncasecmp(func, "alert", 5))
        return RULE_ALERT;

    if(!strncasecmp(func, "pass", 4))
        return RULE_PASS;

    if(!strncasecmp(func, "var", 3))
        return RULE_VAR;

#ifdef PORTLISTS
    if(!strncasecmp(func, "portvar", 7))
        return RULE_PORTVAR;
#endif

#ifdef SUP_IP6
    if(!strncasecmp(func, "ipvar", 5))
        return RULE_IPVAR;
#endif

    if(!strncasecmp(func, "include", 7))
        return RULE_INCLUDE;

    if(!strncasecmp(func, "preprocessor", 12))
        return RULE_PREPROCESS;

    if(!strncasecmp(func, "output", 6))
        return RULE_OUTPUT;

    if(!strncasecmp(func, "activate", 8))
        return RULE_ACTIVATE;

    if(!strncasecmp(func, "config", 6))
        return RULE_CONFIG;

    if(!strncasecmp(func, "ruletype", 8))
        return RULE_DECLARE;
    
    if(!strncasecmp(func, "threshold", 9))
        return RULE_THRESHOLD;
    
    if(!strncasecmp(func, "suppress", 8))
        return RULE_SUPPRESS;

    if(!strncasecmp(func, "rule_state", 10))
        return RULE_STATE;

#ifdef DYNAMIC_PLUGIN
    if(!strncasecmp(func, "dynamicpreprocessor", 19))
        return RULE_DYNAMICPREPROCESSOR;

    if(!strncasecmp(func, "dynamicdetection", 16))
        return RULE_DYNAMICDETECTION;
    
    if(!strncasecmp(func, "dynamicengine", 13))
        return RULE_DYNAMICENGINE;
#endif
    
    if(!strncasecmp(func, "dynamic", 7))
        return RULE_DYNAMIC;

#ifdef TARGET_BASED
    if(!strcasecmp(func, "attribute_table"))
        return RULE_ATTRIBUTE_TABLE;
#endif

    return RULE_UNKNOWN;
}

/****************************************************************************
 *
 * Function: IsInclude(char *)
 *
 * Purpose:  Determine if this is an include line or not
 *
 * Arguments: func => string containing the rule
 *
 * Returns: 1 if include line, 0 if not
 *
 ***************************************************************************/
static int IsInclude(char *rule)
{
    int rule_type;

    rule_type = RuleType(rule);

    if ( rule_type == RULE_INCLUDE )
    {
        return 1;
    }

    return 0;
}

/****************************************************************************
 *
 * Function: definedRule(char *)
 *
 * Purpose: Check if the rule has already been defined.
 *
 * Arguments: rule => current rule
 *
 * Returns: 1 -- already defined rule type; 0 -- otherwise
 *
 ***************************************************************************/
int definedRule(char *rule)
{
	RuleListNode *node;
	
	nonDefaultRules = RuleLists;
	if( !nonDefaultRules || !rule)
	{
		return 0;
	}
	
	node = nonDefaultRules->next;
	if(node)
	{
		char **toks; 
		int num_toks;  
		toks = mSplit(rule, " ", 2, &num_toks, 0);
		while( node && toks)
		{			
			if(!strcasecmp(node->name, toks[0]))
			{
				mSplitFree(&toks, num_toks);
				return 1;
			}
			node = node->next;
		}
		mSplitFree(&toks, num_toks);
	}
	return 0;	
}

/****************************************************************************
 *
 * Function: IsRule(char *)
 *
 * Purpose:  Determine if this is an actual rule or not
 *
 * Arguments: func => string containing the rule
 *
 * Returns: 1 if a rule, 0 if not
 *
 ***************************************************************************/
static int IsRule(char *rule)
{
    int rule_type;

    rule_type = RuleType(rule);

    if ( rule_type == RULE_ALERT ||
         rule_type == RULE_DROP  ||
         rule_type == RULE_LOG   ||
         rule_type == RULE_PASS  ||
#ifdef GIDS
         rule_type == RULE_SDROP ||
         rule_type == RULE_REJECT ||
#endif
         rule_type == RULE_ACTIVATE ||
         rule_type == RULE_DYNAMIC)
    {
        return 1;
    }
    
    return ( definedRule( rule ) );
}

/****************************************************************************
 *
 * Function: WhichProto(char *)
 *
 * Purpose: Figure out which protocol the current rule is talking about
 *
 * Arguments: proto_str => the protocol string
 *
 * Returns: The integer value of the protocol
 *
 ***************************************************************************/
int WhichProto(char *proto_str)
{
    int ret = 0;

    if(!strcasecmp(proto_str, "tcp"))
        ret = IPPROTO_TCP;
    else if(!strcasecmp(proto_str, "udp"))
        ret = IPPROTO_UDP;
    else if(!strcasecmp(proto_str, "icmp"))
        ret = IPPROTO_ICMP;
    else if(!strcasecmp(proto_str, "ip"))
        ret = ETHERNET_TYPE_IP;
    else
        /*
         * if we've gotten here, we have a protocol string we din't recognize and
         * should exit
         */
        FatalError("%s(%d) => Bad protocol: %s\n", file_name, file_line, proto_str);

    return ret;
}


int ProcessIP(char *addr, RuleTreeNode *rtn, int mode, int neg_list)
{
#ifndef SUP_IP6
    char *tok, *end, *tmp;
    int neg_ip;
#endif

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Got address string: %s\n", 
                addr););

#ifdef SUP_IP6 
    /* If a rule has a variable in it, we want to copy that variable's 
     * contents to the IP variable (IP list) stored with the rtn.
     * This code tries to look up the variable, and if found, will copy it 
     * to the rtn->{sip,dip} */
    if(mode == SRC) 
    {   
        int ret;
        if( !rtn->sip && ((rtn->sip = calloc(1, sizeof(sfip_var_t))) == NULL) ) 
        {
            FatalError("%s(%d) => Failed to allocate memory for address: %s\n",
                file_name, file_line, addr);
        }

        /* The function sfvt_add_to_var adds 'addr' to the variable 'rtn->sip' */
        if((ret = sfvt_add_to_var(vartable, rtn->sip, addr)) != SFIP_SUCCESS) 
        {
            if(ret == SFIP_LOOKUP_FAILURE)
                FatalError("%s(%d) => Undefined variable in the string: %s\n",
                    file_name, file_line, addr);
            else if(ret == SFIP_CONFLICT)
                FatalError("%s(%d) => Negated IP ranges that are more-general"
                    " than non-negated ranges are not allowed. Consider"
                    " inverting the logic: %s.\n", 
                    file_name, file_line, addr);
            else if(ret == SFIP_NOT_ANY) 
                FatalError("%s(%d) => !any is not allowed: %s.\n", 
                    file_name, file_line, addr);
            else
                FatalError("%s(%d) => Unable to process the IP address: %s\n",
                    file_name, file_line, addr);
        }

        if(rtn->sip->head && rtn->sip->head->flags & SFIP_ANY) 
        {
            rtn->flags |= ANY_SRC_IP;
        }
    } 
    /* mode == DST */
    else 
    {
        int ret;
        if( !rtn->dip && ((rtn->dip = calloc(1, sizeof(sfip_var_t))) == NULL) ) 
        {
            FatalError("%s(%d) => Failed to allocate memory for address: %s\n",
                file_name, file_line, addr);
        }

        if((ret = sfvt_add_to_var(vartable, rtn->dip, addr)) != SFIP_SUCCESS) 
        {
            if(ret == SFIP_LOOKUP_FAILURE)
                FatalError("%s(%d) => Undefined variable in the string: %s\n",
                    file_name, file_line, addr);
            else if(ret == SFIP_CONFLICT)
                FatalError("%s(%d) => Negated IP ranges that are more-general"
                    " than non-negated ranges are not allowed. Consider"
                    " inverting the logic: %s.\n", 
                    file_name, file_line, addr);
            else if(ret == SFIP_NOT_ANY) 
                FatalError("%s(%d) => !any is not allowed: %s.\n", 
                    file_name, file_line, addr);
            else
                FatalError("%s(%d) => Unable to process the IP address: %s\n",
                    file_name, file_line, addr);
        }

        if(rtn->dip->head && rtn->dip->head->flags & SFIP_ANY) 
        {
            rtn->flags |= ANY_DST_IP;
        }
    }
#else
    while(*addr) 
    {
        /* Skip whitespace and leading commas */
        for(; *addr && (isspace((int)*addr) || *addr == ','); addr++) ;

        /* Handle multiple negations (such as if someone negates variable that
         * contains a negated IP */
        neg_ip = 0;
        for(; *addr == '!'; addr++) 
             neg_ip = !neg_ip;

        /* Find end of this token */
        for(end = addr+1; 
           *end && !isspace((int)*end) && *end != ']' && *end != ',';
            end++) ;

        tok = SnortStrndup(addr, end - addr);

        if(!tok)
        {
            FatalError("%s(%d) => Unterminated IP List '%s'\n", 
                       file_name, file_line, addr);
        }
        
        if(*addr == '[') 
        {
            int brack_count = 0;
            char *list_tok;
    
            /* Find corresponding ending bracket */
            for(end = addr; *end; end++) 
            {
                if(*end == '[') 
                    brack_count++;
                else if(*end == ']')
                    brack_count--;
    
                if(!brack_count)
                    break;
            }
    
            if(!*end) 
            {
                FatalError("%s(%d) => Unterminated IP List '%s'\n", 
                           file_name, file_line, addr);
            }
        
            addr++;
    
            list_tok = SnortStrndup(addr, end - addr);
        
            if(!list_tok) {
                FatalError("%s(%d) => Failed to allocate space for parsing '%s'\n", 
                           file_name, file_line, addr);
            }

            ProcessIP(list_tok, rtn, mode, neg_list ^ neg_ip);
            free(list_tok);
        }
        else if(*addr == '$') 
        {
            if((tmp = VarGet(tok + 1)) == NULL)
            {
                FatalError("%s(%d) => Undefined variable %s\n", file_name, 
                        file_line, addr);
            }
            
            ProcessIP(tmp, rtn, mode, neg_list ^ neg_ip); 
        }
        else if(*addr == ']')
        {
            if(!(*(addr+1))) 
            {
                /* Succesfully reached the end of this list */
                free(tok);
                return 0;
            }

            FatalError("%s(%d) => Mismatched bracket in '%s'\n", 
                           file_name, file_line, addr);
        }
        else 
        {
            /* Skip leading commas */
            for(; *addr && (*addr == ',' || isspace((int)*addr)); addr++) ;

            if(mode == SRC) 
            {
                if(!rtn->sip)
                    rtn->sip = (IpAddrSet*)SnortAlloc(sizeof(IpAddrSet));

                ParseIP(tok, rtn->sip, neg_list ^ neg_ip);

                if(rtn->sip->iplist && 
                   !rtn->sip->iplist->ip_addr && !rtn->sip->iplist->netmask) 
                    rtn->flags |= ANY_SRC_IP;
                
            }
            else
            {
                if(!rtn->dip)
                    rtn->dip = (IpAddrSet*)SnortAlloc(sizeof(IpAddrSet));

                ParseIP(tok, rtn->dip, neg_list ^ neg_ip);

                if(rtn->dip->iplist &&
                   !rtn->dip->iplist->ip_addr && !rtn->dip->iplist->netmask) 
                    rtn->flags |= ANY_DST_IP;

                /* Note: the neg_iplist is not checked for '!any' here since
                 * ParseIP should have already FatalError'ed on it. */
            }
        }
        
        free(tok);

        if(*end)
            addr = end + 1;   
        else break;
    }
#endif

    return 0;
}


/****************************************************************************
 *
 * Function: ParsePort(char *, u_short *)
 *
 * Purpose:  Convert the port string over to an integer value
 *
 * Arguments: prule_port => port rule string
 *            port => converted integer value of the port
 *
 * Returns: 0 for a normal port number, 1 for an "any" port
 *
 ***************************************************************************/
int ParsePort(char *prule_port, u_short * hi_port, u_short * lo_port, char *proto, int *not_flag)
{
    char **toks;        /* token dbl buffer */
    int num_toks;       /* number of tokens found by mSplit() */
    char *rule_port;    /* port string */

    *not_flag = 0;

    /* check for variable */
    if(!strncmp(prule_port, "$", 1))
    {
        if((rule_port = VarGet(prule_port + 1)) == NULL)
        {
            FatalError("%s(%d) => Undefined variable %s\n", file_name, file_line, prule_port);
        }
    }
    else
        rule_port = prule_port;

    if(rule_port[0] == '(')
    {
        /* user forgot to put a port number in for this rule */
        FatalError("%s(%d) => Bad port number: \"%s\"\n", 
                   file_name, file_line, rule_port);
    }


    /* check for wildcards */
    if(!strcasecmp(rule_port, "any"))
    {
        *hi_port = 0;
        *lo_port = 0;
        return 1;
    } 

    if(rule_port[0] == '!')
    {
        if(!strcasecmp(&rule_port[1], "any"))
        {
            LogMessage("Warning: %s(%d) => Negating \"any\" is invalid. Rule will be ignored\n", 
                            file_name, file_line);
            return -1;
        } 

        *not_flag = 1;
        rule_port++;
    }

    if(rule_port[0] == ':')
    {
        *lo_port = 0;
    }

    toks = mSplit(rule_port, ":", 2, &num_toks, 0);

    switch(num_toks)
    {
        case 1:
            *hi_port = (u_short)ConvPort(toks[0], proto);

            if(rule_port[0] == ':')
            {
                *lo_port = 0;
            }
            else
            {
                *lo_port = *hi_port;

                if(strchr(rule_port, ':') != NULL)
                {
                    *hi_port = 65535;
                }
            }

            break;

        case 2:
            *lo_port = (u_short)ConvPort(toks[0], proto);

            if(toks[1][0] == 0)
                *hi_port = 65535;
            else
                *hi_port = (u_short)ConvPort(toks[1], proto);

            break;

        default:
            FatalError("%s(%d) => port conversion failed on \"%s\"\n",
                       file_name, file_line, rule_port);
    }

    mSplitFree(&toks, num_toks);

    return 0;
}


/****************************************************************************
 *
 * Function: ConvPort(char *, char *)
 *
 * Purpose:  Convert the port string over to an integer value
 *
 * Arguments: port => port string
 *            proto => converted integer value of the port
 *
 * Returns:  the port number
 *
 ***************************************************************************/
u_int16_t ConvPort(char *port, char *proto)
{
    int conv;           /* storage for the converted number */
    char *digit;      /* used to check for a number */
    struct servent *service_info;

    /*
     * convert a "word port" (http, ftp, imap, whatever) to its corresponding
     * numeric port value
     */
    if(isalpha((int) port[0]) != 0)
    {
        service_info = getservbyname(port, proto);

        if(service_info != NULL)
        {
            conv = ntohs(service_info->s_port);
            return conv;
        }
        else
        {
            FatalError("%s(%d) => getservbyname() failed on \"%s\"\n",
                       file_name, file_line, port);
        }
    }
    digit = port;
    while (*digit) {

        if(!isdigit((int) *digit))
        {
            FatalError("%s(%d) => Invalid port: %s\n", file_name,
                       file_line, port);
        }
        digit++;
    }
    /* convert the value */
    conv = atoi(port);

    /* make sure it's in bounds */
    if ((conv < 0) || (conv > 65535))
    {
        FatalError("%s(%d) => bad port number: %s\n", file_name, file_line, port);
    }

    return (u_int16_t)conv;
}



/****************************************************************************
 *
 * Function: ParseMessage(char *)
 *
 * Purpose: Stuff the alert message onto the rule
 *
 * Arguments: msg => the msg string
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParseMessage(char *msg)
{
    char *ptr = NULL; /* The start of the message */
    char *end = NULL; /* The end of the message */
    char *start_msg = msg;    /* Start of search space for first quote */
    char *start_endquote_search; /* Start of search space for last quote */
    char *end_buffer;         /* end of buffer passed in */
    char *start_quote = NULL; /* The leading quote */
    char *end_quote = NULL;  /* The trailing quote */
    int size;
    int count = 0;
    char *read;
    char *write;

    /* mark the end of the buffer */
    end_buffer = msg + strlen(msg) -1;

    /* figure out where the message starts... */
    while (ptr == NULL)
    {
        ptr = strchr(start_msg, '"');

        if(ptr == NULL)
        {
            ptr = msg;
        }
        else
        {
            if ((ptr > msg + 1) &&
                *(ptr-1) == '\\')
            {
                /* Escaped quote... */
                start_msg = ptr+1;
                ptr = NULL;
                continue;
            }

            start_quote = ptr;
            ptr++;
        }
    }
    /* here, ptr should be the byte after the first quote or
     * the first byte, if no quotes... */
    
    /* ...and ends */
    start_endquote_search = ptr; 
    while (end == NULL)
    {
        end = strrchr(start_endquote_search, '"');

        if(end == NULL)
        {
            end = ptr + strlen(ptr);
        }
        else
        {
            if ((end > msg + 1) &&
                *(end-1) == '\\')
            {
                /* escaped quote is the late one... */
                start_endquote_search = end+1;
                end = ptr + strlen(ptr);
            }
            else
            {
                end_quote = end;
                *end = 0;
            }
        }
    }

    /* mismatched quotes that aren't escaped */
    if (((start_quote) && (!end_quote)) ||
        ((!start_quote) && (end_quote)))
    {
        FatalError("%s(%d): Rule message with mismatching leading and trailing quotes.\n",
            file_name, file_line);
    }

    /* eliminate leading spaces from message in rule */
    while(isspace((int) *ptr))
        ptr++;

    /* check for missing semi-colons */
    if (end < end_buffer)
    {
        FatalError("%s(%d): Rule message not properly terminated\n",
            file_name, file_line);
    }

    if ((start_quote) && (start_quote != msg))
    {
        ErrorMessage("%s(%d): Rule message has extraneous leading characters.  Missing escaped quote?\n",
            file_name, file_line);
    }

    read = write = ptr;

    while(read < end && write < end)
    {
        if(*read == '\\')
        {
            read++;
            count++;

            if(read >= end)
            {
                break;
            }
        }

        *write++ = *read++;
    }

    if(end)
    {
        *(end - count) = '\x0';
    }

    /* find the end of the alert string */
    size = strlen(msg) + 1;
    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES, "Message: %s\n", msg););

    /* alloc space for the string and put it in the rule */
    if(size > 0)
    {
        otn_tmp->sigInfo.message = SnortStrdup(ptr);

        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES, "Rule message set to: %s\n", 
                otn_tmp->sigInfo.message););

    }
    else
    {
        ErrorMessage("%s(%d): bad alert message size %d\n", file_name, 
                     file_line, size);
    }

    return;
}



/****************************************************************************
 *
 * Function: ParseLogto(char *)
 *
 * Purpose: stuff the special log filename onto the proper rule option
 *
 * Arguments: filename => the file name
 *
 * Returns: void function
 *
 ***************************************************************************/
void ParseLogto(char *filename)
{
    char *sptr;
    char *eptr;

    /* grab everything between the starting " and the end one */
    sptr = strchr(filename, '"');
    eptr = strrchr(filename, '"');

    if(sptr != NULL && eptr != NULL)
    {
        /* increment past the first quote */
        sptr++;

        /* zero out the second one */
        *eptr = 0;
    }
    else
    {
        sptr = filename;
    }

    /* alloc up a nice shiny clean buffer */
    otn_tmp->logto = (char *)SnortAlloc((strlen(sptr) + 1) * sizeof(char));

    SnortStrncpy(otn_tmp->logto, sptr, strlen(sptr) + 1);

    return;
}




/****************************************************************************
 *
 * Function: ParseActivates(char *)
 *
 * Purpose: Set an activation link record
 *
 * Arguments: act_num => rule number to be activated
 *
 * Returns: void function
 *
 ****************************************************************************/
void ParseActivates(char *act_num)
{
    /*
     * allocate a new node on the RTN get rid of whitespace at the front of
     * the list
     */
    while(!isdigit((int) *act_num))
        act_num++;

    otn_tmp->activates = atoi(act_num);

    return;
}




/****************************************************************************
 *
 * Function: ParseActivatedBy(char *)
 *
 * Purpose: Set an activation link record
 *
 * Arguments: act_by => rule number to be activated
 *
 * Returns: void function
 *
 ****************************************************************************/
void ParseActivatedBy(char *act_by)
{
    ActivateList *al_ptr;

    al_ptr = rtn_tmp->activate_list;

    if(al_ptr == NULL)
    {
        rtn_tmp->activate_list = (ActivateList *)SnortAlloc(sizeof(ActivateList));

        al_ptr = rtn_tmp->activate_list;
    }
    else
    {
        while(al_ptr->next != NULL)
        {
            al_ptr = al_ptr->next;
        }

        al_ptr->next = (ActivateList *)SnortAlloc(sizeof(ActivateList));

        al_ptr = al_ptr->next;
    }

    /* get rid of whitespace at the front of the list */
    while(!isdigit((int) *act_by))
        act_by++;

    /* set the RTN list node number */
    al_ptr->activated_by = atoi(act_by);

    /* set the OTN list node number */
    otn_tmp->activated_by = atoi(act_by);

    return;
}



void ParseCount(char *num)
{
    while(!isdigit((int) *num))
        num++;

    otn_tmp->activation_counter = atoi(num);

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Set activation counter to %d\n", otn_tmp->activation_counter););

    return;
}




/****************************************************************************
 *
 * Function: XferHeader(RuleTreeNode *, RuleTreeNode *)
 *
 * Purpose: Transfer the rule block header data from point A to point B
 *
 * Arguments: rule => the place to xfer from
 *            rtn => the place to xfer to
 *
 * Returns: void function
 *
 ***************************************************************************/
void XferHeader(RuleTreeNode * rule, RuleTreeNode * rtn)
{
    rtn->flags = rule->flags;
    rtn->type = rule->type;
    rtn->sip = rule->sip;
    rtn->dip = rule->dip;

    // PORTLISTS
    rtn->proto=rule->proto;

#ifdef PORTLISTS
    rtn->src_portobject = rule->src_portobject;
    rtn->dst_portobject = rule->dst_portobject;
#endif
   
    rtn->hsp = rule->hsp;
    rtn->lsp = rule->lsp;
    rtn->hdp = rule->hdp;
    rtn->ldp = rule->ldp;
    rtn->not_sp_flag = rule->not_sp_flag;
    rtn->not_dp_flag = rule->not_dp_flag;
}

/****************************************************************************
 *
 * Function: CompareIPNodes(RuleTreeNode *, RuleTreeNode *).  Support function
 *           for CompareIPLists.
 *
 * Purpose: Checks if the node's contents equal.
 *
 * Returns: 1 if they match, 0 if they don't
 *
 ***************************************************************************/
int CompareIPNodes(IpAddrNode *one, IpAddrNode *two) 
{
#ifdef SUP_IP6
     if( (sfip_compare(one->ip, two->ip) != SFIP_EQUAL) ||
         (sfip_bits(one->ip) != sfip_bits(two->ip)) ||
         (sfvar_flags(one) != sfvar_flags(two)) )
         return 0;
#else

     if( (one->ip_addr != two->ip_addr) ||
         (one->netmask != two->netmask) ||
         (one->addr_flags != two->addr_flags) )
         return 0;
#endif
    return 1;
}

/****************************************************************************
 *
 * Function: CompareIPLists(RuleTreeNode *, RuleTreeNode *).  Support function
 *           for TestHeader.
 *
 * Purpose: Checks if all nodes in each list are present in the other
 *
 * Returns: 1 if they match, 0 if they don't
 *
 ***************************************************************************/
int CompareIPLists(IpAddrNode *one, IpAddrNode *two) 
{
    IpAddrNode *idx1, *idx2;
    int i, match;
    int total1 = 0;
    int total2 = 0;
    char *usage;

    /* Walk first list.  For each node, check if there is an equal
     * counterpart in the second list.  This method breaks down of there are 
     * duplicated nodes.  For instance, if one = {a, b} and two = {a, a}.
     * Therefore, need additional data structure[s] ('usage') to check off 
     * which nodes have been accounted for already. 
     *
     * Also, the lists are unordered, so comparing node-for-node won't work */

    for(idx1 = one; idx1; idx1 = idx1->next) 
        total1++;
    for(idx2 = two; idx2; idx2 = idx2->next) 
        total2++;

    if(total1 != total2) 
        return 0;

    usage = (char *)SnortAlloc(total1);

    for(idx1 = one; idx1; idx1 = idx1->next, i++)
    {
        match = 0;

        for(idx2 = two, i = 0; idx2; idx2 = idx2->next, i++)
        {
            if(CompareIPNodes(idx1, idx2) && !usage[i])
            {
                match = 1;
                usage[i] = 1;
                break;
            }
        }

        if(!match) {
            free(usage);
            return 0;
        }
    }

    free(usage);
    return 1;
}


/****************************************************************************
 *
 * Function: TestHeader(RuleTreeNode *, RuleTreeNode *)
 *
 * Purpose: Check to see if the two header blocks are identical
 *
 * Arguments: rule => uh
 *            rtn  => uuuuhhhhh....
 *
 * Returns: 1 if they match, 0 if they don't
 *
 ***************************************************************************/
int TestHeader(RuleTreeNode * rule, RuleTreeNode * rtn)
{
#ifdef SUP_IP6    
    if(rule->sip && rtn->sip)
    {
        if(sfvar_compare(rule->sip, rtn->sip) != SFIP_EQUAL) 
        {
            return 0;
        }
    }

    if(rule->dip && rtn->dip)
    {
        if(sfvar_compare(rule->dip, rtn->dip) != SFIP_EQUAL)
        {
            return 0;
        }
    }
#else
    if(rule->sip && rtn->sip)
    {
        if(!CompareIPLists(rule->sip->iplist, rtn->sip->iplist)) 
            return 0;
        if(!CompareIPLists(rule->sip->neg_iplist, rtn->sip->neg_iplist))
            return 0;
    }

    if(rule->dip && rtn->dip)
    {
        if(!CompareIPLists(rule->dip->iplist, rtn->dip->iplist)) 
            return 0;
        if(!CompareIPLists(rule->dip->neg_iplist, rtn->dip->neg_iplist))
            return 0;
    }
#endif

#ifdef PORTLISTS
    /* 
    * compare the port group pointers - this prevents confusing src/dst port objects 
    * with the same port set, and it's quicker. It does assume that we only have 
    * one port object and pointer for each unique port set...this is handled by the
    * parsing and initial port object storage and lookup.  This must be consistent during
    * the rule parsing phase. - man
    */ 
    if( rtn->src_portobject==rule->src_portobject )
        if( rtn->dst_portobject==rule->dst_portobject )
            if( rtn->flags == rule->flags)
                return 1;
#else

    if((rtn->hsp == rule->hsp) && (rtn->lsp == rule->lsp) &&
       (rtn->hdp == rule->hdp) && (rtn->ldp == rule->ldp) &&
       (rtn->flags == rule->flags))
        return 1;
#endif

    return 0;
}

#ifdef PORTLISTS
/*
 * PortVarDefine
 *
 *  name - portlist name, i.e. http, smtp, ...
 *  s    - port number, port range, or a list of numbers/ranges in brackets
 * 
 *  examples:
 *  portvar http [80,8080,8138,8700:8800,!8711]
 *  portvar http $http_basic
 */
int PortVarDefine( char * name, char * s )
{
    PortObject *po;
    POParser pop;
    char *errstr="unknown";
    int   rstat;
    
    DisallowCrossTableDuplicateVars(name, RULE_PORTVAR); 

    if( SnortStrcasestr(s,"any") ) /* this allows 'any' or '[any]' */
    {
      if(strstr(s,"!"))
      {
        FatalError("%s(%d) => illegal use of negation and 'any': %s\n", 
                   file_name, file_line, s);
      }

      po = PortObjectNew();
      if( !po )
      {
        FatalError("PortVarTable missing an 'any' variable\n");
      }
      PortObjectSetName( po, name );
      PortObjectAddPortAny( po );
    }
    else
    {
      /* Parse the Port List info into a PortObject  */
      po = PortObjectParseString(portVarTable,&pop,name,s,0);
      if(!po)
      {
         errstr = PortObjectParseError( &pop );
         FatalError("%s(%d) *** PortVar Parse error: (pos=%d,error=%s)\n>>%s\n>>%*s\n",
                file_name, file_line,
                pop.pos,errstr,s,pop.pos,"^");
      }
    }
    
    /* Add The PortObject to the PortList Table */
    rstat = PortVarTableAdd( portVarTable, po );
    if( rstat < 0 )
    {
        FatalError("%s(%d) ***PortVarTableAdd failed with '%s', exiting ",
            file_name, file_line, po->name);
    }
    else if( rstat > 0 )
    {
        LogMessage("%s(%d) PortVar '%s', already defined.\n",
            file_name, file_line, po->name);
    }

    /* Print the PortList - PortObjects */
    LogMessage("PortVar '%s' defined : ",po->name);
    PortObjectPrintPortsRaw(po);
    LogMessage("\n");

    return 0;
}
#endif

/****************************************************************************
 *
 * Function: VarAlloc()
 *
 * Purpose: allocates memory for a variable
 *
 * Arguments: none
 *
 * Returns: pointer to new VarEntry
 *
 ***************************************************************************/
struct VarEntry *VarAlloc()
{
    struct VarEntry *new;

    new = (struct VarEntry *)SnortAlloc(sizeof(struct VarEntry));

    return(new);
}

#ifdef SUP_IP6
/****************************************************************************
 *
 * Function: VarIsIpAddr(char *, char *)
 *
 * Purpose: Checks if a var is an IP address. Necessary since moving forward
 *          we want all IP addresses handled by the IP variable table.
 *
 * Arguments: value => the string to check
 *
 * Returns: 1 if IP address, 0 otherwise
 *
 ***************************************************************************/
int VarIsIpAddr(char *value) 
{
    char *tmp;

    while(*value == '!' || *value == '[') value++;

    /* Check for dotted-quad */
    if( isdigit((int)*value) &&
         ((tmp = strchr(value, (int)'.')) != NULL) && 
         ((tmp = strchr(tmp+1, (int)'.')) != NULL) &&
         (strchr(tmp+1, (int)'.') != NULL))
        return 1; 

    /* IPv4 with a mask, and fewer than 4 fields */
    if( isdigit((int)*value) &&
         (strchr(value+1, (int)':') == NULL) &&
         ((tmp = strchr(value+1, (int)'/')) != NULL) &&
         isdigit((int)(*(tmp+1))) )
        return 1;

    /* IPv6 */
    if((tmp = strchr(value, (int)':')) != NULL) 
    {
        char *tmp2;

        if((tmp2 = strchr(tmp+1, (int)':')) == NULL) 
            return 0;

        for(tmp++; tmp < tmp2; tmp++)
            if(!isxdigit((int)*tmp)) 
                return 0;

        return 1;
    }

    /* Any */
    if(!strncmp(value, "any", 3))
        return 1;

    /* Check if it's a variable containing an IP */
    if(sfvt_lookup_var(vartable, value+1) || sfvt_lookup_var(vartable, value))
        return 1;

    return 0;
}
#endif

/****************************************************************************
 *
 * Function: DisallowCrossTableDuplicateVars(char *, int) 
 *
 * Purpose: FatalErrors if the a variable name is redefined across variable 
 *          types.  Enforcing this mutual exclusion prevents the
 *          catatrophe where the variable lookup fall-through (see VarSearch)
 *          finds an unintended variable from the wrong table.  Note:  VarSearch
 *          is only necessary for ExpandVars. 
 *
 * Arguments: name => The name of the variable
 *            var_type => The type of the variable that is about to be defined.
 *                        The corresponding variable table will not be searched.
 *
 * Returns: void function
 *
 ***************************************************************************/
void DisallowCrossTableDuplicateVars( char *name, int var_type) 
{

#if defined(SUP_IP6) || defined(PORTLISTS)
    struct VarEntry *p = VarHead;
#endif

#ifdef PORTLISTS
    /* If this is a faked Portvar, treat as a portvar */
    if(var_type == RULE_VAR && (strstr(name, "_PORT") || strstr(name, "PORT_")))
    {
        var_type = RULE_PORTVAR;
    }
#endif

    switch(var_type) 
    {
        case RULE_VAR:
            if(
#ifdef SUP_IP6
               sfvt_lookup_var(vartable, name) ||
#endif
#ifdef PORTLISTS
               PortVarTableFind(portVarTable, name) ||
#endif
            /* This 0 is for the case that neither IPv6 
             * support or Portlists is compiled in. Quiets a warning. */
            0) 
            {
                FatalError("%s(%d) => Can not redefine variable name %s"
                                   " to be of type 'var'. Use a different"
                                   " name.\n", file_name, file_line, name);
            }
            break;

#ifdef PORTLISTS
        case RULE_PORTVAR:
            if(VarHead) 
            {
                do
                {
                    if(strcasecmp(p->name, name) == 0)
                    {
                        FatalError("%s(%d) => Can not redefine variable name %s"
                                   " to be of type 'portvar'. Use a different"
                                   " name.\n", file_name, file_line, name);
                    }
                    p = p->next;
                } while(p != VarHead);
            }

#ifdef SUP_IP6
            if(sfvt_lookup_var(vartable, name))
            {
                FatalError("%s(%d) => Can not redefine variable name %s"
                                   " to be of type 'portvar'. Use a different"
                                   " name.\n", file_name, file_line, name);
            }
#endif /* SUP_IP6 */
#endif /* PORTLISTS */

            break;

#ifdef SUP_IP6
        case RULE_IPVAR:
            if(VarHead) 
            {
                do
                {
                    if(strcasecmp(p->name, name) == 0)
                    {
                        FatalError("%s(%d) => Can not redefine variable name %s"
                                   " to be of type 'ipvar'. Use a different"
                                   " name.\n", file_name, file_line, name);
                    }

                    p = p->next;
                } while(p != VarHead);
            }

#ifdef PORTLISTS
            if(PortVarTableFind(portVarTable, name)) 
            {
                FatalError("%s(%d) => Can not redefine variable name %s"
                                   " to be of type 'ipvar'. Use a different"
                                   " name.\n", file_name, file_line, name);
            }
#endif /* PORTLISTS */
#endif /* SUP_IP6 */

        default:
            /* Invalid function usage */
            break;
    };
}

/****************************************************************************
 *
 * Function: VarDefine(char *, char *)
 *
 * Purpose: define the contents of a variable
 *
 * Arguments: name => the name of the variable
 *            value => the contents of the variable
 *
 * Returns: void function
 *
 ***************************************************************************/
struct VarEntry *VarDefine(char *name, char *value)
{
    struct VarEntry *p;
    //int    vlen,n;
    //char  *s;

    if(value == NULL)
    {
        FatalError("%s(%d): Bad value in variable definition!\n"
                   "Make sure you don't have a \"$\" in the var name\n",
                   file_name, file_line);
    }

#ifdef SUP_IP6
    if(VarIsIpAddr(value)) 
    {
        SFIP_RET ret;

        /* Verify a variable by this name is not already used as either a 
         * portvar or regular var.  Enforcing this mutual exclusion prevents the
         * catatrophe where the variable lookup fall-through (see VarSearch)
         * finds an unintended variable from the wrong table.  Note:  VarSearch
         * is only necessary for ExpandVars. */
        DisallowCrossTableDuplicateVars(name, RULE_IPVAR); 

        if((ret = sfvt_define(vartable, name, value)) != SFIP_SUCCESS)
        {
            switch(ret) {
                case SFIP_ARG_ERR:
                    FatalError("%s(%d) The following is not allowed: %s\n", 
                        file_name, file_line, value);

                case SFIP_DUPLICATE:
                    LogMessage("%s(%d) Var '%s' redefined\n",
                        file_name, file_line, name);
                    break;

                case SFIP_CONFLICT:
                    FatalError("%s(%d) => Negated IP ranges that are more-general"
                    " than non-negated ranges are not allowed. Consider"
                    " inverting the logic in %s.\n", 
                    file_name, file_line, name);

                case SFIP_NOT_ANY:
                    FatalError("%s(%d) => !any is not allowed in %s.\n", 
                        file_name, file_line, name);

                default:
                    FatalError("%s(%d) Failed to parse the IP address: %s\n", 
                        file_name, file_line, value);
            }
        }
        return NULL;
    }
    /* Check if this is a variable that stores an IP */
    else if(*value == '$')
    {
        sfip_var_t *var;
        if((var = sfvt_lookup_var(vartable, value)) != NULL) 
        {
            sfvt_define(vartable, name, value);
            return NULL;
        }
    }

#endif

#ifdef PORTLISTS
    DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,
               "VarDefine: name=%s value=%s\n",name,value););
    value = ExpandVars(value); 
    if(!value)
    {
       FatalError("Could not expand var('%s')\n",name);
    }
    DEBUG_WRAP(DebugMessage(DEBUG_PORTLISTS,
               "VarDefine: name=%s value=%s (expanded)\n",name,value););
#endif
    
    DisallowCrossTableDuplicateVars(name, RULE_VAR); 

    if(!VarHead)
    {
        p = VarAlloc();
        p->name  = SnortStrdup(name);
        p->value = SnortStrdup(value);
        
        p->prev = p;
        p->next = p;

        VarHead = p;

        return p;
    }
    p = VarHead;

    do
    {
        if(strcasecmp(p->name, name) == 0)
        {
            if (!(p->flags & VAR_STATIC))
            {
                if( p->value )
                    free(p->value);
                
                p->value = SnortStrdup(value);
            }
            LogMessage("Var '%s' redefined\n", p->name);
            return (p);
        }
        p = p->next;

    } while(p != VarHead);

    p = VarAlloc();
    p->name  = SnortStrdup(name);
    p->value = SnortStrdup(value);

    p->prev = VarHead;
    p->next = VarHead->next;
    p->next->prev = p;
    VarHead->next = p;
    
#ifdef XXXXXXX
    vlen = strlen(value);
    LogMessage("Var '%s' defined, value len = %d chars", p->name, vlen  );
 
    if( vlen < 64 )
    {
      LogMessage(", value = %s\n", value );
    }
    else
    {
      LogMessage("\n");
      n = 128;
      s = value;
      while(vlen)
      {
         if( n > vlen ) n = vlen;
         LogMessage("   %.*s\n", n, s );
         s    += n;
         vlen -= n;
      }
    }
#endif

    return p;
}

#ifndef SUP_IP6
/****************************************************************************
 *
 * Function: VarDelete(char *)
 *
 * Purpose: deletes a defined variable
 *
 * Arguments: name => the name of the variable
 *
 * Returns: void function
 *
 ***************************************************************************/
void VarDelete(char *name)
{
    struct VarEntry *p;


    if(!VarHead)
        return;

    p = VarHead;

    do
    {
        if(strcasecmp(p->name, name) == 0)
        {
            p->prev->next = p->next;
            p->next->prev = p->prev;

            if(VarHead == p)
                if((VarHead = p->next) == p)
                    VarHead = NULL;

            if(p->name)
                free(p->name);

            if(p->value)
                free(p->value);

            free(p);

            return;
        }
        p = p->next;

    } while(p != VarHead);
}
#endif

static void DeleteVars()
{
    struct VarEntry *q, *p = VarHead;
    
    while (p)
    {
        q = p->next;
        if (p->name)
            free(p->name);
        if (p->value)
            free(p->value);
        free(p);
        p = q;
        if (p == VarHead)
            break;  /* Grumble, it's a friggin circular list */
    }
    VarHead = NULL;
}

/****************************************************************************
 *
 * Function: VarGet(char *)
 *
 * Purpose: get the contents of a variable
 *
 * Arguments: name => the name of the variable
 *
 * Returns: char * to contents of variable or FatalErrors on an
 *          undefined variable name
 *
 ***************************************************************************/
char *VarGet(char *name)
{
#ifdef SUP_IP6
// XXX-IPv6 This function should never be used if IP6 support is enabled!
// Infact it won't presently even work for IP variables since the raw ASCII 
// value is never stored, and is never meant to be used.
    sfip_var_t *var;

    if((var = sfvt_lookup_var(vartable, name)) == NULL) {
        /* Do the old style lookup since it wasn't found in 
         * the variable table */
        if(VarHead)
        {
            struct VarEntry *p = VarHead;
            do
            {
                if(strcasecmp(p->name, name) == 0)
                    return p->value;
                p = p->next;
            } while(p != VarHead);
        }
       
        FatalError("Undefined variable name: (%s:%d): %s\n", 
               file_name, file_line, name);
    }

    return name;
#else
    struct VarEntry *p = NULL;
    char *ret = NULL;

    if (VarHead != NULL)
    {
        p = VarHead;

        do
        {
            if (strcasecmp(p->name, name) == 0)
            {
                ret = p->value;
                break;
            }

            p = p->next;

        } while (p != VarHead);
    }

    if (ret == NULL)
    {
        FatalError("Undefined variable name: (%s:%d): %s\n", 
                   file_name, file_line, name);
    }
    
    return ret;
#endif
}

/****************************************************************************
 *
 * Function: ExpandVars(char *)
 *
 * Purpose: expand all variables in a string
 *
 * Arguments: string => the name of the variable
 *
 * Returns: char * to the expanded string
 *
 ***************************************************************************/
char *ExpandVars(char *string)
{
    static char estring[ PARSERULE_SIZE ];

    char rawvarname[128], varname[128], varaux[128], varbuffer[128];
    char varmodifier, *varcontents;
    int varname_completed, c, i, j, iv, jv, l_string, name_only;
    int quote_toggle = 0;

    if(!string || !*string || !strchr(string, '$'))
        return(string);

    bzero((char *) estring, PARSERULE_SIZE);

    i = j = 0;
    l_string = strlen(string);
    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES, "ExpandVars, Before: %s\n", string););

    while(i < l_string && j < sizeof(estring) - 1)
    {
        c = string[i++];
        
        if(c == '"')
        {
            /* added checks to make sure that we are inside a quoted string
             */
            quote_toggle ^= 1;
        }

        if(c == '$' && !quote_toggle)
        {
            bzero((char *) rawvarname, sizeof(rawvarname));
            varname_completed = 0;
            name_only = 1;
            iv = i;
            jv = 0;

            if(string[i] == '(')
            {
                name_only = 0;
                iv = i + 1;
            }

            while(!varname_completed
                  && iv < l_string
                  && jv < sizeof(rawvarname) - 1)
            {
                c = string[iv++];

                if((name_only && !(isalnum(c) || c == '_'))
                   || (!name_only && c == ')'))
                {
                    varname_completed = 1;

                    if(name_only)
                        iv--;
                }
                else
                {
                    rawvarname[jv++] = (char)c;
                }
            }

            if(varname_completed || iv == l_string)
            {
                char *p;

                i = iv;

                varcontents = NULL;

                bzero((char *) varname, sizeof(varname));
                bzero((char *) varaux, sizeof(varaux));
                varmodifier = ' ';

                p = strchr(rawvarname, ':');
                if (p)
                {
                    SnortStrncpy(varname, rawvarname, p - rawvarname);

                    if(strlen(p) >= 2)
                    {
                        varmodifier = *(p + 1);
                        SnortStrncpy(varaux, p + 2, sizeof(varaux));
                    }
                }
                else
                    SnortStrncpy(varname, rawvarname, sizeof(varname));

                bzero((char *) varbuffer, sizeof(varbuffer));

                varcontents = VarSearch(varname);

                switch(varmodifier)
                {
                    case '-':
                        if(!varcontents || !strlen(varcontents))
                            varcontents = varaux;
                        break;

                    case '?':
                        if(!varcontents || !strlen(varcontents))
                        {
                            ErrorMessage("%s(%d): ", file_name, file_line);

                            if(strlen(varaux))
                                FatalError("%s\n", varaux);
                            else
                                FatalError("Undefined variable \"%s\"\n", varname);
                        }
                        break;
                }

                /* If variable not defined now, we're toast */
                if(!varcontents || !strlen(varcontents))
                {
                    FatalError("Undefined variable name: (%s:%d): %s\n",
                        file_name, file_line, varname);
                }

                if(varcontents)
                {
                    int l_varcontents = strlen(varcontents);

                    iv = 0;

                    while(iv < l_varcontents && j < sizeof(estring) - 1)
                        estring[j++] = varcontents[iv++];
                }
            }
            else
            {
                estring[j++] = '$';
            }
        }
        else
        {
            estring[j++] = (char)c;
        }
    }

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES, "ExpandVars, After: %s\n", estring););

    return estring;
}



/******************************************************************
 *
 * Function: LinkDynamicRules()
 *
 * Purpose: Move through the activation and dynamic lists and link
 *          the activation rules to the rules that they activate.
 *
 * Arguments: None
 *
 * Returns: void function
 *
 ******************************************************************/
void LinkDynamicRules()
{
    SetLinks(Activation.TcpList, Dynamic.TcpList);
    SetLinks(Activation.UdpList, Dynamic.UdpList);
    SetLinks(Activation.IcmpList, Dynamic.IcmpList);
}




/******************************************************************
 *
 * Function: SetLinks()
 *
 * Purpose: Move through the activation and dynamic lists and link
 *          the activation rules to the rules that they activate.
 *
 * Arguments: activator => the activation rules
 *            activatee => the rules being activated
 *
 * Returns: void function
 *
 ******************************************************************/
void SetLinks(RuleTreeNode * activator, RuleTreeNode * activated_by)
{
    RuleTreeNode *act_idx;
    RuleTreeNode *dyn_idx;
    OptTreeNode *act_otn_idx;

    act_idx = activator;
    dyn_idx = activated_by;

    /* walk thru the RTN list */
    while(act_idx != NULL)
    {
        if(act_idx->down != NULL)
        {
            act_otn_idx = act_idx->down;

            while(act_otn_idx != NULL)
            {
                act_otn_idx->RTN_activation_ptr = GetDynamicRTN(act_otn_idx->activates, dyn_idx);

                if(act_otn_idx->RTN_activation_ptr != NULL)
                {
                    act_otn_idx->OTN_activation_ptr = GetDynamicOTN(act_otn_idx->activates, act_otn_idx->RTN_activation_ptr);
                }
                act_otn_idx = act_otn_idx->next;
            }
        }
        act_idx = act_idx->right;
    }
}



RuleTreeNode *GetDynamicRTN(int link_number, RuleTreeNode * dynamic_rule_tree)
{
    RuleTreeNode *rtn_idx;
    ActivateList *act_list;

    rtn_idx = dynamic_rule_tree;

    while(rtn_idx != NULL)
    {
        act_list = rtn_idx->activate_list;

        while(act_list != NULL)
        {
            if(act_list->activated_by == link_number)
            {
                return rtn_idx;
            }
            act_list = act_list->next;
        }

        rtn_idx = rtn_idx->right;
    }

    return NULL;
}




OptTreeNode *GetDynamicOTN(int link_number, RuleTreeNode * dynamic_rule_tree)
{
    OptTreeNode *otn_idx;

    otn_idx = dynamic_rule_tree->down;

    while(otn_idx != NULL)
    {
        if(otn_idx->activated_by == link_number)
        {
            return otn_idx;
        }
        otn_idx = otn_idx->next;
    }

    return NULL;
}


/****************************************************************************
 *
 * Function: ProcessAlertFileOption(char *)
 *
 * Purpose: define the alert file
 *
 * Arguments: filespec => the file specification
 *
 * Returns: void function
 *
 ***************************************************************************/
void ProcessAlertFileOption(char *filespec)
{
    pv.alert_filename = ProcessFileOption(filespec);

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"alertfile set to: %s\n", 
                pv.alert_filename););
    return;
}

char *ProcessFileOption(const char *filespec)
{
    char *filename;
    char buffer[STD_BUF];

    if(filespec == NULL)
    {
        FatalError("no arguement in this file option, remove extra ':' at the end of the alert option\n");
    }

    /* look for ".." in the string and complain and exit if it is found */
    if(strstr(filespec, "..") != NULL)
    {
        FatalError("file definition contains \"..\".  Do not do that!\n");
    }

    if(filespec[0] == '/')
    {
        /* absolute filespecs are saved as is */
        filename = SnortStrdup(filespec);
    }
    else
    {
        /* relative filespec is considered relative to the log directory */
        /* or /var/log if the log directory has not been set */
        if(pv.log_dir)
        {
            strlcpy(buffer, pv.log_dir, STD_BUF);
        }
        else
        {
            strlcpy(buffer, "/var/log/snort", STD_BUF);
        }

        strlcat(buffer, "/", STD_BUF - strlen(buffer));
        strlcat(buffer, filespec, STD_BUF - strlen(buffer));
        filename = SnortStrdup(buffer);
    }

    if(!pv.quiet_flag)
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"ProcessFileOption: %s\n", filename););

    return filename;
}

void ProcessFlowbitsSize(char **args, int nargs)
{
    int i;
    char *pcEnd;

    if(nargs)
    {
        i = strtol(args[0], &pcEnd, 10);
        if(*pcEnd || i < 0 || i > 256)
        {
            FatalError("%s(%d) => Invalid argument to 'flowbits_size'.  "  
                       "Must be a positive integer and less than 256.\n",
                       file_name, file_line);
        }
        
        giFlowbitSize = (unsigned int)i;
    }

    return;
}
#ifdef PPM_MGR
/*
 * config ppm: feature, feature, feature,..
 * 
 * config ppm: max-pkt-time usecs,
 *             disable-pkt-inspection,
 *             max-rule-time usecs, 
 *             disable-rule-inspection, threshold 5,
 *             max-suspend-time secs,
 *             rule-events alert|syslog|console,
 *             pkt-events  alert|syslog|console,
 *             debug,
 *             debug-pkts
 */
void ProcessPPMOptions( char ** cargs, int ncargs )
{
    int i;
    char * endp;
    unsigned long val;
    char ** args;
    int    nargs;
    int pktOpts = 0, ruleOpts = 0;
  
    /* 
    * defaults are set by ppm_init() 
    */
    for(i=0;i<ncargs;i++)
    {
        args = mSplit(cargs[i], " ",10, &nargs, 0);
        
        if( nargs < 1 )
        {
            continue;
        }
        else if( !strcasecmp(args[0],"max-pkt-time") )
        {
            if( 2 != nargs )
                FatalError("%s(%d) => config ppm: missing argument for  '%s'.\n", 
                        file_name, file_line, args[0]);

            val = strtoul(args[1], &endp, 0);
            if (args[1] == endp || *endp || strchr(args[1], '-'))
                FatalError("%s(%d) => config ppm: Invalid %s '%s'.\n", 
                        file_name, file_line, args[0], args[1]);

            ppm_set_max_pkt_time(val);
        }
        else if(!strcasecmp(args[0], "max-rule-time"))
        {
            if( 2 != nargs  )
                FatalError("%s(%d) => config ppm: missing argument for  '%s'.\n", 
                        file_name, file_line, args[0]);

            val = strtoul(args[1], &endp, 0);
            if (args[1] == endp || *endp || strchr(args[1], '-'))
                FatalError("%s(%d) => config ppm: Invalid %s '%s'.\n", 
                        file_name, file_line, args[0], args[1]);
           
            ppm_set_max_rule_time(val);
        }
        else if(!strcasecmp(args[0], "suspend-timeout"))
        {
            if( 2 != nargs  )
                FatalError("%s(%d) => config ppm: missing argument for  '%s'.\n", 
                        file_name, file_line, args[0]);

            val = strtoul(args[1], &endp, 0);
            if (args[1] == endp || *endp || strchr(args[1], '-'))
                FatalError("%s(%d) => config ppm: Invalid %s '%s'.\n", 
                        file_name, file_line, args[0], args[1]);
           
            ppm_set_max_suspend_time(val);
            ruleOpts++;
        }
        else if(!strcasecmp(args[0], "suspend-expensive-rules"))
        {
            if( 1 != nargs )
                FatalError("%s(%d) => config ppm: too many arguments for '%s'.\n", 
                        file_name, file_line, args[0]);
            ppm_set_rule_action(PPM_ACTION_SUSPEND);
            ruleOpts++;
        }
        else if( !strcasecmp(args[0],"threshold") )
        {
            if( 2 != nargs )
                FatalError("%s(%d) => config ppm: missing argument for  '%s'.\n", 
                        file_name, file_line, args[0]);

           val = strtoul(args[1], &endp, 0);
           if (args[1] == endp || *endp || strchr(args[1], '-'))
                FatalError("%s(%d) => config ppm: Invalid %s '%s'.\n", 
                        file_name, file_line, args[0], args[1]);

            ppm_set_rule_threshold(val);
            ruleOpts++;
        }
        else if(!strcasecmp(args[0], "fastpath-expensive-packets"))
        {
            if( 1 != nargs )
                FatalError("%s(%d) => config ppm: too many arguments for '%s'.\n", 
                        file_name, file_line, args[0]);
            ppm_set_pkt_action(PPM_ACTION_SUSPEND);
            pktOpts++;
        }
        else if(!strcasecmp(args[0], "pkt-log"))
        {
            if( 1 != nargs )
                FatalError("%s(%d) => config ppm: too many arguments for '%s'.\n", 
                        file_name, file_line, args[0]);

            ppm_set_pkt_log(PPM_LOG_MESSAGE);
            pktOpts++;
        }       
        else if(!strcasecmp(args[0], "rule-log"))
        {
            int k;
          
            if( nargs == 1 )
                FatalError("%s(%d) => config ppm: insufficient %s args.\n", 
                    file_name, file_line, args[0]);
         
            for( k=1;k<nargs;k++)
            {
                if( strcasecmp(args[k],"alert")==0 )
                {
                    ppm_set_rule_log(PPM_LOG_ALERT);
                }
                else if( strcasecmp(args[k],"log")==0 )
                {
                    ppm_set_rule_log(PPM_LOG_MESSAGE);
                }
                else
                {
                    FatalError("%s(%d) => config ppm: Invalid %s arg '%s'.\n", 
                        file_name, file_line, args[0], args[k]);
                }
            }
            ruleOpts++;
        }       
        else if(!strcasecmp(args[0], "debug-pkts"))
        {
            if( 1 != nargs )
                FatalError("%s(%d) => config ppm: too many arguments for '%s'.\n", 
                       file_name, file_line, args[0]);
            ppm_set_debug_pkts(1);
            pktOpts++;
        }
#if 0
        else if(!strcasecmp(args[0], "debug-rules"))
        {
            if( 1 != nargs )
                FatalError("%s(%d) => config ppm: too many arguments for '%s'.\n", 
                       file_name, file_line, args[0]);
            ppm_set_debug_rules(1);
        }
#endif
        else
        {
            FatalError("%s (%d)=> '%s' is an invalid option to the 'config ppm:' configuration.\n", 
                      file_name, file_line, args[0]);
        }
    
        mSplitFree( &args, nargs );
    }
    if( pktOpts > 0 && !PPM_PKTS_ENABLED() )
    {
        FatalError(
            "%s(%d) => config ppm: packet options present but monitoring disabled.\n", 
           file_name, file_line
        );
    }
    if( ruleOpts > 0 && !PPM_RULES_ENABLED() )
    {
        FatalError(
            "%s(%d) => config ppm: rule options present but monitoring disabled.\n", 
           file_name, file_line
        );
    }
}
#endif
void ProcessEventQueue(char **args, int nargs)
{
    int iCtr;

    g_event_queue.process_all_events = pv.process_all_events;

    for(iCtr = 0; iCtr < nargs; iCtr++)
    {
        if(!strcasecmp("max_queue", args[iCtr]))
        {
            iCtr++;
            if(iCtr < nargs)
            {
                g_event_queue.max_events = atoi(args[iCtr]);
                if(g_event_queue.max_events <= 0)
                {
                    FatalError("%s(%d) => Invalid argument to 'max_queue'.  "
                               "Must be a positive integer.\n", file_name,
                               file_line);
                }
            }
            else
            {
                FatalError("%s(%d) => No argument to 'max_queue'.  "
                           "Argument must be a positive integer.\n",
                           file_name, file_line);
            }
        }
        else if(!strcasecmp("log", args[iCtr]))
        {
            iCtr++;
            if(iCtr < nargs)
            {
                g_event_queue.log_events = atoi(args[iCtr]);
                if(g_event_queue.log_events <= 0)
                {
                    FatalError("%s(%d) => Invalid argument to 'log'.  "
                               "Must be a positive integer.\n", file_name,
                               file_line);
                }
            }
            else
            {
                FatalError("%s(%d) => No argument to 'log'.  "
                           "Argument must be a positive integer.\n",
                           file_name, file_line);
            }
        }
        else if(!strcasecmp("order_events", args[iCtr]))
        {
            iCtr++;
            if(iCtr < nargs)
            {
                if(!strcasecmp("priority", args[iCtr]))
                {
                    g_event_queue.order = SNORT_EVENTQ_PRIORITY;
                }
                else if(!strcasecmp("content_length", args[iCtr]))
                {
                    g_event_queue.order = SNORT_EVENTQ_CONTENT_LEN;
                }
            }
            else
            {
                FatalError("%s(%d) => No argument to 'order_events'.  "
                           "Arguments may be either 'priority' or "
                           "content_length.\n",
                           file_name, file_line);
            }
        }
        else if(!strcasecmp("process_all_events", args[iCtr]))
        {
            g_event_queue.process_all_events = 1;
        }
        else
        {
            FatalError("%s(%d) => Invalid argument to 'event_queue'.  "
                       "To configure event_queue, the options 'max_queue', "
                       "'log', and 'order_events' must be configured.\n",
                       file_name, file_line);
        }
    }

    if( g_event_queue.max_events < g_event_queue.log_events )
    {
        g_event_queue.max_events = g_event_queue.log_events;
    }
    return;
}

void ProcessDetectionOptions( char ** args, int nargs )
{
    int i;
    
    for(i=0;i<nargs;i++)
    {
       if( !strcasecmp(args[i],"search-optimize") )
       {
           fpSetDetectSearchOpt(1);
       }
       else if( !strcasecmp(args[i],"search-method") )
       {
           i++;
           if( i < nargs ) 
           {
               if(fpSetDetectSearchMethod(args[i]))
               {
                   FatalError("%s (%d)=> Invalid argument to 'search-method': %s.\n",
                              file_name, file_line, args[i]);
               }
           }
           else
           {
               FatalError("%s (%d)=> Invalid argument to 'search-method': %s.\n",
                          file_name, file_line, args[i]);
           }
       }
       else if(!strcasecmp(args[i], "bleedover-warnings-enabled"))
       {
                fpDetectSetBleedOverWarnings( 1 );
       }
       else if(!strcasecmp(args[i], "bleedover-port-limit"))
       {
//#ifdef PORTLISTS
            i++;
            if(i < nargs)
            {
                int n = atoi(args[i]) ;
                fpDetectSetBleedOverPortLimit( n );
                LogMessage("Bleedover Port Limit : %d\n",n);
            }
            else FatalError("Missing port-count argument to 'bleedover_port_limit\n");
//#endif
       }
       else if(!strcasecmp(args[i], "enable-single-rule-group"))
       {
         fpDetectSetSingleRuleGroup(1);
         LogMessage("Using Single-Rule-Group Detection\n");
       }
       else if(!strcasecmp(args[i], "debug-print-nocontent-rule-tests"))
       {
         fpDetectSetDebugPrintNcRules(1);
       }
       else if(!strcasecmp(args[i], "debug-print-rule-group-build-details"))
       {
         fpDetectSetDebugPrintRuleGroupBuildDetails(1);
       }
       else if(!strcasecmp(args[i], "debug-print-rule-groups-uncompiled"))
       {
         fpDetectSetDebugPrintRuleGroupsUnCompiled(1);
       } 
       else if(!strcasecmp(args[i], "debug-print-rule-groups-compiled"))
       {
         fpDetectSetDebugPrintRuleGroupsCompiled(1);
       } 
       else if(!strcasecmp(args[i], "debug"))
       {
           fpSetDebugMode();
       }
       else if(!strcasecmp(args[i], "no_stream_inserts"))
       {
           fpSetStreamInsert();
       }
       else if(!strcasecmp(args[i], "max_queue_events"))
       {
           i++;
           if(i < nargs)
           {
               if(fpSetMaxQueueEvents(atoi(args[i])))
               {
                   FatalError("%s (%d)=> Invalid argument to "
                              "'max_queue_events'.  Argument must "
                              "be greater than 0.\n",
                              file_name, file_line);
               }
           }
       }
       else
       {
           FatalError("%s (%d)=> '%s' is an invalid option to the "
                      "'config detection:' configuration.\n", 
                      file_name, file_line, args[i]);
       }
    }
}

void ProcessResetMac(char ** args, int nargs)
{
#ifdef GIDS
#ifndef IPFW

    int i = 0;
    int num_macargs=nargs; 
    char **macargs;

    macargs = mSplit(args[0], ":", 6, &num_macargs, '\\');

    if(num_macargs != 6)
    {
    FatalError("%s (%d)=> '%s' is not a valid macaddress "
               "for layer2resets\n",
           file_name, file_line, args[0]);
    }

    for(i = 0; i < num_macargs; i++)
        pv.enet_src[i] = (u_int8_t) strtoul(macargs[i], NULL, 16);

#endif /* IPFW */
#endif /* GIDS */

    return;
} 

#ifdef PERF_PROFILING
void ParseProfileRules(char *args)
{
    char ** toks;
    int     num_toks = 0;
    char ** opts;
    int     num_opts = 0;
    int i;
    int     opt_filename = 0;
    char *endPtr;

    /* Initialize the defaults */
    pv.profile_rules_flag = -1;
    pv.profile_rules_sort = PROFILE_SORT_AVG_TICKS;

    toks = mSplit(args, ",", 20, &num_toks, 0);

    if (num_toks > 3)
    {
        FatalError("profile_rules speciified with invalid options (%s)\n", args);
    }

    for (i=0;i<num_toks;i++)
    {
        opts = mSplit(toks[i], " ", 3, &num_opts, 0);
        if (num_opts > 0)
        {
            opt_filename = !strcasecmp(opts[0], "filename");
        }
        if (((!opt_filename)&&(num_opts != 2))||(opt_filename&&((num_opts > 3)||(num_opts < 2))))
        {
            FatalError("profile_rules has an invalid option (%s)\n", toks[i]);
        }

        if (!strcasecmp(opts[0], "print"))
        {
            if (!strcasecmp(opts[1], "all"))
            {
                pv.profile_rules_flag = -1;
            }
            else
            {
                pv.profile_rules_flag = strtol(opts[1], &endPtr, 10);
            }
        }
        else if (!strcasecmp(opts[0], "sort"))
        {
            if (!strcasecmp(opts[1], "checks"))
            {
                pv.profile_rules_sort = PROFILE_SORT_CHECKS;
            }
            else if (!strcasecmp(opts[1], "matches"))
            {
                pv.profile_rules_sort = PROFILE_SORT_MATCHES;
            }
            else if (!strcasecmp(opts[1], "nomatches"))
            {
                pv.profile_rules_sort = PROFILE_SORT_NOMATCHES;
            }
            else if (!strcasecmp(opts[1], "avg_ticks"))
            {
                pv.profile_rules_sort = PROFILE_SORT_AVG_TICKS;
            }
            else if (!strcasecmp(opts[1], "avg_ticks_per_match"))
            {
                pv.profile_rules_sort = PROFILE_SORT_AVG_TICKS_PER_MATCH;
            }
            else if (!strcasecmp(opts[1], "avg_ticks_per_nomatch"))
            {
                pv.profile_rules_sort = PROFILE_SORT_AVG_TICKS_PER_NOMATCH;
            }
            else if (!strcasecmp(opts[1], "total_ticks"))
            {
                pv.profile_rules_sort = PROFILE_SORT_TOTAL_TICKS;
            }
            else
            {
                FatalError("profile_rules has an invalid sort option (%s)\n", toks[i]);
            }
        }
        else if (!strcasecmp(opts[0], "filename"))
        {
            pv.profile_rules_filename = ProcessFileOption(opts[1]);
            if(opts[2]&&(!strcasecmp(opts[2], "append")))
            {
                pv.profile_rules_append = 1;   
            } else {
                pv.profile_rules_append = 0;
            }
        }
        else
        {
            FatalError("profile_rules has an invalid option (%s)\n", toks[i]);
        }

        mSplitFree(&opts, num_opts);
    }
    mSplitFree(&toks, num_toks );
}

void ParseProfilePreprocs(char *args)
{
    char ** toks;
    int     num_toks = 0;
    char ** opts;
    int     num_opts = 0;
    int     opt_filename = 0;
    int i;
    char *endPtr;

    /* Initialize the defaults */
    pv.profile_preprocs_flag = -1;
    pv.profile_preprocs_sort = PROFILE_SORT_AVG_TICKS;

    toks = mSplit(args, ",", 20, &num_toks, 0);

    if (num_toks > 3)
    {
        FatalError("profile_preprocs speciified with invalid options (%s)\n", args);
    }

    for (i=0;i<num_toks;i++)
    {
        opts = mSplit(toks[i], " ", 3, &num_opts, 0);
        if (num_opts > 0)
        {
            opt_filename = !strcasecmp(opts[0], "filename");
        }
        if (((!opt_filename)&&(num_opts != 2))||(opt_filename&&((num_opts > 3)||(num_opts < 2))))
        {
            FatalError("profile_preprocs has an invalid option (%s)\n", toks[i]);
        }

        if (!strcasecmp(opts[0], "print"))
        {
            if (!strcasecmp(opts[1], "all"))
            {
                pv.profile_preprocs_flag = -1;
            }
            else
            {
                pv.profile_preprocs_flag = strtol(opts[1], &endPtr, 10);
            }
        }
        else if (!strcasecmp(opts[0], "sort"))
        {
            if (!strcasecmp(opts[1], "checks"))
            {
                pv.profile_preprocs_sort = PROFILE_SORT_CHECKS;
            }
            else if (!strcasecmp(opts[1], "avg_ticks"))
            {
                pv.profile_preprocs_sort = PROFILE_SORT_AVG_TICKS;
            }
            else if (!strcasecmp(opts[1], "total_ticks"))
            {
                pv.profile_preprocs_sort = PROFILE_SORT_TOTAL_TICKS;
            }
            else
            {
                FatalError("profile_preprocs has an invalid sort option (%s)\n", toks[i]);
            }
        }
        else if (!strcasecmp(opts[0], "filename"))
        {
            pv.profile_preprocs_filename = ProcessFileOption(opts[1]);
            if(opts[2]&&(!strcasecmp(opts[2], "append")))
            {
                pv.profile_preprocs_append = 1;   
            } else {
                pv.profile_preprocs_append = 0;
            }
        }
        else
        {
            FatalError("profile_preprocs has an invalid option (%s)\n", toks[i]);
        }

        mSplitFree(&opts, num_opts);
    }
    mSplitFree(&toks, num_toks );
}
#endif

void ParseConfig(char *rule)
{
    char ** toks;
    char **rule_toks = NULL;
    char **config_decl = NULL;
    char *args = NULL;
    char *config;
    int num_rule_toks = 0, num_config_decl_toks = 0, num_toks=0;

    rule_toks = mSplit(rule, ":", 2, &num_rule_toks, 0);
    if(num_rule_toks > 1)
    {
        args = rule_toks[1];
    }

    config_decl = mSplit(rule_toks[0], " ", 2, &num_config_decl_toks, '\\');
    if(num_config_decl_toks != 2)
    {
        FatalError("unable to parse config: %s\n", rule);
    }

    config = config_decl[1];

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Config: %s\n", config););
    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Args: %s\n", args););
    
    if(!strcasecmp(config, "order"))
    {
        if(!pv.rules_order_flag)
            OrderRuleLists(args);
        else
            LogMessage("Commandline option overiding rule file config\n");

        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
    
        return;
    }
    else if(!strcasecmp(config, "nopcre"))
    {
        g_nopcre=1;
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "alertfile"))
    {
        toks = mSplit(args, " ", 1, &num_toks, 0);

        ProcessAlertFileOption(toks[0]);
    
        mSplitFree( &toks, num_toks );
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "classification"))
    {
        ParseClassificationConfig(args);
    
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
#ifdef PPM_MGR
    else if(!strcasecmp(config, "ppm"))
    {   /* packet processing monitor */
        toks = mSplit(args, ",",40, &num_toks, 0);
        ProcessPPMOptions(toks,num_toks);
        mSplitFree( &toks, num_toks );
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
#endif
    else if(!strcasecmp(config, "detection"))
    {
        toks = mSplit(args, ", ",20, &num_toks, 0);
        ProcessDetectionOptions(toks,num_toks);
        mSplitFree( &toks, num_toks );
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "flowbits_size"))
    {
        toks = mSplit(args, ", ",20, &num_toks, 0);
        ProcessFlowbitsSize(toks, num_toks);
        mSplitFree( &toks, num_toks );
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "event_queue"))
    {
        toks = mSplit(args, ", ", 20, &num_toks, 0);
        ProcessEventQueue(toks, num_toks);
        mSplitFree( &toks, num_toks );
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "layer2resets"))
    {   
        if(args)
        {
            toks = mSplit(args, " ", 1, &num_toks, 0);
            ProcessResetMac(toks, num_toks);

            mSplitFree( &toks, num_toks );
        }

#ifdef GIDS
#ifndef IPFW

        pv.layer2_resets = 1;

#endif
#endif

        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);

        return;
        
    }
    else if(!strcasecmp(config, "asn1"))
    {
        toks = mSplit(args, ", ", 20, &num_toks, 0);

        if(num_toks > 0)
        {
            if(asn1_init_mem(atoi(toks[0])))
            {
                FatalError("%s(%d) => Invalid argument to 'asn1' "
                           "configuration.  Must be a positive integer.\n", 
                           file_name, file_line);
            }
        }
        mSplitFree( &toks, num_toks );
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "dump_chars_only"))
    {
        /* dump the application layer as text only */
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Character payload dump set\n"););
        pv.char_data_flag = 1;
    
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "dump_payload"))
    {
        /* dump the application layer */
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Payload dump set\n"););
        pv.data_flag = 1;
    
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
#ifdef INLINE_FAILOPEN
    else if (!strcasecmp(config, "disable_inline_init_failopen"))
    {
        /* disable the fail open during initialization */
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Inline Init Failopen disabled\n"););

        pv.inline_failopen_disabled_flag = 1;
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
#endif
    else if(!strcasecmp(config, "disable_decode_alerts"))
    {
        /* dump the application layer */
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "disabling the decoder alerts\n"););
        pv.decoder_flags.decode_alerts = 0;
    
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "enable_decode_oversized_alerts"))
    {
        /* dump the application layer */
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Enabling the decoder oversized packet alerts\n"););
        pv.decoder_flags.oversized_alert = 1;
    
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "enable_decode_oversized_drops"))
    {
        /* dump the application layer */
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Enabling the drop of decoder oversized packets\n"););
        pv.decoder_flags.oversized_drop = 1;
    
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }

    else if(!strcasecmp(config, "enable_decode_drops"))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "disabling the drop of decoder alerts\n"););
        pv.decoder_flags.drop_alerts = 1;
    
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    /* OBSOLETE -- default is disabled */
    else if(!strcasecmp(config, "disable_decode_drops"))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "disabling the drop of decoder alerts\n"););
        pv.decoder_flags.drop_alerts = 0;
    
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "disable_tcpopt_experimental_alerts"))
    {
        /* dump the application layer */
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "disabling the tcpopt experimental alerts\n"););
        pv.decoder_flags.tcpopt_experiment = 0;
    
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "enable_tcpopt_experimental_drops"))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "disabling the drop of tcpopt exprimental alerts\n"););
        pv.decoder_flags.drop_tcpopt_experiment = 1;
   
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }              
    /* OBSOLETE -- default is disabled */
    else if(!strcasecmp(config, "disable_tcpopt_experimental_drops"))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "disabling the drop of tcpopt exprimental alerts\n"););
        pv.decoder_flags.drop_tcpopt_experiment = 0;
   
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }              
    else if(!strcasecmp(config, "disable_tcpopt_obsolete_alerts"))
    {
        /* dump the application layer */
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "disabling the tcpopt obsolete alerts\n"););
        pv.decoder_flags.tcpopt_obsolete = 0;
    
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "enable_tcpopt_obsolete_drops"))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "disabling the drop of tcpopt obsolete alerts\n"););
        pv.decoder_flags.drop_tcpopt_obsolete = 1;
   
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }              
    /* OBSOLETE -- default is disabled */
    else if(!strcasecmp(config, "disable_tcpopt_obsolete_drops"))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "disabling the drop of tcpopt obsolete alerts\n"););
        pv.decoder_flags.drop_tcpopt_obsolete = 0;
   
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }              
    else if(!strcasecmp(config, "disable_ttcp_alerts") ||
            !strcasecmp(config, "disable_tcpopt_ttcp_alerts"))
    {
        /* dump the application layer */
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "disabling the ttcp alerts\n"););
        pv.decoder_flags.tcpopt_ttcp = 0;
    
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "enable_ttcp_drops") ||
            !strcasecmp(config, "enable_tcpopt_ttcp_drops"))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "disabling the drop of ttcp alerts\n"););
        pv.decoder_flags.drop_tcpopt_ttcp = 1;
   
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }              
    /* OBSOLETE -- default is disabled */
    else if(!strcasecmp(config, "disable_ttcp_drops"))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "disabling the drop of ttcp alerts\n"););
        pv.decoder_flags.drop_tcpopt_ttcp = 0;
   
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }              

    else if(!strcasecmp(config, "disable_tcpopt_alerts"))
    {
        /* dump the application layer */
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "disabling the all the other tcpopt alerts\n"););
        pv.decoder_flags.tcpopt_decode = 0;
    
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "enable_tcpopt_drops"))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "disabling the drop of all other tcpopt alerts\n"););
        pv.decoder_flags.drop_tcpopt_decode = 1;
   
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }              
    /* OBSOLETE -- default is disabled */
    else if(!strcasecmp(config, "disable_tcpopt_drops"))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "disabling the drop of all other tcpopt alerts\n"););
        pv.decoder_flags.drop_tcpopt_decode = 0;
   
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }              
    else if(!strcasecmp(config, "disable_ipopt_alerts"))
    {
        /* dump the application layer */
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "disabling the all the ipopt alerts\n"););
        pv.decoder_flags.ipopt_decode = 0;
    
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "enable_ipopt_drops"))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "disabling the drop of all the ipopt alerts\n"););
        pv.decoder_flags.drop_ipopt_decode = 1;
   
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }              
    /* OBSOLETE -- default is disabled */
    else if(!strcasecmp(config, "disable_ipopt_drops"))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "disabling the drop of all the ipopt alerts\n"););
        pv.decoder_flags.drop_ipopt_decode = 0;
   
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }              
    else if(!strcasecmp(config, "decode_data_link"))
    {
        /* dump the data link layer as text only */
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Decode DLL set\n"););
        pv.show2hdr_flag = 1;
    
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "bpf_file"))
    {
        /* Read BPF filters from a file */
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "BPF file set\n"););
        /* suck 'em in */
        pv.pcap_cmd = read_infile(args);
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "set_gid"))
    {
#ifdef WIN32
        FatalError(" Setting the group id is not supported in the WIN32 port of snort!\n");
#else
        groupname = (char *)SnortAlloc((strlen(args) + 1) * sizeof(char));
        bcopy(args, groupname, strlen(args));

        if((groupid = atoi(groupname)) == 0)
        {
            gr = getgrnam(groupname);

            if(gr == NULL)
            {
                ErrorMessage("%s(%d) => Group \"%s\" unknown\n", 
                             file_name, file_line, groupname);
            }

            groupid = gr->gr_gid;
        }

        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);

        return;
#endif
    }
    else if(!strcasecmp(config, "daemon"))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Daemon mode flag set\n"););
        pv.daemon_flag = 1;
        flow_set_daemon();
        pv.quiet_flag = 1;
    
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;

    }
    else if(!strcasecmp(config, "reference_net"))
    {
        GenHomenet(args);
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "threshold"))
    {
        ProcessThresholdOptions(args);
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "interface"))
    {
        pv.interface = (char *)SnortAlloc((strlen(args) + 1) * sizeof(char));
        strlcpy(pv.interface, args, strlen(args)+1);
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Interface = %s\n", 
                    PRINT_INTERFACE(pv.interface)););

        if(!pv.readmode_flag)
        {
            if(pd != NULL)
            {
                pcap_close(pd);
                pd = NULL;
            }

            DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Opening interface: %s\n", 
                        PRINT_INTERFACE(pv.interface)););
            /* open up our libpcap packet capture interface */
            OpenPcap();
        }
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "alert_with_interface_name"))
    {
        pv.alert_interface_flag = 1;
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "logdir"))
    {
        LogMessage("Found logdir config directive (%s)\n", args);
        pv.log_dir = SnortStrdup(args);
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Log directory = %s\n", 
                    pv.log_dir););
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
#ifdef NOT_UNTIL_WE_DAEMONIZE_AFTER_READING_CONFFILE
    else if(!strcasecmp(config, "pidpath"))
    {
        LogMessage("Found pidpath config directive (%s)\n", args);
        strncpy(pv.pid_path,args,STD_BUF);
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Pid Path directory = %s\n", 
                    pv.pid_path););
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
#endif
    else if(!strcasecmp(config, "chroot"))
    {
        LogMessage("Found chroot config directive (%s)\n", args);
        pv.chroot_dir = SnortStrdup(args);
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Chroot directory = %s\n",
                    pv.chroot_dir););
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "umask"))
    {
        char *p;
        long val = 0;
        int umaskchange = 0;
        int defumask = 0;

        val = strtol(args, &p, 8);
        if (*p != '\0' || val < 0 || (val & ~FILEACCESSBITS))
        {
            FatalError("bad umask %s\n", args);
        }
        else
        {
            defumask = val;
            umaskchange = 1;
        }

        /* if the umask arg happened, set umask */
        if (!umaskchange)
        {
            umask(077);           /* set default to be sane */
        }
        else
        {
            umask(defumask);
        }
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "pkt_count"))
    {
        pv.pkt_cnt = atoi(args);
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Exiting after %d packets\n", pv.pkt_cnt););
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "nolog"))
    {
        pv.log_mode = LOG_NONE;
        pv.log_cmd_override = 1;    /* XXX this is a funky way to do things */
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "obfuscate"))
    {
        pv.obfuscation_flag = 1;
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "no_promisc"))
    {
        pv.promisc_flag = 0;
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Promiscuous mode disabled!\n"););
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "snaplen"))
    {
        pv.pkt_snaplen = atoi(args);
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Snaplength of Packets set to: %d\n", 
                    pv.pkt_snaplen););
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "quiet"))
    {
        pv.quiet_flag = 1;
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "read_bin_file"))
    {
        if(args) 
        {
            strlcpy(pv.readfile, args, STD_BUF);
            pv.readmode_flag = 1;
            DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Opening file: %s\n", pv.readfile););

            if(pd != NULL)
            {
                pcap_close(pd);
                pd = NULL;
            }

            /* open the packet file for readback */
            OpenPcap();
        }
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "checksum_mode"))
    {
        int num_atoks,i;
        char **atoks;

        atoks  = mSplit(args, " ",10 , &num_atoks, 0);
    
        for(i=0;i<num_atoks;i++)
        {
            args=atoks[i];

            if(args == NULL || !strcasecmp(args, "all"))
            {
                pv.checksums_mode = DO_IP_CHECKSUMS | DO_TCP_CHECKSUMS |
                    DO_UDP_CHECKSUMS | DO_ICMP_CHECKSUMS;
            }
            else if(!strcasecmp(args, "none"))
            {
                pv.checksums_mode = 0;
            }
            else if(!strcasecmp(args, "noip")) 
            {
                pv.checksums_mode &= ~DO_IP_CHECKSUMS;
            }
            else if(!strcasecmp(args, "notcp"))
            {
                pv.checksums_mode &= ~DO_TCP_CHECKSUMS;
            }
            else if(!strcasecmp(args, "noudp"))
            {
                pv.checksums_mode &= ~DO_UDP_CHECKSUMS;
            }
            else if(!strcasecmp(args, "noicmp"))
            {
                pv.checksums_mode &= ~DO_ICMP_CHECKSUMS;
            }
            else if(!strcasecmp(args, "ip")) 
            {
                pv.checksums_mode |= DO_IP_CHECKSUMS;
            }
            else if(!strcasecmp(args, "tcp"))
            {
                pv.checksums_mode |= DO_TCP_CHECKSUMS;
            }
            else if(!strcasecmp(args, "udp"))
            {
                pv.checksums_mode |= DO_UDP_CHECKSUMS;
            }
            else if(!strcasecmp(args, "icmp"))
            {
                pv.checksums_mode |= DO_ICMP_CHECKSUMS;
            }
        }
    
        mSplitFree(&atoks,num_atoks);
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "checksum_drop"))
    {
        int num_atoks,i;
        char **atoks;

        atoks  = mSplit(args, " ",10 , &num_atoks, 0);
    
        for(i=0;i<num_atoks;i++)
        {
            args=atoks[i];

            if(args == NULL || !strcasecmp(args, "all"))
            {
                pv.checksums_drop = DO_IP_CHECKSUMS | DO_TCP_CHECKSUMS |
                    DO_UDP_CHECKSUMS | DO_ICMP_CHECKSUMS;
            }
            else if(!strcasecmp(args, "none"))
            {
                pv.checksums_drop = 0;
            }
            else if(!strcasecmp(args, "noip")) 
            {
                pv.checksums_drop &= ~DO_IP_CHECKSUMS;
            }
            else if(!strcasecmp(args, "notcp"))
            {
                pv.checksums_drop &= ~DO_TCP_CHECKSUMS;
            }
            else if(!strcasecmp(args, "noudp"))
            {
                pv.checksums_drop &= ~DO_UDP_CHECKSUMS;
            }
            else if(!strcasecmp(args, "noicmp"))
            {
                pv.checksums_drop &= ~DO_ICMP_CHECKSUMS;
            }
            else if(!strcasecmp(args, "ip")) 
            {
                pv.checksums_drop |= DO_IP_CHECKSUMS;
            }
            else if(!strcasecmp(args, "tcp"))
            {
                pv.checksums_drop |= DO_TCP_CHECKSUMS;
            }
            else if(!strcasecmp(args, "udp"))
            {
                pv.checksums_drop |= DO_UDP_CHECKSUMS;
            }
            else if(!strcasecmp(args, "icmp"))
            {
                pv.checksums_drop |= DO_ICMP_CHECKSUMS;
            }
        }
    
        mSplitFree(&atoks,num_atoks);
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "set_uid"))
    {
#ifdef WIN32
        FatalError("Setting the user id is not supported in the WIN32 port of snort!\n");
#else
        if(args == NULL)
        {
            FatalError("Setting the user id requires an argument.\n");
        }
        
        username = (char *)SnortAlloc((strlen(args) + 1) * sizeof(char));
        bcopy(args, username, strlen(args));

        if((userid = atoi(username)) == 0)
        {
            pw = getpwnam(username);
            if(pw == NULL)
                FatalError("User \"%s\" unknown\n", username);

            userid = pw->pw_uid;
        }
        else
        {
            pw = getpwuid(userid);
            if(pw == NULL)
                FatalError(
                        "Can not obtain username for uid: %lu\n",
                        (u_long) userid);
        }

        if(groupname == NULL)
        {
            char name[256];

            SnortSnprintf(name, 255, "%lu", (u_long) pw->pw_gid);

            groupname = (char *)SnortAlloc((strlen(name) + 1) * sizeof(char));

            groupid = pw->pw_gid;
        }

        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "UserID: %lu GroupID: %lu\n",
                    (unsigned long) userid, (unsigned long) groupid););

        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);

        return;
#endif
    }
    else if(!strcasecmp(config, "utc"))
    {
        pv.use_utc = 1;
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "verbose"))
    {
        pv.verbose_flag = 1;
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Verbose Flag active\n"););
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "dump_payload_verbose"))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, 
                    "Verbose packet bytecode dumps enabled\n"););

        pv.verbose_bytedump_flag = 1;
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "show_year"))
    {
        pv.include_year = 1;
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Enabled year in timestamp\n"););
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "stateful")) /* this one's for Johnny! */
    {
        pv.assurance_mode = ASSURE_EST;
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "min_ttl"))
    {
        if(args)
        {
            int min_ttl_value = 0;

            if (!isdigit((int)args[0]))
            {
                FatalError("config min_ttl requires a positive number argument\n");
            }

            min_ttl_value = atoi(args);

            if (min_ttl_value < 0 || min_ttl_value > 255)
            {
                FatalError("config min_ttl argument must be between 0 and 255 inclusive\n");
            }

            pv.min_ttl = (u_int8_t)min_ttl_value;
        }
        else 
        {
            FatalError("config min_ttl requires an argument\n");
        }
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "reference"))
    {
        if(args)
        {
            ParseReferenceSystemConfig(args);
        }
        else
        {
            ErrorMessage("%s(%d) => Reference config without "
                         "arguments\n", file_name, file_line);
        }
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if (!strcasecmp(config, "ignore_ports"))
    {
        LogMessage("Found ignore_ports config directive (%s)\n", args);
        ParsePortList(args);        
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if(!strcasecmp(config, "default_rule_state"))
    {
        LogMessage("Found rule_state config directive (%s)\n", args);
        if (args)
        {
            if (!strcasecmp(args, "disabled"))
                pv.default_rule_state = RULE_STATE_DISABLED;
            else
                pv.default_rule_state = RULE_STATE_ENABLED;
        }
        else
        {
                pv.default_rule_state = RULE_STATE_ENABLED;
        }
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
#ifdef PERF_PROFILING
    else if (!strcasecmp(config, "profile_rules"))
    {
        LogMessage("Found profile_rules config directive (%s)\n", args);
        ParseProfileRules(args);        
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if (!strcasecmp(config, "profile_preprocs"))
    {
        LogMessage("Found profile_preprocs config directive (%s)\n", args);
        ParseProfilePreprocs(args);        
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
#endif
    else if(!strcasecmp(config, "tagged_packet_limit"))
    {
        pv.tagged_packet_limit = atoi(args);
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
#ifdef TARGET_BASED
    else if(!strcasecmp(config, "max_attribute_hosts"))
    {
        u_int32_t val = 0;
        char *endp;
        val = strtoul(args, &endp, 10);
        if (args == endp || *endp || (val == 0))
        {
            FatalError("%s(%d) => max_attribute_hosts: Invalid number of "
                       "hosts '%s', must be unsigned positive integer value.\n",
                       file_name, file_line, args);
        }
        if ((val > MAX_MAX_ATTRIBUTE_HOSTS) || (val < MIN_MAX_ATTRIBUTE_HOSTS))
        {
            FatalError("%s(%d) => max_atttribute_hosts: Invalid number of "
                       "hosts %s'.  Must be between %d and %d\n",
                       file_name, file_line, args,
                       MIN_MAX_ATTRIBUTE_HOSTS, MAX_MAX_ATTRIBUTE_HOSTS);
        }
        pv.max_attribute_hosts = val;
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
#endif
#if defined(ENABLE_RESPONSE2) && !defined(ENABLE_RESPONSE)
    else if (!strcasecmp(config, "flexresp2_interface"))
    {
        if (args)
        {
#ifdef WIN32
            char *devicet = NULL;
            int adaplen = atoi(args);
            char errorbuf[PCAP_ERRBUF_SIZE];

            if (adaplen > 0)
            {
                devicet = pcap_lookupdev(errorbuf);
                if (devicet == NULL)
                    FatalError("%s(%d) => flexresp2_interface failed in "
                            "pcap_lookupdev(): %s.\n", file_name, file_line,
                            strerror(errorbuf));

                pv.respond2_ethdev = GetAdapterFromList(devicet, adaplen);
                if (pv.respond2_ethdev == NULL)
                    FatalError("%s(%d) => flexresp2_interface: Invalid "
                            "interface '%d'.\n", file_name, file_line,
                            atoi(adaplen));

                pv.respond2_link = 1;
                DEBUG_WRAP(
                        DebugMessage(DEBUG_INIT,
                                "sp_respond2: link-layer responses: ENABLED\n");
                        DebugMessage(DEBUG_INIT,
                                "sp_respond2: link-layer device: %s\n",
                                pv.respond2_ethdev););
                return;
            }
            else
#endif /* WIN32 */
            {
                pv.respond2_ethdev = (char *)SnortAlloc((strlen(args) + 1) * sizeof(char));
                strlcpy(pv.respond2_ethdev, args, strlen(args) + 1);
                pv.respond2_link = 1;
                DEBUG_WRAP(
                        DebugMessage(DEBUG_INIT,
                                "sp_respond2: link-layer responses: ENABLED\n");
                        DebugMessage(DEBUG_INIT,
                                "sp_respond2: link-layer device: %s\n",
                                pv.respond2_ethdev););
            }
            return;
        }
        else 
        {
            FatalError("%s(%d) => flexresp2_interface config without "
                         "arguments\n", file_name, file_line);
        }
    }
    else if (!strcasecmp(config, "flexresp2_attempts"))
    {
        char *endp;
        u_long val = 0;

        if (args)
        {
            val = strtoul(args, &endp, 0);
            if (args == endp || *endp)
                FatalError("%s(%d) => flexresp2_attempts: Invalid number of "
                        "response attempts '%s'.\n", file_name, file_line, args);

            if (val < 21)
            {
                pv.respond2_attempts = (u_int8_t)val;
                DEBUG_WRAP(DebugMessage(DEBUG_INIT, "sp_respond2: "
                            "response attempts: %u\n", pv.respond2_attempts););
                return;
            }
            else
            {
                ErrorMessage("%s(%d) => flexresp2_attempts: Maximum "
                        "number of response attempts is 20.\n", file_name,
                        file_line);
                pv.respond2_attempts = 20;
                DEBUG_WRAP(DebugMessage(DEBUG_INIT, "sp_respond2: response "
                            "attempts: %u\n", pv.respond2_attempts););
                return;
            }
        }
        else 
        {
            FatalError("%s(%d) => flexresp2_attempts config without "
                         "arguments\n", file_name, file_line);
        }
    }
    else if (!strcasecmp(config, "flexresp2_memcap"))
    {
        char *endp;
        long val = 0;

        if (args)
        {
            val = strtol(args, &endp, 0);
            if (args == endp || *endp)
                FatalError("%s(%d) => flexresp2_memcap: Invalid memcap '%s'.\n", 
                        file_name, file_line, args);

                DEBUG_WRAP(DebugMessage(DEBUG_INIT, "sp_respond2: memcap: "
                            "%d\n", pv.respond2_memcap););
                return;
        }
        else
        {
            FatalError("%s(%d) => flexresp2_memcap config without "
                         "arguments\n", file_name, file_line);
        }
    }
    else if (!strcasecmp(config, "flexresp2_rows"))
    {
        char *endp;
        long val = 0;

        if (args)
        {
            val = strtol(args, &endp, 0);
            if (args == endp || *endp)
                FatalError("%s(%d) => flexresp2_memcap: Invalid rows '%s'.\n", 
                        file_name, file_line, args);

                DEBUG_WRAP(DebugMessage(DEBUG_INIT, "sp_respond2: rows: %d\n", 
                            pv.respond2_rows););
                return;
        }
        else
        {
            FatalError("%s(%d) => flexresp2_rows config without "
                         "arguments\n", file_name, file_line);
        }
    }
#endif /* defined(ENABLE_RESPONSE2) && !defined(ENABLE_RESPONSE) */
    else if (!strcasecmp(config, "ipv6_frag"))
    {
        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"IPv6 Rule Option\n"););
        ParseIPv6Options(args);
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
    else if (!strcasecmp(config, "pcre_match_limit"))
    {
        char *endp;
        long val = 0;

        if (args)
        {
            val = strtol(args, &endp, 0);
            if ((args == endp) || *endp || (val < -1))
                FatalError("%s(%d) => pcre_match_limit: Invalid value '%s'.\n", 
                            file_name, file_line, args);

            pv.pcre_match_limit = val;

            DEBUG_WRAP(DebugMessage(DEBUG_INIT, "pcre_match_limit: %d\n",
                            pv.pcre_match_limit););
            return;
        }
        else
        {
            FatalError("%s(%d) => pcre_match_limit config without "
                        "arguments\n", file_name, file_line);
        }
    }
    else if (!strcasecmp(config, "pcre_match_limit_recursion"))
    {
        char *endp;
        long val = 0;

        if (args)
        {
            val = strtol(args, &endp, 0);
            if ((args == endp) || *endp || (val < -1))
                FatalError("%s(%d) => pcre_match_limit_recursion: Invalid value '%s'.\n", 
                            file_name, file_line, args);

            pv.pcre_match_limit_recursion = val;

            DEBUG_WRAP(DebugMessage(DEBUG_INIT, "pcre_match_limit_recursion: %d\n",
                            pv.pcre_match_limit_recursion););
            return;
        }
        else
        {
            FatalError("%s(%d) => pcre_match_limit config without "
                        "arguments\n", file_name, file_line);
        }
    }
#ifdef PREPROCESSOR_AND_DECODER_RULE_EVENTS
    else if(!strcasecmp(config, "autogenerate_preprocessor_decoder_rules"))
    {
        pv.generate_preprocessor_decoder_otn = 1;
        DEBUG_WRAP(DebugMessage(DEBUG_INIT, "Autogenerating Preprocessor and Decoder OTNs\n"););
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
#endif
#ifdef TIMESTATS
    else if (!strcasecmp(config, "timestats_interval"))
    {
        char *endp;
        u_int32_t val = 0;

        if (args)
        {
            val = strtoul(args, &endp, 0);
            if (args == endp || *endp)
            {
                FatalError("%s(%d) => timestats_interval: Invalid argument '%s'.\n", 
                        file_name, file_line, args);
            }

            pv.timestats_interval = val;
            /* Reset the alarm to use the new time interval */
            alarm(pv.timestats_interval);
            DEBUG_WRAP(DebugMessage(DEBUG_INIT, "timetstats_interval: "
                            "%d\n", pv.timestats_interval););
        }
        else
        {
            FatalError("%s(%d) => timestats_interval config without "
                         "arguments\n", file_name, file_line);
        }
         
        mSplitFree(&rule_toks,num_rule_toks);
        mSplitFree(&config_decl,num_config_decl_toks);
        return;
    }
#endif
#ifdef MPLS
    else if (!strcasecmp(config, "enable_mpls_multicast"))
    {
       pv.mpls_multicast = 1;
       return;
    }
    else if (!strcasecmp(config, "enable_mpls_overlapping_ip"))
    {
        pv.overlapping_IP = 1;
        return;
    }
    else if (!strcasecmp(config, "max_mpls_labelchain_len"))
    {
        char *endp;
        long val = 0;

        if (args)
        {
            val = strtol(args, &endp, 0);
            if ((args == endp) || *endp || (val < -1))
                val = DEFAULT_LABELCHAIN_LENGTH;
        } 
        else 
        {
            val = DEFAULT_LABELCHAIN_LENGTH;	
        }
        pv.mpls_stack_depth = val;
        return;
    }
    else if (!strcasecmp(config, "mpls_payload_type"))
    {
        if(args)
        {
            if(!strcasecmp(args, "ipv4"))
            {
                pv.mpls_payload_type = MPLS_PAYLOADTYPE_IPV4;
            } 
            else 
            {
                if(!strcasecmp(args, "ipv6"))
                {
                    pv.mpls_payload_type = MPLS_PAYLOADTYPE_IPV6;
                } 
                else 
                {
                    if(!strcasecmp(args, "ethernet"))
                    {
                        pv.mpls_payload_type = MPLS_PAYLOADTYPE_ETHERNET;
                    } 
                    else 
                    {
                        FatalError("%s(%d) => non supported mpls payload type\n", 
                            file_name, file_line);
                    }
                }
            }
        } 
        else 
        {
            pv.mpls_payload_type = DEFAULT_MPLS_PAYLOADTYPE;
        }
        return;
    }
#endif
    FatalError("Unknown config directive: %s\n", rule);
    

    return;
}

/****************************************************************************
 *
 * Purpose: Check that special rules have an OTN.
 *          TODO: Free up memory associated with disabled rules.
 *
 * Arguments: list => Pointer for a list of rules
 *
 * Returns: void function
 *
 * Notes: man - modified to used .shared flag in otn sigInfo instead of specialGID
 *        sas - removed specialGID
 * 
 *****************************************************************************/
int CheckRuleStates(RuleTreeNode **list)
{
    RuleTreeNode *rtn;
    OptTreeNode *otnPrev;
    OptTreeNode *otn;
    int oneErr = 0;

    if (!list || !(*list))
        return 0;

    for (rtn = *list; rtn != NULL; rtn = rtn->right)
    {
        otn = rtn->down;
        otnPrev = NULL;
        while (otn)
        {
            if ( otn->sigInfo.shared )
            {
                if (otn->ds_list[PLUGIN_DYNAMIC] == NULL)
                {
                    LogMessage("Encoded Rule Plugin SID: %d, GID: %d not registered properly.  Disabling this rule.\n",
                            otn->sigInfo.id, otn->sigInfo.generator);
                    oneErr = 1;

                    otn->rule_state = RULE_STATE_DISABLED;
                }
            }
            if (otn->rule_state != RULE_STATE_ENABLED)
            {
                /* XXX: Future, free it and clean up */
#if 0
                if (otnPrev)
                {
                    otnPrev->next = otn->next;
                    free(otn);
                    otn = otnPrev->next;
                }
                else
                {
                    rtn->down = otn->next;
                    free(otn);
                    otn = rtn->down;
                }
                /* Removed a node.  */
                continue;
#endif
            }
            otn = otn->next;
        }
    }
    return oneErr;
}

/****************************************************************************
 *
 * Purpose: Adjust the information for a given rule
 *          relative to the Rule State list
 *
 * Arguments: None
 *
 * Returns: void function
 *
 * Notes:  specialGID is depracated, uses sigInfo.shared flag
 * 
 *****************************************************************************/
void SetRuleStates()
{
    RuleState *ruleState = pv.ruleStateList;
    OptTreeNode *otn = NULL;
    RuleListNode *rule;
    int oneErr = 0, err;

    /* First, cycle through the rule state list and update the
     * rule state for each one we find.
     */
    while (ruleState)
    {
        /* Lookup the OTN by ruleState->sid, ruleState->gid */
        otn = otn_lookup(ruleState->gid, ruleState->sid);
        if (!otn)
        {
            FatalError("Rule state specified for invalid SID: %d GID: %d\n",
                    ruleState->sid, ruleState->gid);
        }

        otn->rule_state = ruleState->state;

        /* Set the action -- err "rule type" */
        otn->type = ruleState->action;

        ruleState = ruleState->next;
    }

    /* Next, cycle through all rules.
     * For all RTNs that are disabled, pull them out of the list.
     * If an OTN matching the special GID doesn't have any OTN info, fatal.
     */
    for (rule=RuleLists; rule; rule=rule->next)
    {
        if(!rule->RuleList)
            continue;

        /* First Check TCP */
        err = CheckRuleStates(&(rule->RuleList->TcpList));
        if (err)
            oneErr = 1;
        /* Next Check UDP */
        err = CheckRuleStates(&(rule->RuleList->UdpList));
        if (err)
            oneErr = 1;
        /* Next Check ICMP */
        err = CheckRuleStates(&(rule->RuleList->IcmpList));
        if (err)
            oneErr = 1;
        /* Finally IP */
        err = CheckRuleStates(&(rule->RuleList->IpList));
        if (err)
            oneErr = 1;
    }
#ifdef DYNAMIC_PLUGIN
#if 0
    if (oneErr)
    {
        FatalError("Misconfigured or unregistered encoded rule plugins\n");
    }
#endif
#endif
}

/****************************************************************************
 *
 * Purpose: Parses a rule state line.
 *          Format is sid, gid, state, action.
 *          state should be "enabled" or "disabled"
 *          action should be "alert", "drop", "sdrop", "log", etc.
 *
 * Arguments: args => string containing a single rule state entry
 *
 * Returns: void function
 *
 *****************************************************************************/
void ParseRuleState(char *args)
{
    char ** toks;
    int     num_toks = 0;
    RuleState state;
    RuleState *newState;

    toks = mSplit(args, ", ", 65535, &num_toks, 0);

    if ( !num_toks || num_toks != 4)
    {
        FatalError("%s(%d) => config rule_state: Empty state info.\n", 
                    file_name, file_line);
    }

    if (!isdigit((int)toks[0][0]))
        FatalError("%s(%d) => config rule_state: Invalid SID.\n", 
                    file_name, file_line);

    state.sid = atoi(toks[0]);

    if (!isdigit((int)toks[1][0]))
        FatalError("%s(%d) => config rule_state: Invalid GID.\n", 
                    file_name, file_line);

    state.gid = atoi(toks[1]);

    if (!strcasecmp(toks[2], "disabled"))
    {
        state.state = RULE_STATE_DISABLED;
    }
    else if (!strcasecmp(toks[2], "enabled"))
    {
        state.state = RULE_STATE_ENABLED;
    }
    else
    {
        FatalError("%s(%d) => config rule_state: Invalid state - "
                    "must be either 'enabled' or 'disabled'.\n", 
                    file_name, file_line);
    }

    state.action = RuleType(toks[3]);
    state.next = NULL;
    switch (state.action)
    {
        case RULE_LOG:
        case RULE_PASS:
        case RULE_ALERT:
        case RULE_DROP:
#ifdef GIDS
        case RULE_SDROP:
        case RULE_REJECT:
#endif
        case RULE_ACTIVATE:
        case RULE_DYNAMIC:
            break;
        default:
            FatalError("%s(%d) => config rule_state: Invalid action - "
                    "must be a valid rule type.\n", 
                    file_name, file_line);
    }

    pv.numRuleStates++;
    newState = (RuleState *)SnortAlloc(sizeof(RuleState));
    if (!newState)
        FatalError("%s(%d) => config rule_state: Could not allocate "
                   "rule state node.\n", 
                   file_name, file_line);
    memcpy(newState, &state, sizeof(RuleState));

    if (!pv.ruleStateList)
    {
        pv.ruleStateList = newState;
    }
    else
    {
        newState->next = pv.ruleStateList;
        pv.ruleStateList = newState;
    }
}

#ifdef DYNAMIC_PLUGIN
void DeleteDynamicPaths()
{
    unsigned int i;
    for (i=0;i < pv.dynamicEngineCount;i++)
    {
        if (pv.dynamicEngine[i])
        {
            if (pv.dynamicEngine[i]->path)
                free(pv.dynamicEngine[i]->path);
            free(pv.dynamicEngine[i]);
        }
    }

    for (i=0;i < pv.dynamicLibraryCount;i++)
    {
        if (pv.dynamicDetection[i])
        {
            if (pv.dynamicDetection[i]->path)
                free(pv.dynamicDetection[i]->path);
            free(pv.dynamicDetection[i]);
        }
    }

    for (i=0;i < pv.dynamicPreprocCount;i++)
    {
        if (pv.dynamicPreprocs[i])
        {
            if (pv.dynamicPreprocs[i]->path)
                free(pv.dynamicPreprocs[i]->path);
            free(pv.dynamicPreprocs[i]);
        }
    }
}

/****************************************************************************
 *
 * Purpose: Parses a dynamic engine line
 *          Format is full path of dynamic engine
 *
 * Arguments: args => string containing a single dynamic engine
 *
 * Returns: void function
 *
 *****************************************************************************/
void ParseDynamicEngine(char *args)
{
    char **toks;
    int num_toks;
    DynamicDetectionSpecifier *dynamicLib;
    char *dynamicEngineLibPath = NULL;
    int type = DYNAMIC_LIBRARY_FILE;

    if (pv.dynamicEngineCount >= MAX_DYNAMIC_ENGINES)
    {
        FatalError("Maximum number of loaded Dynamic Engines (%d) exceeded\n", MAX_DYNAMIC_ENGINES);
    }

    toks = mSplit(args, " ", 4, &num_toks, 0);
    if(num_toks == 1)
    {
        /* Load everything from current dir */
        if (!pv.dynamicEngineCurrentDir)
        {
            dynamicLib = (DynamicDetectionSpecifier *)SnortAlloc(sizeof(DynamicDetectionSpecifier));

            /* getcwd will dynamically allocate space for the path */
            dynamicEngineLibPath = getcwd(dynamicLib->path, 0);
            dynamicLib->path = SnortStrdup(dynamicEngineLibPath);
            dynamicLib->type = DYNAMIC_ENGINE_DIRECTORY;
            pv.dynamicEngineCurrentDir = 1;

            pv.dynamicEngine[pv.dynamicEngineCount] = dynamicLib;
            pv.dynamicEngineCount++;
            mSplitFree(&toks, num_toks);
            return;
        }
    }
    else if (num_toks == 2)
    {
        /* Old default case -- dynamicengine sharedlibpath */
        dynamicEngineLibPath = toks[1];
        type = DYNAMIC_ENGINE_FILE;
    }
    else if (num_toks == 3)
    {
        dynamicEngineLibPath = toks[2];
        if (!strcasecmp(toks[1], "file"))
        {
            type = DYNAMIC_ENGINE_FILE;
        }
        else if (!strcasecmp(toks[1], "directory"))
        {
            type = DYNAMIC_ENGINE_DIRECTORY;
        }
        else
        {
            FatalError("%s(%d) Invalid specifier for Dynamic Engine "
                        "Libs.\n Should be file|directory pathname.\n",
                        file_name, file_line);
        }
    }
    else
    {
        FatalError("%s(%d) => Missing/incorrect dynamic engine lib "
                    "specifier.\n", 
                    file_name, file_line);
    }

    dynamicLib = (DynamicDetectionSpecifier *)SnortAlloc(sizeof(DynamicDetectionSpecifier));

    dynamicLib->type = type;
    dynamicLib->path = SnortStrdup(dynamicEngineLibPath);

    pv.dynamicEngine[pv.dynamicEngineCount] = dynamicLib;
    pv.dynamicEngineCount++;
    mSplitFree(&toks, num_toks);
}

/****************************************************************************
 *
 * Purpose: Parses a dynamic detection lib line
 *          Format is full path of dynamic engine
 *
 * Arguments: args => string containing a single dynamic engine
 *
 * Returns: void function
 *
 *****************************************************************************/
void ParseDynamicDetection(char *args)
{
    char **toks;
    int num_toks;
    DynamicDetectionSpecifier *dynamicLib;
    char *dynamicDetectionLibPath = NULL;
    int type = DYNAMIC_LIBRARY_FILE;

    if (pv.dynamicLibraryCount >= MAX_DYNAMIC_DETECTION_LIBS)
    {
        FatalError("Maximum number of loaded Dynamic Detection Libs (%d) exceeded\n", MAX_DYNAMIC_DETECTION_LIBS);
    }

    toks = mSplit(args, " ", 4, &num_toks, 0);
    if(num_toks == 1)
    {
        /* Load everything from current dir */
        if (!pv.dynamicLibraryCurrentDir)
        {
            dynamicLib = (DynamicDetectionSpecifier *)SnortAlloc(sizeof(DynamicDetectionSpecifier));

            /* getcwd will dynamically allocate space for the path */
            dynamicDetectionLibPath = getcwd(dynamicLib->path, 0);
            dynamicLib->path = SnortStrdup(dynamicDetectionLibPath);
            dynamicLib->type = DYNAMIC_LIBRARY_DIRECTORY;
            pv.dynamicLibraryCurrentDir = 1;

            pv.dynamicDetection[pv.dynamicLibraryCount] = dynamicLib;
            pv.dynamicLibraryCount++;
            mSplitFree(&toks, num_toks);
            return;
        }
    }
    else if (num_toks == 3)
    {
        dynamicDetectionLibPath = toks[2];
        if (!strcasecmp(toks[1], "file"))
        {
            type = DYNAMIC_LIBRARY_FILE;
        }
        else if (!strcasecmp(toks[1], "directory"))
        {
            type = DYNAMIC_LIBRARY_DIRECTORY;
        }
        else
        {
            FatalError("%s(%d) Invalid specifier for Dynamic Detection "
                        "Libs.\n Should be file|directory pathname.\n",
                        file_name, file_line);
        }
    }
    else
    {
        FatalError("%s(%d) => Missing/incorrect dynamic detection lib "
                    "specifier.\n", 
                    file_name, file_line);
    }

    dynamicLib = (DynamicDetectionSpecifier *)SnortAlloc(sizeof(DynamicDetectionSpecifier));

    dynamicLib->type = type;
    dynamicLib->path = SnortStrdup(dynamicDetectionLibPath);

    pv.dynamicDetection[pv.dynamicLibraryCount] = dynamicLib;
    pv.dynamicLibraryCount++;
    mSplitFree(&toks, num_toks);
}

/****************************************************************************
 *
 * Purpose: Parses a dynamic preprocessor lib line
 *          Format is full path of dynamic engine
 *
 * Arguments: args => string containing a single dynamic engine
 *
 * Returns: void function
 *
 *****************************************************************************/
void ParseDynamicPreprocessor(char *args)
{
    char **toks;
    int num_toks;
    DynamicDetectionSpecifier *dynamicLib;
    char *dynamicDetectionLibPath = NULL;
    int type = DYNAMIC_PREPROC_FILE;

    if (pv.dynamicPreprocCount >= MAX_DYNAMIC_PREPROC_LIBS)
    {
        FatalError("Maximum number of loaded Dynamic Preprocessor Libs (%d) exceeded\n", MAX_DYNAMIC_PREPROC_LIBS);
    }

    toks = mSplit(args, " ", 4, &num_toks, 0);
    if(num_toks == 1)
    {
        /* Load everything from current dir */
        if (!pv.dynamicPreprocCurrentDir)
        {
            dynamicLib = (DynamicDetectionSpecifier *)SnortAlloc(sizeof(DynamicDetectionSpecifier));

            /* getcwd will dynamically allocate space for the path */
            dynamicDetectionLibPath = getcwd(dynamicLib->path, 0);
            dynamicLib->path = SnortStrdup(dynamicDetectionLibPath);
            dynamicLib->type = DYNAMIC_PREPROC_DIRECTORY;
            pv.dynamicPreprocCurrentDir = 1;

            pv.dynamicPreprocs[pv.dynamicPreprocCount] = dynamicLib;
            pv.dynamicPreprocCount++;
            mSplitFree(&toks, num_toks);
            return;
        }
    }
    else if (num_toks == 3)
    {
        dynamicDetectionLibPath = toks[2];
        if (!strcasecmp(toks[1], "file"))
        {
            type = DYNAMIC_PREPROC_FILE;
        }
        else if (!strcasecmp(toks[1], "directory"))
        {
            type = DYNAMIC_PREPROC_DIRECTORY;
        }
        else
        {
            FatalError("%s(%d) Invalid specifier for Dynamic Detection "
                        "Libs.\n Should be file|directory pathname.\n",
                        file_name, file_line);
        }
    }
    else
    {
        FatalError("%s(%d) => Missing/incorrect dynamic detection lib "
                    "specifier.\n", 
                    file_name, file_line);
    }

    dynamicLib = (DynamicDetectionSpecifier *)SnortAlloc(sizeof(DynamicDetectionSpecifier));

    dynamicLib->type = type;
    dynamicLib->path = SnortStrdup(dynamicDetectionLibPath);

    pv.dynamicPreprocs[pv.dynamicPreprocCount] = dynamicLib;
    pv.dynamicPreprocCount++;
    mSplitFree(&toks, num_toks);
}

#endif

 /****************************************************************************
 *
 * Purpose: Parses a protocol plus a list of ports.
 *          The protocol should be "udp" or "tcp".
 *          The ports list should be a list of numbers or pairs of numbers.
 *          Each element of the list is separated by a space character.
 *          Each pair of numbers is separated by a colon character.
 *          So the string passed in is e.g. "tcp 443 578 6667:6681 13456"
 *          The numbers do not have to be in numerical order.
 *
 * Arguments: args => string containing protocol plus list of ports
 *
 * Returns: void function
 *
 *****************************************************************************/
void ParsePortList(char *args)
{
    char ** toks;
    int     num_toks = 0;
    int     i, p;
    u_short hi_port, lo_port;
    int     protocol;
    int     not_flag;

    toks = mSplit(args, " ", 65535, &num_toks, 0);

    if ( !num_toks )
    {
        FatalError("%s(%d) => config ignore_ports: Empty port list.\n", 
                    file_name, file_line);
    }

    protocol = WhichProto(toks[0]);

    if ( !(protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) )
    {
        FatalError("%s(%d) => Invalid protocol: %s\n", file_name, file_line, toks[0]);
    }

    for ( i = 1; i < num_toks; i++ )
    {  
        /*  Re-use function from rules processing  */
        ParsePort(toks[i], &hi_port, &lo_port, toks[0], &not_flag);      
           
        for ( p = lo_port; p <= hi_port; p++ )
            pv.ignore_ports[p] = (char)protocol;  /* protocol will be 6 (TCP) or 17 (UDP) */
    }
    
    mSplitFree(&toks, num_toks);
}


/* verify that we are not reusing some other keyword */
int checkKeyword(char *keyword)
{
    RuleListNode *node = RuleLists;

    if(RuleType(keyword) != RULE_UNKNOWN)
    {
        return 1;
    }

    /* check the declared ruletypes now */
    while(node != NULL)
    {
        if(!strcasecmp(node->name, keyword))
        {
            return 1;
        }

        node = node->next;
    }

    return 0;
}

void ParseRuleTypeDeclaration(FILE* rule_file, char *rule)
{
    char *input;
    char *keyword;
    char **toks;
    int num_toks;
    int type;
    int rval = 1;
    ListHead *listhead = NULL;

    toks = mSplit(rule, " ", 10, &num_toks, 0);
    keyword = SnortStrdup(toks[1]);

    /* Verify keyword is unique */
    if(checkKeyword(keyword))
    {
        FatalError("%s(%d): Duplicate keyword: %s\n",
                   file_name, file_line, keyword);
    }

    DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"Declaring new rule type: %s\n", keyword););

    if(num_toks > 2)
    {
        if(strcasecmp("{", toks[2]) != 0)
        {
            FatalError("%s(%d): Syntax error: %s\n",
                       file_name, file_line, rule);
        }
    }
    else
    {
        input = ReadLine(rule_file);
        free(input);
    }

    input = ReadLine(rule_file);

    mSplitFree(&toks, num_toks);

    toks = mSplit(input, " ", 10, &num_toks, 0);

    /* read the type field */
    if(!strcasecmp("type", toks[0]))
    {
        type = RuleType(toks[1]);
        /* verify it is a valid ruletype */
        if((type != RULE_LOG) && (type != RULE_PASS) && (type != RULE_ALERT) &&
           (type != RULE_ACTIVATE) && (type != RULE_DYNAMIC))
        {
            FatalError("%s(%d): Invalid type for rule type declaration: %s\n", file_name, file_line, toks[1]);
        }

        DEBUG_WRAP(DebugMessage(DEBUG_CONFIGRULES,"\ttype(%i): %s\n", type, toks[1]););

        if(type == RULE_PASS)
        {
            rval = 0;
        }

        listhead = CreateRuleType(keyword, type, rval, NULL);
    }
    else
    {
        FatalError("%s(%d): Type not defined for rule file declaration: %s\n", file_name, file_line, keyword);
    }

    free(input);
    input = ReadLine(rule_file);
    
    mSplitFree(&toks, num_toks);


    toks = mSplit(input, " ", 2, &num_toks, 0);

    while(strcasecmp("}", toks[0]) != 0)
    {
        if(RuleType(toks[0]) != RULE_OUTPUT)
        {
            FatalError("%s(%d): Not an output plugin declaration: %s\n", file_name, file_line, keyword);
        }

        head_tmp = listhead;
        ParseOutputPlugin(input);
        head_tmp = NULL;
        free(input);
        input = ReadLine(rule_file);

        mSplitFree(&toks, num_toks);
        toks = mSplit(input, " ", 2, &num_toks, 0);
    }

    mSplitFree(&toks, num_toks);

    pv.num_rule_types++;

    return;
}

void ParseIPv6Options(char *args) 
{
    int num_opts;
    int num_args;
    char **opt_toks;
    char **arg_toks;
    int i;

    opt_toks = mSplit(args, ",", 128, &num_opts, 0);

    for(i=0; i < num_opts; i++)
    {
        arg_toks = mSplit(opt_toks[i], " ", 2, &num_args, 0);

        if(!arg_toks[1]) 
        {
             FatalError("%s(%d) => ipv6_frag option '%s' requires an argument.\n",
                          file_name, file_line, arg_toks[0]);
        }

        if(!strcasecmp(arg_toks[0], "bsd_icmp_frag_alert"))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_INIT, 
                      "disabling the BSD ICMP fragmentation alert\n"););
            if(!strcasecmp(arg_toks[1], "off"))
                pv.decoder_flags.bsd_icmp_frag = 0;
        }
        else if(!strcasecmp(arg_toks[0], "bad_ipv6_frag_alert"))
        {
            DEBUG_WRAP(DebugMessage(DEBUG_INIT, 
                      "disabling the IPv6 bad fragmentation packet alerts\n"););
            if(!strcasecmp(arg_toks[1], "off"))
                pv.decoder_flags.ipv6_bad_frag_pkt = 0;
        
        }
        else if (!strcasecmp(arg_toks[0], "frag_timeout"))
        {
            long val;
            char *endp;

            if(!args)
            {
                 FatalError("Setting the ipv6_frag_timeout requires an integer argument.\n");
            }

            val = strtol(arg_toks[1], &endp, 0);
            if(val <= 0 || val > 3600)
                FatalError("%s(%d) => ipv6_frag_timeout: Invalid argument '%s'."
                          " Must be greater that 0 and less than 3600 secnods.",
                        file_name, file_line, arg_toks[1]);

            if(args == endp || *endp)
                FatalError("%s(%d) => ipv6_frag_timeout: Invalid argument '%s'.\n", 
                        file_name, file_line, arg_toks[1]);

            pv.ipv6_frag_timeout = val;
        }
        else if (!strcasecmp(arg_toks[0], "max_frag_sessions"))
        {
            long val;
            char *endp;

            if(!args)
            {
                 FatalError("Setting the ipv6_max_frag_sessions requires an integer argument.\n");
            }

            val = strtol(arg_toks[1], &endp, 0);
            if (val <= 0) 
                FatalError("%s(%d) => ipv6_max_frag_sessions: Invalid number of"    
                        " sessions '%s'. Must be greater than 0\n", 
                        file_name, file_line, arg_toks[1]);

            if(args == endp || *endp)
                FatalError("%s(%d) => ipv6_max_frag_sessions: Invalid number of"    
                        " sessions '%s'.\n", 
                        file_name, file_line, arg_toks[1]);

            pv.ipv6_max_frag_sessions = val;
        }
        else if (!strcasecmp(arg_toks[0], "drop_bad_ipv6_frag"))
        {
            if(!strcasecmp(arg_toks[1], "off"))
            {
                DEBUG_WRAP(DebugMessage(DEBUG_INIT, 
                      "disabling the BSD ICMP fragmentation alert\n"););
                pv.decoder_flags.drop_bad_ipv6_frag = 0;
            }
        }
        else 
        {
             FatalError("%s(%d) => Invalid option to ipv6_frag '%s %s'.\n", 
                          file_name, file_line, arg_toks[0], arg_toks[1]);
        }
        mSplitFree(&arg_toks, num_args);
    }

    mSplitFree(&opt_toks, num_opts);
}
/* adapted from ParseRuleFile in rules.c */
char *ReadLine(FILE * file)
{
    char * index;
    char * buf; 
    char * p;
    
    buf = (char *)SnortAlloc((MAX_LINE_LENGTH + 1) * sizeof(char));

    /*
     * Read a line from file and return it. Skip over lines beginning with #,
     * ;, or a newline
     */
    while((fgets(buf, MAX_LINE_LENGTH, file)) != NULL)
    {
        file_line++;
        index = buf;

#ifdef DEBUG2
        LogMessage("Got line %s (%d): %s\n", file_name, file_line, buf);
#endif
        /* if it's not a comment or a <CR>, we return it */
        if((*index != '#') && (*index != 0x0a) && (*index != ';')
           && (index != NULL))
        {
            /* advance through any whitespace at the beginning of ther line */
            while(isspace((int) *index))
                ++index;

            /* return a copy of the line */
             p = SnortStrdup(index);
             free( buf );
             return p;
        }
    }

    return NULL;
}

/*
 * Same as VarGet - but this does not Fatal out if a var is not found
 */
char *VarSearch(char *name)
{
#ifdef SUP_IP6
    if(!sfvt_lookup_var(vartable, name)) 
    {
#endif

#ifdef PORTLISTS
    if(!PortVarTableFind(portVarTable, name)) 
    {
#endif
        if(VarHead)
        {
            struct VarEntry *p = VarHead;
            do
            {
                if(strcasecmp(p->name, name) == 0)
                    return p->value;
                p = p->next;
            } while(p != VarHead);
        }
       
        return NULL;

#ifdef PORTLISTS
    }
#endif

#ifdef SUP_IP6
    }
#endif

    return name;
}


/*****************************************************************
 * Function: GetPcaps()
 *
 * This function takes a list of pcap types and arguments from
 * the command line, parses them depending on type and puts them
 * in a user supplied queue. The pcap object list will contain
 * PcapReadObject structures.  The returned queue contains
 * strings representing paths to pcaps.
 *
 * returns -1 on error and 0 on success
 *
 ****************************************************************/
int GetPcaps(SF_LIST *pcap_object_list, SF_QUEUE *pcap_queue)
{
    PcapReadObject *pro = NULL;
    int type = 0;
    char *arg = NULL;
    char *filter = NULL;
    int ret = 0;

    if ((pcap_object_list == NULL) || (pcap_queue == NULL))
        return -1;

    for (pro = (PcapReadObject *)sflist_first(pcap_object_list);
         pro != NULL;
         pro = (PcapReadObject *)sflist_next(pcap_object_list))
    {
        type = pro->type;
        arg = pro->arg;
        filter = pro->filter;

        switch (type)
        {
            case PCAP_SINGLE:
                {
                    char *pcap = NULL;
                    struct stat stat_buf;

                    /* do a quick check to make sure file exists */
                    if (stat(arg, &stat_buf) == -1)
                    {
                        LogMessage("Error getting stat on pcap file: %s: %s\n",
                                   arg, strerror(errno));
                        return -1;
                    }
                    else if (!(stat_buf.st_mode & S_IFREG))
                    {
                        LogMessage("Specified pcap is not a regular file: %s\n", arg);
                        return -1;
                    }

                    pcap = SnortStrdup(arg);
                    ret = sfqueue_add(pcap_queue, (NODE_DATA)pcap);
                    if (ret == -1)
                    {
                        LogMessage("Could not add pcap to pcap list\n");
                        free(pcap);
                        return -1;
                    }
                }

                break;

            case PCAP_FILE_LIST:
                /* arg should be a file with a list of pcaps in it */
                {
                    FILE *pcap_file = NULL;
                    char *pcap = NULL;
                    char path_buf[4096];   /* max chars we'll accept for a path */

                    pcap_file = fopen(arg, "r");
                    if (pcap_file == NULL)
                    {
                        LogMessage("Could not open pcap list file: %s: %s\n",
                                   arg, strerror(errno));
                        return -1;
                    }

                    while (fgets(path_buf, sizeof(path_buf), pcap_file) != NULL)
                    {
                        char *path_buf_ptr, *path_buf_end;
                        struct stat stat_buf;

                        path_buf[sizeof(path_buf) - 1] = '\0';
                        path_buf_ptr = &path_buf[0];
                        path_buf_end = path_buf_ptr + strlen(path_buf_ptr);

                        /* move past spaces if any */
                        while (isspace((int)*path_buf_ptr))
                            path_buf_ptr++;

                        /* if nothing but spaces on line, continue */
                        if (*path_buf_ptr == '\0')
                            continue;

                        /* get rid of trailing spaces */
                        while ((path_buf_end > path_buf_ptr) &&
                               (isspace((int)*(path_buf_end - 1))))
                            path_buf_end--;

                        *path_buf_end = '\0';

                        /* do a quick check to make sure file exists */
                        if (stat(path_buf_ptr, &stat_buf) == -1)
                        {
                            LogMessage("Error getting stat on pcap file: %s: %s\n",
                                       path_buf_ptr, strerror(errno));
                            fclose(pcap_file);
                            return -1;
                        }
#ifndef WIN32
                        else if (stat_buf.st_mode & S_IFDIR)
                        {
                            ret = GetFilesUnderDir(path_buf_ptr, pcap_queue, filter);
                            if (ret == -1)
                            {
                                LogMessage("Error getting pcaps under dir: %s\n", path_buf_ptr);
                                fclose(pcap_file);
                                return -1;
                            }
                        }
#endif
                        else if (stat_buf.st_mode & S_IFREG)
                        {
#ifndef WIN32
                            if ((filter == NULL) || (fnmatch(filter, path_buf_ptr, 0) == 0))
                            {
#endif
                                pcap = SnortStrdup(path_buf_ptr);
                                ret = sfqueue_add(pcap_queue, (NODE_DATA)pcap);
                                if (ret == -1)
                                {
                                    LogMessage("Could not insert pcap into list: %s\n", pcap);
                                    free(pcap);
                                    fclose(pcap_file);
                                    return -1;
                                }
#ifndef WIN32
                            }
#endif
                        }
                        else
                        {
#ifdef WIN32
                            LogMessage("Specified entry in \'%s\' is not a regular file: %s\n",
                                       pcap_file, path_buf_ptr);
#else
                            LogMessage("Specified entry in \'%s\' is not a regular file or directory: %s\n",
                                       pcap_file, path_buf_ptr);
#endif
                            fclose(pcap_file);
                            return -1;
                        }
                    }

                    fclose(pcap_file);
                }

                break;

            case PCAP_LIST:
                /* arg should be a space separated list of pcaps */
                {
                    char *tmp = NULL;
                    char *pcap = NULL;
                    struct stat stat_buf;

                    tmp = strtok_r(arg, " ", &arg);
                    if (tmp == NULL)
                    {
                        LogMessage("No pcaps specified in pcap list\n");
                        return -1;
                    }

                    do
                    {
                        /* do a quick check to make sure file exists */
                        if (stat(tmp, &stat_buf) == -1)
                        {
                            LogMessage("Error getting stat on file: %s: %s\n",
                                       tmp, strerror(errno));
                            return -1;
                        }
                        else if (!(stat_buf.st_mode & S_IFREG))
                        {
                            LogMessage("Specified pcap is not a regular file: %s\n", tmp);
                            return -1;
                        }

                        pcap = SnortStrdup(tmp);
                        ret = sfqueue_add(pcap_queue, (NODE_DATA)pcap);
                        if (ret == -1)
                        {
                            LogMessage("Could not insert pcap into list: %s\n", pcap);
                            free(pcap);
                            return -1;
                        }

                    } while ((tmp = strtok_r(NULL, " ", &arg)) != NULL);
                }

                break;

#ifndef WIN32
            case PCAP_DIR:
                /* arg should be a directory name */
                ret = GetFilesUnderDir(arg, pcap_queue, filter);
                if (ret == -1)
                {
                    LogMessage("Error getting pcaps under dir: %s\n", arg);
                    return -1;
                }

                break;
#endif

            default:
                FatalError("Bad read multiple pcaps type\n");
                break;
        }
    }

    return 0;
}

int ValidateIPList(IpAddrSet *addrset, char *token)
{
    int check_flag = 0;
#ifdef SUP_IP6
    if(!addrset || !(addrset->head||addrset->neg_head))
    {
    	check_flag = -1;
    } else {
    	/* more conflict checking takes place inside the SFIP library */
    	return 0;
    }
#else
    check_flag = CheckForIPListConflicts(addrset);
#endif
    
    switch( check_flag )
    {
        case -1:
            FatalError("%s(%d) => Empty IP used either as source IP or as destination IP in a rule. IP list: %s.\n", 
            file_name, file_line, token);
            break;
            
        case 1: 
    	    FatalError("%s(%d) => Negated IP ranges that are equal to or are"
            " more-general than non-negated ranges are not allowed."
            " Consider inverting the logic: %s.\n", 
            file_name, file_line, token);
            break;
        default:
    	    break;
    }

    return 0;
}

void ParserCleanup()
{
#ifdef PORTLISTS
    /* Clean up the port list entries */
    port_list_free(&port_list);
#endif
#ifdef SHUTDOWN_MEMORY_CLEANUP
    DeleteRuleTreeNodes();
#endif
    DeleteVars();
    DeleteClassifications();
    DeleteReferenceSystems();
#ifdef DYNAMIC_PLUGIN
    DeleteDynamicPaths();
#endif

#ifdef SUP_IP6
    sfvt_free_table(vartable);
    vartable = NULL;
#endif
}
