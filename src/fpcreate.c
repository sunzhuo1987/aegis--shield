/*
**  $Id$
** 
**  fpcreate.c
**
**  Copyright (C) 2002-2008 Sourcefire, Inc.
**  Dan Roelker <droelker@sourcefire.com>
**  Marc Norton <mnorton@sourcefire.com>
**
**  NOTES
**  5.7.02 - Initial Checkin. Norton/Roelker
**
**  This program is free software; you can redistribute it and/or modify
**  it under the terms of the GNU General Public License Version 2 as
**  published by the Free Software Foundation.  You may not use, modify or
**  distribute this program under any other version of the GNU General
**  Public License.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with this program; if not, write to the Free Software
**  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
** 6/13/05 - marc norton
**   Added plugin support for fast pattern match data, requires DYNAMIC_PLUGIN be defined
**
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rules.h"
#include "parser.h"
#include "fpcreate.h"
#include "fpdetect.h"
#include "sp_pattern_match.h"
#include "sp_icmp_code_check.h"
#include "sp_icmp_type_check.h"
#include "sp_ip_proto.h"
#include "plugin_enum.h"
#include "util.h"
#include "rules.h"
#include "parser.h"

#include "mpse.h"
#include "bitop_funcs.h"

#ifdef PORTLISTS
#include "snort.h"
#include "sp_clientserver.h"
#include "sfutil/sfportobject.h"
#include "sfutil/sfrim.h"
#endif

#ifdef DETECTION_OPTION_TREE
#include "detection_options.h"
extern int CheckANDPatternMatch(void *option_data, Packet *p);
extern int CheckUriPatternMatch(void *option_data, Packet *p);
#endif

#ifdef DYNAMIC_PLUGIN
#include "dynamic-plugins/sp_dynamic.h"
#endif

/*
#define LOCAL_DEBUG
*/
#ifdef PORTLISTS

extern rule_index_map_t * ruleIndexMap;
extern rule_port_tables_t portTables;

extern RuleListNode *RuleLists;
extern PV pv;

extern PortTable *nonamePortVarTable;
extern PortVarTable     * portVarTable;

#ifdef TARGET_BASED
#include "target-based/sftarget_protocol_reference.h"
/*
 *  Service Rule Map Master Table
 */
typedef struct 
{
  SFGHASH * tcp_to_srv;
  SFGHASH * tcp_to_cli;
  
  SFGHASH * udp_to_srv;
  SFGHASH * udp_to_cli;

  SFGHASH * icmp_to_srv;
  SFGHASH * icmp_to_cli;

  SFGHASH * ip_to_srv;
  SFGHASH * ip_to_cli;

} srmm_table_t;

srmm_table_t srmmTable;  /* srvc rule map master table */
srmm_table_t spgmmTable;  /* srvc port_group map master table */

/*
 *  Service/Protocol Oridinal To PORT_GROUP table
 */
typedef struct 
{
  PORT_GROUP *tcp_to_srv[MAX_PROTOCOL_ORDINAL];
  PORT_GROUP *tcp_to_cli[MAX_PROTOCOL_ORDINAL];
  
  PORT_GROUP *udp_to_srv[MAX_PROTOCOL_ORDINAL];
  PORT_GROUP *udp_to_cli[MAX_PROTOCOL_ORDINAL];

  PORT_GROUP *icmp_to_srv[MAX_PROTOCOL_ORDINAL];
  PORT_GROUP *icmp_to_cli[MAX_PROTOCOL_ORDINAL];

  PORT_GROUP *ip_to_srv[MAX_PROTOCOL_ORDINAL];
  PORT_GROUP *ip_to_cli[MAX_PROTOCOL_ORDINAL];

} sopg_table_t; 

sopg_table_t sopgTable; /* service-oridnal to port_group table */ 

void sopg_init()
{
    memset(&sopgTable,0,sizeof(sopg_table_t));
}

/*
 * Test if this otn is for traffic to the server
 */
static 
int fpOtnFlowToServer( OptTreeNode * otn ) 
{
    if( OtnFlowFromClient(otn) ) 
        return  1;
    
#ifdef DYNAMIC_PLUGIN
    if (otn->ds_list[PLUGIN_DYNAMIC])
    {
        DynamicData *dd = (DynamicData *)otn->ds_list[PLUGIN_DYNAMIC];
        int optType = OPTION_TYPE_FLOWFLAGS;
        int flags = FLOW_TO_SERVER;

        if (dd->hasOptionFunction(dd->contextData, optType, flags))
            return 1;
    }
#endif
    return 0;
}
/*
 * Test if this otn is for traffic to the client 
 */
static 
int fpOtnFlowToClient( OptTreeNode * otn ) 
{
    if( OtnFlowFromServer(otn) ) 
        return 1;
    
#ifdef DYNAMIC_PLUGIN
    if (otn->ds_list[PLUGIN_DYNAMIC])
    {
        DynamicData *dd = (DynamicData *)otn->ds_list[PLUGIN_DYNAMIC];
        int optType = OPTION_TYPE_FLOWFLAGS;
        int flags = FLOW_TO_CLIENT;

        if (dd->hasOptionFunction(dd->contextData, optType, flags))
            return 1;
    }
#endif
    return 0;
}

/*
* Extract the Icmp Type field to determine the PortGroup.  
*
* returns :
*   -1 : any, or not an EQ tests
*   >0 : any other ip type
*   
*/
static 
int GetOtnIcmpType (OptTreeNode * otn )
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

static 
SFGHASH * alloc_srvmap()
{
   SFGHASH * p;
   
   p = sfghash_new(1000,0,0,(void(*)(void*))sflist_free/*nodes are lists,free them in sfghash_delete*/);        
   if( !p )
   {
       FatalError("could not allocate a service rule map - no memory?\n");
   }
   return p;
}
static
void srvcmap_init()
{
    if( srmmTable.tcp_to_srv ) /* already allocated */
        return;
    
    srmmTable.tcp_to_srv = alloc_srvmap ();        
    srmmTable.tcp_to_cli = alloc_srvmap (); 

    srmmTable.udp_to_srv = alloc_srvmap (); 
    srmmTable.udp_to_cli = alloc_srvmap (); 
        
    srmmTable.icmp_to_srv= alloc_srvmap (); 
    srmmTable.icmp_to_cli= alloc_srvmap ();

    srmmTable.ip_to_srv = alloc_srvmap ();
    srmmTable.ip_to_cli = alloc_srvmap ();
}

#ifdef SHUTDOWN_MEMORY_CLEANUP
static 
void srvcmap_term_table( SFGHASH * p )
{
    sfghash_delete( p );
}
static
void srvcmap_term()
{
    srvcmap_term_table( srmmTable.tcp_to_srv );
    srvcmap_term_table( srmmTable.tcp_to_cli );
    srvcmap_term_table( srmmTable.udp_to_srv );
    srvcmap_term_table( srmmTable.udp_to_cli );
    srvcmap_term_table( srmmTable.icmp_to_srv );
    srvcmap_term_table( srmmTable.icmp_to_cli );
    srvcmap_term_table( srmmTable.ip_to_srv );
    srvcmap_term_table( srmmTable.ip_to_cli );

    memset( &srmmTable, 0, sizeof( srmmTable ) );
}
#endif

static 
SFGHASH * alloc_spgmm()
{
   SFGHASH * p;
   
   /* 
    * TODO: keys are ascii service names - for now ! 
    */
   p = sfghash_new(1000,/* # rows in table */
           0, /* size: of key 0 = ascii, >0 = fixed size */
           0, /* bool:user keys,  if true just store this pointer, don't copy the key */
           (void(*)(void*))0 /* free nodes are port_groups do not delete here */ );        
   if( !p )
   {
       FatalError("could not allocate a service port_group map : no memory?\n");
   }
   return p;
}
static
void spgmm_init()
{
    if( spgmmTable.tcp_to_srv ) /* already allocated */
        return;
    
    spgmmTable.tcp_to_srv = alloc_spgmm ();        
    spgmmTable.tcp_to_cli = alloc_spgmm (); 

    spgmmTable.udp_to_srv = alloc_spgmm (); 
    spgmmTable.udp_to_cli = alloc_spgmm (); 
        
    spgmmTable.icmp_to_srv= alloc_spgmm (); 
    spgmmTable.icmp_to_cli= alloc_spgmm ();

    spgmmTable.ip_to_srv = alloc_spgmm ();
    spgmmTable.ip_to_cli = alloc_spgmm ();
}

#ifdef SHUTDOWN_MEMORY_CLEANUP
static 
void spgmm_term_table( SFGHASH * p )

{
    SFGHASH_NODE * n;
    PORT_GROUP * pg;
      
    if( !p ) return ;
 
    for( n = sfghash_findfirst(p);
         n;
         n = sfghash_findnext(p) )
    {
        pg = (PORT_GROUP*)n->data;
        if( !pg ) continue;

        /* TODO: (if we need to recycle these) free the PORT_GROUP */
        n->data = NULL;
    }

    sfghash_delete( p );
}
static
void spgmm_term()
{
    spgmm_term_table( spgmmTable.tcp_to_srv );
    spgmm_term_table( spgmmTable.tcp_to_cli );
    spgmm_term_table( spgmmTable.udp_to_srv );
    spgmm_term_table( spgmmTable.udp_to_cli );
    spgmm_term_table( spgmmTable.icmp_to_srv );
    spgmm_term_table( spgmmTable.icmp_to_cli );
    spgmm_term_table( spgmmTable.ip_to_srv );
    spgmm_term_table( spgmmTable.ip_to_cli );

    memset( &spgmmTable, 0, sizeof( spgmmTable ) );
}
#endif

/*
 * Add the otn to the list stored by the key = servicename.
 *
 * table - table of service/otn-list pairs
 * servicename - ascii service name from rule metadata option
 * otn - rule - may be content,-no-content, or uri-content
 *
 */
static
void srvcmap_add_otn_raw( SFGHASH * table, char * servicename, OptTreeNode * otn )
{
    SF_LIST * list;
    
    list = (SF_LIST*) sfghash_find( table, servicename );
    
    if( !list )
    {
        /* create the list */
        list = sflist_new();
        if( !list )
            FatalError("service_rule_map: could not create a  service rule-list\n");
        
        /* add the service list to the table */
        if( sfghash_add( table, servicename, list ) != SFGHASH_OK )
        {
            FatalError("service_rule_map: could not add a rule to the rule-service-map\n");
        }
    }
    
    /* add the rule */
    if( sflist_add_tail( list, otn ) )
        FatalError("service_rule_map: could not add a rule to the service rule-list\n");
}
/*
 *  maintain a table of service maps, one for each protocol and direction,
 *  each service map maintains a list of otn's for each service it maps to a 
 *  service name.
 */
static
int srvcmap_add_otn( int proto, char * servicename, OptTreeNode * otn )
{
    SFGHASH * to_srv; /* to srv service rule map */
    SFGHASH * to_cli; /* to cli service rule map */
   
    if( !servicename ) 
        return 0;

    if(!otn )
        return 0;
    
    if( proto == IPPROTO_TCP)
    {
        to_srv = srmmTable.tcp_to_srv;
        to_cli = srmmTable.tcp_to_cli;
    }
    else if( proto == IPPROTO_UDP)
    {
        to_srv = srmmTable.udp_to_srv;
        to_cli = srmmTable.udp_to_cli;
    }
    else if( proto == IPPROTO_ICMP )
    {
        to_srv = srmmTable.icmp_to_srv;
        to_cli = srmmTable.icmp_to_cli;
    }
    else if( proto ==  ETHERNET_TYPE_IP )
    {
        to_srv = srmmTable.tcp_to_srv;
        to_cli = srmmTable.ip_to_cli;
    }
    else
    {
        return 0;
    }

    if( fpOtnFlowToServer(otn) )
    {
        srvcmap_add_otn_raw( to_srv, servicename, otn );
    }
    else if( fpOtnFlowToClient(otn) ) 
    {
        srvcmap_add_otn_raw( to_cli, servicename, otn );
    }
    else /* else add to both sides */
    {
        srvcmap_add_otn_raw( to_srv, servicename, otn );
        srvcmap_add_otn_raw( to_cli, servicename, otn );
    }

    return 0;
}
// TARGET_BASED
#endif
// PORTLISTS
#endif

/*
**  Main variables to this file. 
**
**  The port-rule-maps map the src-dst ports to rules for
**  udp and tcp, for Ip we map the dst port as the protocol, 
**  and for Icmp we map the dst port to the Icmp type. This 
**  allows us to use the decode packet information to in O(1) 
**  select a group of rules to apply to the packet.  These 
**  rules may have uricontent, content, or they may be no content 
**  rules, or any combination. We process the uricontent 1st,
**  then the content, and then the no content rules for udp/tcp 
**  and icmp, than we process the ip rules.
*/
static PORT_RULE_MAP *prmTcpRTNX = NULL;
static PORT_RULE_MAP *prmUdpRTNX = NULL;
static PORT_RULE_MAP *prmIpRTNX  = NULL;
static PORT_RULE_MAP *prmIcmpRTNX= NULL;

static FPDETECT fpDetect;

/*
**  The following functions are wrappers to the pcrm routines,
**  that utilize the variables that we have intialized by
**  calling fpCreateFastPacketDetection().  These functions
**  are also used in the file fpdetect.c, where we do lookups
**  on the initialized variables.
*/
int prmFindRuleGroupIp(int ip_proto, PORT_GROUP **ip_group, PORT_GROUP ** gen)
{
    PORT_GROUP *src;
    return prmFindRuleGroup( prmIpRTNX, ip_proto, -1, &src, ip_group, gen);
}

int prmFindRuleGroupIcmp(int type, PORT_GROUP **type_group, PORT_GROUP ** gen)
{
    PORT_GROUP *src;
    return prmFindRuleGroup( prmIcmpRTNX, type, -1, &src, type_group, gen);
}

int prmFindRuleGroupTcp(int dport, int sport, PORT_GROUP ** src, 
        PORT_GROUP **dst , PORT_GROUP ** gen)
{
    return prmFindRuleGroup( prmTcpRTNX, dport, sport, src, dst , gen);
}

int prmFindRuleGroupUdp(int dport, int sport, PORT_GROUP ** src, 
        PORT_GROUP **dst , PORT_GROUP ** gen)
{
    return prmFindRuleGroup( prmUdpRTNX, dport, sport, src, dst , gen);
}


/*
**  These Otnhas* functions check the otns for different contents.  This
**  helps us decide later what group (uri, content) the otn will go to.
*/
int OtnHasContent( OptTreeNode * otn ) 
{
    if( !otn ) return 0;
    
    if( otn->ds_list[PLUGIN_PATTERN_MATCH] || otn->ds_list[PLUGIN_PATTERN_MATCH_OR] )
    {
        return 1; 
    }

#ifdef DYNAMIC_PLUGIN
    if (otn->ds_list[PLUGIN_DYNAMIC])
    {
        DynamicData *dd = (DynamicData *)otn->ds_list[PLUGIN_DYNAMIC];
        if (dd->fpContentFlags & FASTPATTERN_NORMAL)
            return 1;
    }
#endif

    return 0;
}

int OtnHasUriContent( OptTreeNode * otn ) 
{
    if( !otn ) return 0;

    if( otn->ds_list[PLUGIN_PATTERN_MATCH_URI] )
    {
        return PatternMatchUriBuffer(otn->ds_list[PLUGIN_PATTERN_MATCH_URI]); 
    }

#ifdef DYNAMIC_PLUGIN
    if (otn->ds_list[PLUGIN_DYNAMIC])
    {
        DynamicData *dd = (DynamicData *)otn->ds_list[PLUGIN_DYNAMIC];
        if (dd->fpContentFlags & FASTPATTERN_URI)
            return 1;
    }
#endif

    return 0;
}

#ifndef PORTLISTS 
/*
**  
**  NAME
**    CheckPorts::
**
**  DESCRIPTION
**    This function returns the port to use for a given signature.
**    Currently, only signatures that have a unique port (meaning that
**    the port is singular and not a range) are added as specific 
**    ports to the port list.  If there is a range of ports in the
**    signature, then it is added as a generic rule.
**
**    This can be refined at any time, and limiting the number of
**    generic rules would be a good idea.
**
**  FORMAL INPUTS
**    u_short - the high port of the signature range
**    u_short - the low port of the signature range
**
**  FORMAL OUTPUT
**    int - -1 means generic, otherwise it is the port
**
*/
static int CheckPorts(u_short high_port, u_short low_port)
{
    if( high_port == low_port )
    {
       return high_port;
    }
    else
    {
       return -1;
    }
}
#endif /* PORTLISTS */


#ifdef DETECTION_OPTION_TREE
void free_detection_option_root(void **existing_tree)
{
    detection_option_tree_root_t *root;

    if (!existing_tree || !*existing_tree)
        return;

    root = *existing_tree;
    free(root->children);
    free(root);
    *existing_tree = NULL;
}

void free_detection_option_tree(detection_option_tree_node_t *node)
{
    int i;
    for (i=0;i<node->num_children;i++)
    {
        free_detection_option_tree(node->children[i]);
    }
    free(node->children);
    free(node);
}

static int num_trees = 0;
static int num_nc_trees = 0;
static int num_dup_trees = 0;
int finalize_detection_option_tree(detection_option_tree_root_t *root)
{
    detection_option_tree_node_t *node = NULL;
    detection_option_tree_node_t *dup_node = NULL;
    int i;

    if (!root)
        return -1;

    for (i=0;i<root->num_children;i++)
    {
        node = root->children[i];
        if (add_detection_option_tree(node, (void **)&dup_node) == DETECTION_OPTION_EQUAL)
        {
            free_detection_option_tree(node);
            root->children[i] = dup_node;
            num_dup_trees++;
        }
        else
        {
            num_trees++;
        }
#ifdef DEBUG_OPTION_TREE
        print_option_tree(root->children[i], 0);
#endif
    }

    return 0;
}

int otn_create_tree(OptTreeNode *otn, void **existing_tree)
{
    detection_option_tree_node_t *node = NULL, *child;
    detection_option_tree_root_t *root = NULL;
    OptFpList *opt_fp = NULL;
    int i;

    if (!existing_tree)
        return -1;

    if (!*existing_tree)
    {
        *existing_tree = SnortAlloc(sizeof(detection_option_tree_root_t));
    }
    root = *existing_tree;
#ifdef PPM_MGR
    root->tree_state = RULE_STATE_ENABLED;
#endif

    opt_fp = otn->opt_func;

    if (!root->children)
    {
        root->num_children++;
        root->children = SnortAlloc(sizeof(detection_option_tree_node_t *) * root->num_children);
    }

    i = 0;
    child = root->children[i];

    /* Build out sub-nodes for each option in the OTN fp list */
    while (opt_fp)
    {
        /* If child node does not match existing option_data, 
         * Create a child branch from a given sub-node. */
        void *option_data = opt_fp->context;
        char found_child_match = 0;

        if (opt_fp->type == RULE_OPTION_TYPE_LEAF_NODE)
        {
            opt_fp = opt_fp->next;
            continue;
        }

        if (!child)
        {
            /* No children at this node */
            child = SnortAlloc(sizeof(detection_option_tree_node_t));
            child->option_data = option_data;
            child->option_type = opt_fp->type;
            child->evaluate = opt_fp->OptTestFunc;
            if (!node)
            {
                root->children[i] = child;
            }
            else
            {
                node->children[i] = child;
            }
            child->num_children++;
            child->children = SnortAlloc(sizeof(detection_option_tree_node_t *) * child->num_children);
            child->last_check.is_relative = opt_fp->isRelative;
            if (node && child->last_check.is_relative)
            {
                node->relative_children++;
            }
        }
        else
        {
            if (child->option_data != option_data)
            {
                if (!node)
                {
                    for (i=1;i<root->num_children;i++)
                    {
                        child = root->children[i];
                        if (child->option_data == option_data)
                        {
                            found_child_match = 1;
                            break;
                        }
                    }
                }
                else
                {
                    for (i=1;i<node->num_children;i++)
                    {
                        child = node->children[i];
                        if (child->option_data == option_data)
                        {
                            found_child_match = 1;
                            break;
                        }
                    }
                }
            }
            else
            {
                found_child_match = 1;
            }

            if (found_child_match == 0)
            {
                /* No matching child node, create a new and add to array */
                detection_option_tree_node_t **tmp_children;
                child = SnortAlloc(sizeof(detection_option_tree_node_t));
                child->option_data = option_data;
                child->option_type = opt_fp->type;
                child->evaluate = opt_fp->OptTestFunc;
                child->num_children++;
                child->children = SnortAlloc(sizeof(detection_option_tree_node_t *) * child->num_children);
                child->last_check.is_relative = opt_fp->isRelative;

                if (!node)
                {
                    root->num_children++;
                    tmp_children = SnortAlloc(sizeof(detection_option_tree_node_t *) * root->num_children);
                    memcpy(tmp_children, root->children, sizeof(detection_option_tree_node_t *) * (root->num_children-1));

                    free(root->children);
                    root->children = tmp_children;
                    root->children[root->num_children-1] = child;
                }
                else
                {
                    node->num_children++;
                    tmp_children = SnortAlloc(sizeof(detection_option_tree_node_t *) * node->num_children);
                    memcpy(tmp_children, node->children, sizeof(detection_option_tree_node_t *) * (node->num_children-1));

                    free(node->children);
                    node->children = tmp_children;
                    node->children[node->num_children-1] = child;
                    if (child->last_check.is_relative)
                        node->relative_children++;
                }
            }
        }
        node = child;
        i=0;
        child = node->children[i];
        opt_fp = opt_fp->next;
    }

    /* Append a leaf node that has option data of the SigInfo/otn pointer */
    child = SnortAlloc(sizeof(detection_option_tree_node_t));
    child->option_data = otn;
    child->option_type = RULE_OPTION_TYPE_LEAF_NODE;
    if (!node)
    {
        if (root->children[0])
        {
            detection_option_tree_node_t **tmp_children;
            root->num_children++;
            tmp_children = SnortAlloc(sizeof(detection_option_tree_node_t *) * root->num_children);
            memcpy(tmp_children, root->children, sizeof(detection_option_tree_node_t *) * (root->num_children-1));
            free(root->children);
            root->children = tmp_children;
        }
        root->children[root->num_children-1] = child;
    }
    else
    {
        if (node->children[0])
        {
            detection_option_tree_node_t **tmp_children;
            node->num_children++;
            tmp_children = SnortAlloc(sizeof(detection_option_tree_node_t *) * node->num_children);
            memcpy(tmp_children, node->children, sizeof(detection_option_tree_node_t *) * (node->num_children-1));
            free(node->children);
            node->children = tmp_children;
        }
        node->children[node->num_children-1] = child;
    }

    return 0;
}

int pmx_create_tree(void *id, void **existing_tree)
{
    PMX              *pmx    = NULL;
    RULE_NODE        *rnNode = NULL;
    OTNX             *otnx   = NULL;
    OptTreeNode      *otn    = NULL;

    if (!existing_tree)
        return -1;

    if (!*existing_tree)
    {
        *existing_tree = SnortAlloc(sizeof(detection_option_tree_root_t));
    }

    if (!id)
    {
        /* NULL input id (PMX *), last call for this pattern state */
        return finalize_detection_option_tree((detection_option_tree_root_t *)*existing_tree);
    }

    pmx    = (PMX*)id;
    rnNode = (RULE_NODE*)(pmx->RuleNode);
    otnx   = (OTNX*)(rnNode->rnRuleData);
    otn    = otnx->otn;
    return otn_create_tree(otn, existing_tree);
}
#endif

/*
**  The following functions deal with the intialization of the 
**  detection engine.  These are set through parser.c with the
**  option 'config detection:'.  This functionality may be 
**  broken out later into it's own file to separate from this
**  file's functionality.
*/

/*
**  Initialize detection options.
*/
int fpInitDetectionEngine()
{
    memset(&fpDetect, 0x00, sizeof(fpDetect));

    /*
    **  We inspect pkts that are going to be rebuilt and
    **  reinjected through snort.
    */
    fpDetect.inspect_stream_insert = 1;
    fpDetect.search_method = MPSE_AC_BNFA;
    fpDetect.search_method_verbose = 0;
    fpDetect.debug = 0;
    fpDetect.max_queue_events = 5;
  
#ifdef PORTLISTS
    fpDetect.bleedover_port_limit=1024;
    fpDetect.portlists_flags = 0;
#endif

    /*
    **  This functions gives fpdetect.c the detection configuration
    **  set up in fpcreate.
    */
    fpSetDetectionOptions(&fpDetect);

    return 0;
}
int fpDetectGetSingleRuleGroup(void)
{
    return fpDetect.portlists_flags & PL_SINGLE_RULE_GROUP;
}
int fpDetectGetBleedOverPortLimit(void)
{
    return fpDetect.bleedover_port_limit;
}
int fpDetectGetBleedOverWarnings(void)
{
    return fpDetect.portlists_flags & PL_BLEEDOVER_WARNINGS_ENABLED;
}
int fpDetectGetDebugPrintNcRules(void)
{
    return fpDetect.portlists_flags & PL_DEBUG_PRINT_NC_DETECT_RULES;
}
int fpDetectGetDebugPrintRuleGroupBuildDetails(void)
{
    return fpDetect.portlists_flags & PL_DEBUG_PRINT_RULEGROWP_BUILD;
}
int fpDetectGetDebugPrintRuleGroupsCompiled(void)
{
    return fpDetect.portlists_flags & PL_DEBUG_PRINT_RULEGROUPS_COMPILED;
}
int fpDetectGetDebugPrintRuleGroupsUnCompiled(void)
{
    return fpDetect.portlists_flags & PL_DEBUG_PRINT_RULEGROUPS_UNCOMPILED;;
}

void fpDetectSetSingleRuleGroup()
{
    fpDetect.portlists_flags |= PL_SINGLE_RULE_GROUP;
}
void fpDetectSetBleedOverPortLimit(int n)
{
    if( n > 0 )
        fpDetect.bleedover_port_limit = n;
}
void fpDetectSetBleedOverWarnings()
{
    fpDetect.portlists_flags |= PL_BLEEDOVER_WARNINGS_ENABLED;
}
void fpDetectSetDebugPrintNcRules()
{
    fpDetect.portlists_flags |= PL_DEBUG_PRINT_NC_DETECT_RULES;
}
void fpDetectSetDebugPrintRuleGroupBuildDetails()
{
    fpDetect.portlists_flags |= PL_DEBUG_PRINT_RULEGROWP_BUILD;
}
void fpDetectSetDebugPrintRuleGroupsCompiled()
{
    fpDetect.portlists_flags |= PL_DEBUG_PRINT_RULEGROUPS_COMPILED;
}
void fpDetectSetDebugPrintRuleGroupsUnCompiled()
{
    fpDetect.portlists_flags |= PL_DEBUG_PRINT_RULEGROUPS_UNCOMPILED;
}

int fpSetDetectSearchOpt( int flag )
{
    fpDetect.search_opt=flag;
    if( flag )
        LogMessage("    Search-Method-Optimizations = enabled\n");
    return 0;
}

/*
   Search method is set using:
   config detect: search-method ac-bnfa | ac | ac-full | ac-sparsebands | ac-sparse | ac-banded | ac-std | verbose
*/
int fpSetDetectSearchMethod( char * method )
{
    LogMessage("Detection:\n");

    if( !strcasecmp(method,"ac-std") ) /* default */
    {
       fpDetect.search_method = MPSE_AC ;
       LogMessage("   Search-Method = AC-Std\n");
       return 0;
    }
    if( !strcasecmp(method,"ac-bnfa-q") ||
        !strcasecmp(method,"ac-bnfa") )
    {
       fpDetect.search_method = MPSE_AC_BNFA_Q ;
       LogMessage("   Search-Method = AC-BNFA-Q\n");
       return 0;
    }
    if( !strcasecmp(method,"ac-bnfa-nq") )
    {
       fpDetect.search_method = MPSE_AC_BNFA ;
       LogMessage("   Search-Method = AC-BNFA\n");
       return 0;
    }
    if( !strcasecmp(method,"ac-q") ||
        !strcasecmp(method,"ac") )
    {
       fpDetect.search_method = MPSE_ACF_Q ;
       LogMessage("   Search-Method = AC-Full-Q\n");
       return 0;
    }
    if( !strcasecmp(method,"ac-nq") )
    {
       fpDetect.search_method = MPSE_ACF ;
       LogMessage("   Search-Method = AC-Full\n");
       return 0;
    }
    if( !strcasecmp(method,"acs") )
    {
       fpDetect.search_method = MPSE_ACS ;
       LogMessage("   Search-Method = AC-Sparse\n");
       return 0;
    }
    if( !strcasecmp(method,"ac-banded") )
    {
       fpDetect.search_method = MPSE_ACB ;
       LogMessage("   Search-Method = AC-Banded\n");
       return 0;
    }
    if( !strcasecmp(method,"ac-sparsebands") )
    {
       fpDetect.search_method = MPSE_ACSB ;
       LogMessage("   Search-Method = AC-Sparse-Bands\n");
       return 0;
    }
        
    /* These are for backwards compatability - and will be removed in future releases*/

    if( !strcasecmp(method,"mwm") ) 
    {
       fpDetect.search_method = MPSE_LOWMEM ;
       LogMessage("   Search-Method = Low-Mem (MWM depracated)\n");
       return 0;
    }

    if( !strcasecmp(method,"lowmem-q") ||
        !strcasecmp(method,"lowmem") )
    {
       fpDetect.search_method = MPSE_LOWMEM_Q ;
       LogMessage("   Search-Method = Low-Mem-Q\n");
       return 0;
    }
    if( !strcasecmp(method,"lowmem-nq") )
    {
       fpDetect.search_method = MPSE_LOWMEM ;
       LogMessage("   Search-Method = Low-Mem\n");
       return 0;
    }
    return 1;
}

/*
**  Set the debug mode for the detection engine.
*/
int fpSetDebugMode()
{
    fpDetect.debug = 1;
    return 0;
}

/*
**  Revert the detection engine back to not inspecting packets
**  that are going to be rebuilt.
*/
int fpSetStreamInsert()
{
    fpDetect.inspect_stream_insert = 0;
    return 0;
}

/*
**  Sets the maximum number of events to queue up in fpdetect before
**  selecting an event.
*/
int fpSetMaxQueueEvents(int iNum)
{
    if(iNum <= 0)
    {
        return 1;
    }

    fpDetect.max_queue_events = iNum;

    return 0;
}

#ifdef TARGET_BASED 
/*
**
**   NAME
**     IsPureNotRule
**
**   DESCRIPTION
**     Checks to see if a rule is a pure not rule.  A pure not rule
**     is a rule that has all "not" contents or Uri contents.
**
**   FORMAL INPUTS
**     PatternMatchData * - the match data to check for not contents.
**
**   FORMAL OUTPUTS
**     int - 1 is rule is a pure not, 0 is rule is not a pure not.
**
*/
#ifdef DETECTION_OPTION_TREE
static int IsPureNotRule( PatternMatchData *pmd_to_check, OptTreeNode * otn )
{
    int rcnt=0,ncnt=0;
    OptFpList *opt_fp = otn->opt_func;
    PatternMatchData *pmd;

    while (opt_fp)
    {
        if ((opt_fp->OptTestFunc == CheckANDPatternMatch) ||
            (opt_fp->OptTestFunc == CheckUriPatternMatch))
        {
            pmd = (PatternMatchData *)opt_fp->context;
            if (pmd->buffer_func != pmd_to_check->buffer_func)
            {
                opt_fp = opt_fp->next;
                continue;
            }
            rcnt++;
            if( pmd->exception_flag ) ncnt++;
        }
        opt_fp = opt_fp->next;
    }
    if( !rcnt ) return 0;
    
    return ( rcnt == ncnt ) ;  
}
#else
static int IsPureNotRule( PatternMatchData * pmd )
{
    int rcnt=0,ncnt=0;

    for( ;pmd; pmd=pmd->next )
    {
        rcnt++;
        if( pmd->exception_flag ) ncnt++;
    }

    if( !rcnt ) return 0;
    
    return ( rcnt == ncnt ) ;  
}
#endif /* DETECTION_OPTION_TREE */
#endif

/* FLP_Trim
  *
  * Trim zero byte prefixes, this increases uniqueness
  * 
  * returns 
  *   length - of trimmed pattern
  *   buff - ptr to new beggining of trimmed buffer
  */
static int FLP_Trim( char * p, int plen, char ** buff )
 {
    int i;
    int size = 0;
 
    if( !p )
        return 0;
    
    for(i=0;i<plen;i++)
    {
        if( p[i] != 0 ) break;
    }
  
    if( i < plen )
        size = plen - i;
    else
        size = 0;
    
    if( buff && (size==0) ) 
    {
        *buff = 0;
    }
    else if( buff ) 
    {
        *buff = &p[i];
    }
    return size;
 }

/*
**
**  NAME
**    FindLongestPattern
**
**  DESCRIPTION
**    This functions selects the longest pattern out of a set of
**    patterns per snort rule.  By picking the longest pattern, we
**    help the pattern matcher speed and the selection criteria during
**    detection.
**
**  FORMAL INPUTS
**    PatternMatchData * - contents to select largest
**
**  FORMAL OUTPUTS 
**    PatternMatchData * - ptr to largest pattern
**
*/
#ifdef DETECTION_OPTION_TREE
static PatternMatchData * FindLongestPattern( PatternMatchData *pmd_to_check, OptTreeNode * otn )
{
    OptFpList *opt_fp = otn->opt_func;
    PatternMatchData *pmd;

    PatternMatchData *pmdmax = NULL;
    PatternMatchData *pmdmax_raw = NULL;
    u_int max_size_raw=0; 
    int max_size=0; 
    int size=0; 

    while (opt_fp)
    {
        if ((opt_fp->OptTestFunc == CheckANDPatternMatch) ||
            (opt_fp->OptTestFunc == CheckUriPatternMatch))
        {
            pmd = (PatternMatchData *)opt_fp->context;
            if (pmd->buffer_func != pmd_to_check->buffer_func)
            {
                opt_fp = opt_fp->next;
                continue;
            }

            if ((opt_fp->OptTestFunc == CheckUriPatternMatch) &&
                (pmd->uri_buffer == HTTP_SEARCH_COOKIE))
            {
                /* Don't add cookie buffer patterns */
                opt_fp = opt_fp->next;
                continue;
            }

            /* If this content is flagged for fast pattern, use it */
            if (pmd->flags & CONTENT_FAST_PATTERN)
            {
                return pmd;
            }

            if (pmd->pattern_buf && !pmd->exception_flag)
            {
                /* Track longest filtered pattern length */
                size = FLP_Trim(pmd->pattern_buf, pmd->pattern_size,NULL);
                if( (size > max_size) )
                {
                    pmdmax = pmd;
                    max_size = size;
                }

                /* Track longest raw pattern length */
                if( pmd->pattern_size > max_size_raw )
                {
                    pmdmax_raw=pmd;
                    max_size_raw = pmd->pattern_size;
                }
            }
        }
        opt_fp = opt_fp->next;
    }

    /* return the longest filterd pattern, if a non-zero-byte one exists */
    if( pmdmax )
        return pmdmax;

    /* else return the longest, even if its all zeros */
    return pmdmax_raw;
}
#else
static PatternMatchData * FindLongestPattern( PatternMatchData * pmd )
{
    PatternMatchData *pmdmax;
    PatternMatchData *pmdmax_raw;
    u_int max_size_raw=0; 
    int max_size=0; 
    int size=0; 
   
    /* Find the 1st pattern that is not a NOT pattern */   
    while( pmd && pmd->exception_flag ) pmd=pmd->next;
        
    if( !pmd ) return NULL;  /* All Patterns are NOT patterns */
      
    /* If this content is flagged for fast pattern, use it */
    if (pmd->flags & CONTENT_FAST_PATTERN)
    {
        return pmd;
    }
      
    /* Track raw lengths */
    max_size_raw = pmd->pattern_size;
    pmdmax_raw = pmd; /* we can return at least the 1st pattern, if zero */
     
    /* Track filtered lengths */
    max_size = FLP_Trim(pmd->pattern_buf, pmd->pattern_size,NULL);
    if( max_size > 0 )
        pmdmax = pmd;
    else
        pmdmax = NULL;
     
    pmd=pmd->next;

    while( pmd )
    {
        if (pmd->uri_buffer == HTTP_SEARCH_COOKIE)
        {
            /* Don't add cookie buffer patterns */
            pmd = pmd->next;
            continue;
        }

        /* If this content is flagged for fast pattern, use it */
        if (pmd->flags & CONTENT_FAST_PATTERN)
        {
            return pmd;
        }

        if(pmd->pattern_buf && !pmd->exception_flag ) 
        {
            /* Track longest filtered pattern length */
            size = FLP_Trim(pmd->pattern_buf, pmd->pattern_size,NULL);
            if( (size > max_size) )
            {
                pmdmax = pmd;
                max_size = size;
            }
 
             /* Track longest raw pattern length */
             if( pmd->pattern_size > max_size_raw ) 
             {
                 pmdmax_raw=pmd;
                 max_size_raw = pmd->pattern_size;
             }
        }
        pmd = pmd->next;
    }

    /* return the longest filterd pattern, if a non-zero-byte one exists */
    if( pmdmax )
        return pmdmax;
 
    /* else return the longest, even if its all zeros */
    return pmdmax_raw;
}
#endif /* DETECTION_OPTION_TREE */

#ifdef PORTLISTS 
/*
 * Original PortRuleMaps for each protocol requires creating the following structures.
 *          -pcrm.h
 *          PORT_RULE_MAP -> srcPortGroup,dstPortGroup,genericPortGroup
 *          PORT_GROUP    -> pgPatData, pgPatDataUri (acsm objects), (also rule_node lists 1/rule, not neeed)
 *                           each rule content added to an acsm object has a PMX data ptr associated with it. 
 *          RULE_NODE     -> iRuleNodeID (used for bitmap object index), otnx
 *
 *          -fpcreate.h
 *          PMX   -> RULE_NODE(->otnx), PatternMatchData
 *          OTNX  -> otn,rtn,content_length
 *
 *  PortList model supports the same structures except:
 *
 *          -pcrm.h
 *          PORT_GROUP    -> no rule_node lists needed, PortObjects maintain a list of rules used
 *
 *  Generation of PortRuleMaps and data is done differently.
 *
 *    1) Build tcp/udp/icmp/ip src and dst PORT_GROUP objects based on the PortList Objects rules.
 * 
 *    2) For each protocols PortList objects walk it's ports and assign the PORT_RULE_MAP src and dst
 *         PORT_GROUP[port] array pointers to that PortList objects PORT_GROUP.
 *
 *    Implementation:
 *      
 *    Each PortList Object will be translated into a PORT_GROUP, than pointed to by the 
 *    PORT_GROUP array in the PORT_RULE_MAP for the procotocol
 *      
 *    protocol = tcp, udp, ip, icmp - one port_rule_map for each of these protocols
 *    { create a port_rule_map
 *      dst port processing
 *          for each port-list object create a port_group object
 *          {   create a pattern match object, store its pointer in port_group
 *              for each rule index in port-list object
 *              {  
 *                  get the gid+sid for the index
 *                  lookup up the otn
 *                  create otnx
 *                  create pmx
 *                  create RULE_NODE, set iRuleNodeID within this port-list object
 *                  get longest content for the rule
 *                  set up otnx,pmx,RULE_NODE
 *                  add the content and pmx to the pattern match object
 *              }
 *              compile the pattern match object
 *              
 *              repeat for uri content
 *          }
 *      src port processing
 *          repeat as for dst port processing
 *    }
 *    ** bidirectional rules - these are added to both src and dst PortList objects, so they are 
 *    automatically handled during conversion to port_group objects.
 */
/*
**  Build a Pattern group for the Uri-Content rules in this group
**
**  The patterns added for each rule must be suffcient so if we find any of them
**  we proceed to fully analyze the OTN and RTN against the packet.
**
*/
/*
 *  Init a port-list based rule map
 */
static
int fpCreateInitRuleMap( PORT_RULE_MAP * prm, PortTable * src, PortTable * dst, PortObject * anyany, PortObject * nc )
{
   SFGHASH_NODE   * node; 
   PortObjectItem * poi;
   PortObject2    * po;
   int              i;
   //int            * pi;
  
   /* setup the any-any-port content port group */
   prm->prmGeneric =(PORT_GROUP*) anyany->data;
   
   /* all rules that are any any some may not be content ? */
   prm->prmNumGenericRules = anyany->rule_list->count;
     
   prm->prmNumSrcRules= 0;
   prm->prmNumDstRules= 0;
   
   prm->prmNumSrcGroups= 0;
   prm->prmNumDstGroups= 0;
      
   /* Process src PORT groups */
   if(src )
   for( node=sfghash_findfirst(src->pt_mpxo_hash);
        node;
        node=sfghash_findnext(src->pt_mpxo_hash) )
   {
        po = (PortObject2*)node->data;
  
        if( !po ) continue;
        if( !po->data ) continue;

        /* Add up the total src rules */
        prm->prmNumSrcRules  += po->rule_hash->count;
      
        /* Increment the port group count */
        prm->prmNumSrcGroups++;

        /* Add this port group to the src table at each port that uses it */
        for( poi = (PortObjectItem*)sflist_first(po->item_list);
             poi;
             poi = (PortObjectItem*)sflist_next(po->item_list) )
        {
             switch(poi->type)
             {
               case PORT_OBJECT_ANY:
                    break;
               case PORT_OBJECT_PORT:
#if 0
                 /* This test is always true since poi->lport is a 16 bit
                  * int and MAX_PORTS is 64K.  If this relationship should
                  * change, the test should be compiled back in.
                  */
                 if(  poi->lport < MAX_PORTS )
#endif
                     prm->prmSrcPort[ poi->lport ] = (PORT_GROUP*)po->data;
                 break;
               case PORT_OBJECT_RANGE:
                 for(i= poi->lport;i<= poi->hport;i++ )
                 {
                     prm->prmSrcPort[ i ] = (PORT_GROUP*)po->data;
                 }
                 break;
             }
        }
   }                                             
 
   /* process destination port groups */
   if( dst )
   for( node=sfghash_findfirst(dst->pt_mpxo_hash);
        node;
        node=sfghash_findnext(dst->pt_mpxo_hash) )
   {
        po = (PortObject2*)node->data;
  
        if( !po ) continue;
        if( !po->data ) continue;

        /* Add up the total src rules */
        prm->prmNumDstRules  += po->rule_hash->count;
      
        /* Increment the port group count */
        prm->prmNumDstGroups++;

        /* Add this port group to the src table at each port that uses it */
        for( poi = (PortObjectItem*)sflist_first(po->item_list);
             poi;
             poi = (PortObjectItem*)sflist_next(po->item_list) )
        {
             switch(poi->type)
             {
               case PORT_OBJECT_ANY:
                    break;
               case PORT_OBJECT_PORT:
#if 0
                 /* This test is always true since poi->lport is a 16 bit
                  * int and MAX_PORTS is 64K.  If this relationship should
                  * change, the test should be compiled back in.
                  */
                 if(  poi->lport < MAX_PORTS )
#endif
                     prm->prmDstPort[ poi->lport ] = (PORT_GROUP*)po->data;
                 break;
               case PORT_OBJECT_RANGE:
                 for(i= poi->lport;i<= poi->hport;i++ )
                 {
                     prm->prmDstPort[ i ] = (PORT_GROUP*)po->data;
                 }
                 break;
             }
        }
   }                                             
   
  return 0;
}
/*
 * Create and initialize the rule maps
 */
static
int fpCreateRuleMaps( rule_port_tables_t * p )
{
    prmTcpRTNX = prmNewMap();
    if(prmTcpRTNX == NULL)
        return 1;
    if( fpCreateInitRuleMap( prmTcpRTNX, p->tcp_src, p->tcp_dst, p->tcp_anyany,p->tcp_nocontent ) )
        return -1;
    
    prmUdpRTNX = prmNewMap();
    if(prmUdpRTNX == NULL)
        return -1;
    
    if( fpCreateInitRuleMap( prmUdpRTNX, p->udp_src, p->udp_dst, p->udp_anyany,p->udp_nocontent ) )
        return -1;
    
    prmIpRTNX = prmNewMap();
    if(prmIpRTNX == NULL)
        return 1;
    
    if( fpCreateInitRuleMap( prmIpRTNX, p->ip_src, p->ip_dst, p->ip_anyany, p->ip_nocontent ) )
        return -1;
    
    prmIcmpRTNX = prmNewMap();
    if(prmIcmpRTNX == NULL)
        return 1;
    
    if( fpCreateInitRuleMap( prmIcmpRTNX, p->icmp_src, p->icmp_dst, p->icmp_anyany, p->icmp_nocontent ) )
        return -1;
   
    return 0;
}

#ifdef SHUTDOWN_MEMORY_CLEANUP
static
void fpFreeRuleMaps()
{
    if (prmTcpRTNX)
    {
        free(prmTcpRTNX);
        prmTcpRTNX = NULL;
    }

    if (prmUdpRTNX)
    {
        free(prmUdpRTNX);
        prmUdpRTNX = NULL;
    }

    if (prmIpRTNX)
    {
        free(prmIpRTNX);
        prmIpRTNX = NULL;
    }

    if (prmIcmpRTNX)
    {
        free(prmIcmpRTNX);
        prmIcmpRTNX = NULL;
    }
}
#endif


/*
 *  Add the longest content in the Pattern Match Data
 *  to the mpse pattern matcher
 */
static
int fpAddLongestContent( void * mpse,
        OptTreeNode * otn, 
        int id,
        PatternMatchData * pmd )
{
    PatternMatchData * pmdmax;
    OTNX * otnx;
    PMX * pmx;
    RULE_NODE * rn;
    int    FLP_Bytes;
    char * FLP_Ptr;
        
    /* add AND content */
    if( !pmd || ! otn || ! pmd  )
        return 0;
    
    /* get longest content after trimming the zero prefix 
     * this may return a zero byte string, if there is no choice
     */
#ifdef DETECTION_OPTION_TREE
    pmdmax = FindLongestPattern( pmd, otn );  
#else
    pmdmax = FindLongestPattern( pmd );  
#endif
    if( !pmdmax )
        return 0;
   
    
    /* create ontx */
    otnx = SnortAlloc( sizeof(OTNX) );
    otnx->otn = otn;
    otnx->rtn = otn->rtn;
    otnx->content_length =  pmdmax->pattern_size;

    /* create a rule_node */
    rn = (RULE_NODE*) SnortAlloc( sizeof(RULE_NODE) ); 
    rn->iRuleNodeID = id;
    rn->rnRuleData  = otnx; 

    /* create pmx */
    pmx = (PMX*)SnortAlloc (sizeof(PMX) );
    pmx->RuleNode    = rn;
    pmx->PatternMatchData= pmdmax;

    /* trim the prefix */ 
    FLP_Bytes= FLP_Trim(pmdmax->pattern_buf,pmdmax->pattern_size,&FLP_Ptr);
 
    /* if we have a zero byte string, use the whole string */
    if( FLP_Bytes == 0 )
    {
        FLP_Bytes = pmdmax->pattern_size;
        FLP_Ptr   = pmdmax->pattern_buf;
    }
     
    mpseAddPattern( mpse,
        FLP_Ptr, 
        FLP_Bytes,  
        pmdmax->nocase,  /* NoCase: 1-NoCase, 0-Case */
        pmdmax->offset, 
        pmdmax->depth,
        pmx,
        rn->iRuleNodeID );
           
    return 0;
}
/*
 *  Add all contents in the Pattern Match Data
 *  to the mpse pattern matcher
 */
static
int fpAddAllContents( void * mpse,
        OptTreeNode * otn, 
        int id,
        PatternMatchData * pmd )
{
    OTNX * otnx;
    PMX * pmx;
    RULE_NODE * rn;
    int    FLP_Bytes;
    char * FLP_Ptr;
#ifdef DETECTION_OPTION_TREE
    OptFpList *opt_fp;
    PatternMatchData *pmd_to_check = pmd;
#endif

    if( !pmd || ! otn || ! pmd  )
        return 0;

#ifdef DETECTION_OPTION_TREE
    opt_fp = otn->opt_func;

    while (opt_fp)
    {
        if ((opt_fp->OptTestFunc == CheckANDPatternMatch) ||
            (opt_fp->OptTestFunc == CheckUriPatternMatch))
        {
            pmd = (PatternMatchData *)opt_fp->context;
            if (pmd->buffer_func != pmd_to_check->buffer_func)
            {
                opt_fp = opt_fp->next;
                continue;
            }

#else    
    while( pmd && pmd->pattern_buf )
#endif
    {

#ifdef DETECTION_OPTION_TREE
            if ((opt_fp->OptTestFunc == CheckUriPatternMatch) &&
                (pmd->uri_buffer == HTTP_SEARCH_COOKIE))
            {
                /* Don't add cookie buffer patterns */
                opt_fp = opt_fp->next;
                continue;
            }
#else    
          if (pmd->uri_buffer == HTTP_SEARCH_COOKIE)
          {
              /* Don't add cookie buffer patterns */
              pmd = pmd->next;
              continue;
          }
#endif

          /* create ontx */
          otnx = SnortAlloc( sizeof(OTNX) );
          otnx->otn = otn;
          otnx->rtn = otn->rtn;
          otnx->content_length =  pmd->pattern_size;

          /* create a rule_node */
          rn = (RULE_NODE*) SnortAlloc( sizeof(RULE_NODE) ); 
          rn->iRuleNodeID = id;
          rn->rnRuleData  = otnx; 
          
          /* create pmx */
          pmx = (PMX*)SnortAlloc (sizeof(PMX) );
          pmx->RuleNode = rn;
          pmx->PatternMatchData = pmd;

          /* Trim leading zeros for the muli-match */
          FLP_Bytes= FLP_Trim(pmd->pattern_buf,pmd->pattern_size,&FLP_Ptr);
          if( FLP_Bytes == 0 )
          {
               FLP_Bytes = pmd->pattern_size;
               FLP_Ptr   = pmd->pattern_buf;
          }
          mpseAddPattern( mpse,
                 FLP_Ptr,
                 FLP_Bytes,
                 pmd->nocase,  /* NoCase: 1-NoCase, 0-Case */
                 pmd->offset, 
                 pmd->depth,
                 pmx,
                 rn->iRuleNodeID );
          
#ifndef DETECTION_OPTION_TREE
          pmd = pmd->next;
#endif
    }
#ifdef DETECTION_OPTION_TREE
        }

        opt_fp = opt_fp->next;
    }
#endif

    return 0; 
}

/*
 *  Add the content 'type' to the mpse pattern matcher
 */
#ifdef DYNAMIC_PLUGIN
static
int fpAddDynamicContents( void * mpse,
        OptTreeNode * otn, 
        int id,
        int type  /* normal or uri */ )
{
    OTNX * otnx;
    PMX * pmx;
    RULE_NODE * rn;
    int    FLP_Bytes;
    char * FLP_Ptr;

    DynamicData      *dd;
    FPContentInfo    *fplist[PLUGIN_MAX_FPLIST_SIZE];

        /* 
        ** Add in plugin contents for fast pattern matcher  
        */     
        dd =(DynamicData*) otn->ds_list[PLUGIN_DYNAMIC];
        if( dd )
        {
            PatternMatchData * pmd;
            int n,i;
           
            /* get the array of content 'types = NORMAL or URI */
            n = dd->fastPatternContents(dd->contextData,type,fplist,PLUGIN_MAX_FPLIST_SIZE);
            
            for(i=0;i<n;i++) 
            {
                pmd = (PatternMatchData*)SnortAlloc(sizeof(PatternMatchData) );

                /* create ontx */
                otnx = SnortAlloc( sizeof(OTNX) );
                otnx->otn = otn;
                otnx->rtn = otn->rtn;
                otnx->content_length = pmd->pattern_size; /* this forces a unique otnx/rn/pmx for each pmd */

                /* create a rule_node */
                rn = (RULE_NODE*) SnortAlloc( sizeof(RULE_NODE) ); 
                rn->iRuleNodeID = id;
                rn->rnRuleData  = otnx; 
                
                pmx = (PMX*)SnortAlloc(sizeof(PMX) );
                pmx->RuleNode        = rn;
                pmx->PatternMatchData= pmd;
                
                pmd->pattern_buf = fplist[i]->content;
                pmd->pattern_size= fplist[i]->length;
                pmd->nocase      = fplist[i]->noCaseFlag;
                pmd->offset      = 0;
                pmd->depth       = 0;
                
                /* Here we will trim leading zeros for the muli-match */
                FLP_Bytes= FLP_Trim(pmd->pattern_buf,pmd->pattern_size,&FLP_Ptr);
                if( FLP_Bytes == 0 )
                {
                    FLP_Bytes = pmd->pattern_size;
                    FLP_Ptr   = pmd->pattern_buf;
                }
                
                mpseAddPattern( mpse, 
                    FLP_Ptr, 
                    FLP_Bytes,
                    pmd->nocase,  /* 1-NoCase, 0-Case */
                    pmd->offset,
                    pmd->depth,
                    pmx,  
                    rn->iRuleNodeID );
            }
        }
    return 0;
}
#endif
  
/*
 *  Content flag values
 */
enum
{
    PGCT_NOCONTENT=0,
    PGCT_CONTENT=1,
    PGCT_URICONTENT=2
};
/* 
 *  Add a rule to the proper port group RULE_NODE list
 *
 *  cflag : content flag  ( 0=no content, 1=content, 2=uri-content)
 */
static
int fpAddPortGroupRule( PORT_GROUP * pg, OptTreeNode * otn, int id,int  cflag )
{
    OTNX * otnx;
    //RULE_NODE * rn;

    /* create otnx */
    otnx = (OTNX*) SnortAlloc( sizeof(OTNX) );
    otnx->otn = otn;
    otnx->rtn = otn->rtn;
    otnx->content_length = 0; 

    /* Add the no content rule_node to the port group (NClist) */
    switch( cflag )
    {
        case PGCT_NOCONTENT:
            prmxAddPortRuleNC( pg, otnx );
        break;
        case PGCT_CONTENT:
            prmxAddPortRule( pg, otnx );
        break;
        case PGCT_URICONTENT:
            prmxAddPortRuleUri( pg, otnx );
        break;
        default:
            return -1;
        break;
    }
    return 0;
}

void fpDeletePMX(void *data)
{
    PMX *pmx = (PMX *)data;
    RULE_NODE *rn;
    OTNX *otnx;

    rn = (RULE_NODE *)pmx->RuleNode;
    otnx = (OTNX *)rn->rnRuleData;
    free(otnx);
    free(rn);
    free(pmx);
}

void fpDeletePortGroup(void *data)
{
    PORT_GROUP *pg = (PORT_GROUP *)data;
    RULE_NODE *rn, *tmpRn;
    OTNX *otnx;

    rn = pg->pgHead;
    while (rn)
    {
        tmpRn = rn->rnNext;
        otnx = (OTNX *)rn->rnRuleData;
        free(otnx);
        free(rn);
        rn = tmpRn;
    }
    pg->pgHead = NULL;

    rn = pg->pgUriHead;
    while (rn)
    {
        tmpRn = rn->rnNext;
        otnx = (OTNX *)rn->rnRuleData;
        free(otnx);
        free(rn);
        rn = tmpRn;
    }
    pg->pgUriHead = NULL;
    
    rn = pg->pgHeadNC;
    while (rn)
    {
        tmpRn = rn->rnNext;
        otnx = (OTNX *)rn->rnRuleData;
        free(otnx);
        free(rn);
        rn = tmpRn;
    }
    pg->pgHeadNC = NULL;

    mpseFree( pg->pgPatData );
    mpseFree( pg->pgPatDataUri );

    boFreeBITOP(&pg->boRuleNodeID);

#ifdef DETECTION_OPTION_TREE
    free_detection_option_root(&pg->pgNonContentTree);
#endif

    free(pg);
}

/*
 *  Create the PortGroup for these PortObject2 entitiies
 *
 *  This builds the 1st pass multi-pattern state machines for 
 *  content and uricontent based on the rules in the PortObjects
 *  hash table.
 */
static
int fpCreatePortObject2PortGroup( PortObject2 * po, PortObject2 * poaa )
{
    SFGHASH_NODE * node; 
    unsigned sid,gid;
    OptTreeNode * otn;
    PatternMatchData *pmd, *pmdor;
    PORT_GROUP * pg;
    int crules = 0;  /* content rule count */
    int urules = 0;  /* uri rule count */
    int ncrules = 0; /* no content rules */
    int id = 0;      /* for id'ing rules within this group for bitop */
    int hc;
    int huc;
    PortObject2 * pox;

    /* verify we have a port object */
    if( !po )
        return 0;

    po->data = 0;

    //TODO : 
    if( fpDetectGetDebugPrintRuleGroupBuildDetails() )
    {
       PortObject2PrintPorts( po );
    }

    /* Check if we have any rules */
    if( !po->rule_hash )
        return 0;

    /* create a port_group */
    pg = (PORT_GROUP*)SnortAlloc(sizeof(PORT_GROUP));

    /* init pattern matchers  */
    pg->pgPatData    = mpseNew( fpDetect.search_method,
                                MPSE_INCREMENT_GLOBAL_CNT,
                                fpDeletePMX
#ifdef DETECTION_OPTION_TREE
                                , free_detection_option_root
#endif
                                );
    if( !pg->pgPatData )
    {
        free(pg);
        LogMessage("mpseNew failed\n");
        return -1;
    }
    if(fpDetect.search_opt)mpseSetOpt(pg->pgPatData,1);

    pg->pgPatDataUri = mpseNew( fpDetect.search_method,
                                MPSE_INCREMENT_GLOBAL_CNT,
                                fpDeletePMX
#ifdef DETECTION_OPTION_TREE
                                , free_detection_option_root
#endif
                                );
    if( !pg->pgPatDataUri )
    {
        LogMessage("mpseNew failed\n");
        mpseFree( pg->pgPatData );
        free(pg);
        return -1;
    }
    if(fpDetect.search_opt)mpseSetOpt(pg->pgPatDataUri,1);

    /* 
    * Walk the rules in the PortObject and add to 
    * the PORT_GROUP pattern state machine
    *  and to the port group RULE_NODE lists.
    * (The lists are still used in some cases
    *  during detection to walk the rules in a group
    *  so we have to load these as well...fpEvalHeader()... for now.)
    *
    * po   src/dst ports : content/uri and nocontent  
    * poaa any-any ports : content/uri and nocontent
    *
    * each PG has src or dst contents, generic-contents, and no-contents 
    * (src/dst or any-any ports)
    * 
    */
    pox = po;

    if( !po ) pox = poaa;

    while(pox)
    {
      for( node=sfghash_findfirst(pox->rule_hash);
           node;
           node=sfghash_findnext(pox->rule_hash) )
      {
           int * prindex;

           prindex = (int*)node->data;
           if( !prindex ) 
               continue; /* be safe - no rule index, ignore it */

           /* look up sid:gid */
           sid = RuleIndexMapSid( ruleIndexMap, *prindex );
           gid = RuleIndexMapGid( ruleIndexMap, *prindex );
           
           /* look up otn */
           otn =  otn_lookup(  gid, sid );
           if( !otn )
           {
             LogMessage("fpCreatePortObject2PortGroup...failed otn lookup, gid=%u sid=%u\n",gid,sid);
             continue;
           }

           if (otn->sigInfo.rule_type != SI_RULE_TYPE_DETECT)
           {
               /* Preprocessor or decoder rule, skip inserting it */
               continue;
           }
           
           hc = huc = 0; /* track if we have content or uri content in this rule */

           /* Not enabled, don't do the FP content */
           if (otn->rule_state != RULE_STATE_ENABLED)
           {
               continue;
           }

           if( OtnHasContent(otn) )
           {
              /* get the content pattern match data */
              pmd = otn->ds_list[PLUGIN_PATTERN_MATCH];
              /* add the longest AND content... */
              if( pmd ) //&& !IsPureNotRule( pmd ) )
                  fpAddLongestContent( pg->pgPatData, otn, id, pmd );

              /* add ALL OR contents... */
              pmdor = otn->ds_list[PLUGIN_PATTERN_MATCH_OR];
              if( pmdor ) //&& !IsPureNotRule( pmdor ) ) /* ignore pure not rules */
                  fpAddAllContents( pg->pgPatData, otn, id, pmdor );

              /* add content for shared object rules */
#ifdef DYNAMIC_PLUGIN
              fpAddDynamicContents( pg->pgPatData, otn, id, FASTPATTERN_NORMAL  );
#endif
              hc++;
              crules++;
              /* Add the rule to the port groups content RULE_NODE lists */
              fpAddPortGroupRule(pg,otn,id,PGCT_CONTENT);
           }
           
           if( OtnHasUriContent(otn) )
           {
              /* get the uri content pattern match data */
              pmd = otn->ds_list[PLUGIN_PATTERN_MATCH_URI];
              /* add ALL AND contents for HTTP... */
              if( pmd ) //&& !IsPureNotRule( pmd ) )/* ignore pure not rules */
                  fpAddAllContents( pg->pgPatDataUri, otn, id, pmd );

              /* add uri content for shared object rules */
#ifdef DYNAMIC_PLUGIN
              fpAddDynamicContents( pg->pgPatDataUri, otn, id, FASTPATTERN_URI  );
#endif
              huc++;
              urules++;
              /* Add the rule to the port groups uricontent RULE_NODE lists */
              fpAddPortGroupRule(pg,otn,id,PGCT_URICONTENT);
           }

           if( !hc && !huc )
           { 
             /* no content for this rule  - add into this port groups no-content rule list */ 
             fpAddPortGroupRule(pg,otn,id,PGCT_NOCONTENT);
             ncrules++; 
           }
           
           id++; /* inc rule node id, used for bitmap indexing */
        }

        if( fpDetectGetDebugPrintRuleGroupBuildDetails() )
             LogMessage("PortGroup Summary: CONTENT: %d, URICONTENT: %d,"
                        " NOCONTENT: %d\n", crules,urules,ncrules);
      
        if( pox == poaa ) break; 
      
        pox = poaa;
    }
  
   /*
   **  Initialize the BITOP structure for this
   **  port group.
   */
   if( pg->pgContentCount &&  boInitBITOP(&(pg->boRuleNodeID),pg->pgContentCount) )
   {
       LogMessage("boInitBITOP failed, content count=%d\n",pg->pgContentCount);
       mpseFree( pg->pgPatData );
       mpseFree( pg->pgPatDataUri );
       free(pg);
       return -1;
   }

   /* Compile the Content Pattern Machine */
   if( crules )
   {
      mpsePrepPatterns( pg->pgPatData 
#ifdef DETECTION_OPTION_TREE
                      , pmx_create_tree
#endif
                      );
      if( fpDetect.debug ) mpsePrintInfo( pg->pgPatData );
   }
   else
   { 
      mpseFree( pg->pgPatData );
      pg->pgPatData = NULL;
   }
   
   /* Compile the UriContent Pattern Machine */
   if( urules )
   {
      mpsePrepPatterns( pg->pgPatDataUri
#ifdef DETECTION_OPTION_TREE
                      , pmx_create_tree
#endif
                      );
      if( fpDetect.debug ) mpsePrintInfo( pg->pgPatDataUri );
   }
   else
   {
      /* release  the pattern matcher */
      mpseFree( pg->pgPatDataUri );
      pg->pgPatDataUri = NULL;
   }
   
#ifdef DETECTION_OPTION_TREE
   if (ncrules)
   {
       RULE_NODE *ruleNode;
       
       for (ruleNode = pg->pgHeadNC; ruleNode; ruleNode = ruleNode->rnNext)
       {
           OTNX *otnx = (OTNX *)ruleNode->rnRuleData;
           otn_create_tree(otnx->otn, &pg->pgNonContentTree);
       }
       finalize_detection_option_tree((detection_option_tree_root_t*)pg->pgNonContentTree);
       num_nc_trees++;
   }
#endif

   /* Assign the port_group */
   if( urules || crules  || ncrules )
   {
      po->data = pg;
      po->data_free = fpDeletePortGroup;
   }
   else
   {
      free( pg ); /* no rules...mmm, clean it up */
   }
  
   return 0;
}

/*
 *  Create the port groups for this port table
 */
static
int fpCreatePortTablePortGroups( PortTable * p, PortObject2 * poaa )
{
   SFGHASH_NODE * node; 
   int cnt=1;
   
   if( fpDetectGetDebugPrintRuleGroupBuildDetails() )
     LogMessage("%d Port Groups in Port Table\n",p->pt_mpo_hash->count);
   
   for( node=sfghash_findfirst(p->pt_mpo_hash);  //p->pt_mpxo_hash
        node;
        node=sfghash_findnext(p->pt_mpo_hash) ) //p->pt->mpxo_hash
   {
        PortObject2 * po;

        po = (PortObject2*)node->data;
        if( !po ) 
            continue;
   
        if( fpDetectGetDebugPrintRuleGroupBuildDetails() )
          LogMessage("Creating Port Group Object %d of %d\n",cnt++,p->pt_mpo_hash->count);

        /* 
        * if the object is not referenced, don't add it to the PORT_GROUPs 
        * as it may overwrite other objects that are more inclusive.
        */
        if( !po->port_cnt ) 
            continue;

        if( fpCreatePortObject2PortGroup( po, poaa ) )
        {
            LogMessage("fpCreatePortObject2PortGroup() failed\n");
            return -1;
        }

        if( fpDetectGetDebugPrintRuleGroupBuildDetails() )
            mpsePrintSummary(); //PORTLISTS-testing
   }                                             
   return 0;
}
/*
 *  Create port group objects for all port tables 
 *
 *  note: any-any ports are standard PortObjects not PortObject2's so we have to 
 *  uprade them for the create port group function
 */
static
int fpCreatePortGroups( rule_port_tables_t * p )
{
    PortObject2 * po2;
   
    extern int rule_count;/* parser.c */

    if(!rule_count)
        return 0 ;
    
    /* TCP */ 
    /* convert the tcp-any-any to a PortObject2 creature */
    po2 = PortObject2Dup( p->tcp_anyany );
    if(!po2 )
        FatalError("Could not create a PortObject version 2 for tcp-any-any rules\n!");

    if( fpDetectGetDebugPrintRuleGroupBuildDetails() )
        LogMessage("\nTCP-SRC ");
    
    if( fpCreatePortTablePortGroups( p->tcp_src, po2 ) )
    {
        LogMessage("fpCreatePorTablePortGroups failed-tcp_src\n");
        return -1;
    }
    
    if( fpDetectGetDebugPrintRuleGroupBuildDetails() )
      LogMessage("\nTCP-DST ");
    
    if( fpCreatePortTablePortGroups( p->tcp_dst, po2 ) )
    {
        LogMessage("fpCreatePorTablePortGroups failed-tcp_dst\n");
        return -1;
    }
   
    if( fpDetectGetDebugPrintRuleGroupBuildDetails() )
      LogMessage("\nTCP-ANYANY ");

    if( fpCreatePortObject2PortGroup( po2, 0 ) )
    {
        LogMessage("fpCreatePorTablePortGroups failed-tcp any-any\n");
        return -1;
    }
    /* save the any-any port group */
    p->tcp_anyany->data = po2->data;
    p->tcp_anyany->data_free = fpDeletePortGroup;
    po2->data=0;
    /* release the dummy PortObject2 copy of tcp-any-any */
    //LogMessage("fpcreate: calling PortObjectFree2(po2), line = %d\n",__LINE__ );
    PortObject2Free( po2 );

    /* UDP */ 
    po2 = PortObject2Dup( p->udp_anyany );
    if(!po2 )
        FatalError("Could not create a PortObject version 2 for udp-any-any rules\n!");
    
    if( fpDetectGetDebugPrintRuleGroupBuildDetails() )
    LogMessage("\nUDP-SRC ");
    
    if( fpCreatePortTablePortGroups( p->udp_src, po2 ) )
    {
        LogMessage("fpCreatePorTablePortGroups failed-udp_src\n");
        return -1;
    }
    
    if( fpDetectGetDebugPrintRuleGroupBuildDetails() )
    LogMessage("\nUDP-DST ");
    
    if( fpCreatePortTablePortGroups( p->udp_dst, po2 ) )
    {
        LogMessage("fpCreatePorTablePortGroups failed-udp_src\n");
        return -1;
    }
    
    if( fpDetectGetDebugPrintRuleGroupBuildDetails() )
      LogMessage("\nUDP-ANYANY ");
    
    if( fpCreatePortObject2PortGroup( po2, 0 ) )
    {
        LogMessage("fpCreatePorTablePortGroups failed-udp_src\n");
        return -1;
    }
    p->udp_anyany->data = po2->data;
    p->udp_anyany->data_free = fpDeletePortGroup;
    po2->data=0;
    //LogMessage("fpcreate: calling PortObjectFree2(po2), line = %d\n",__LINE__ );
    PortObject2Free( po2 );
    
    /* ICMP */ 
    po2 = PortObject2Dup( p->icmp_anyany );
    if(!po2 )
        FatalError("Could not create a PortObject version 2 for icmp-any-any rules\n!");
    
    if( fpDetectGetDebugPrintRuleGroupBuildDetails() )
      LogMessage("\nICMP-SRC ");
    
    if( fpCreatePortTablePortGroups( p->icmp_src, po2 ) )
    {
        LogMessage("fpCreatePorTablePortGroups failed-icmp_src\n");
        return -1;
    }
    
    if( fpDetectGetDebugPrintRuleGroupBuildDetails() )
      LogMessage("\nICMP-DST ");
    
    if( fpCreatePortTablePortGroups( p->icmp_dst, po2 ) )
    {
        LogMessage("fpCreatePorTablePortGroups failed-icmp_src\n");
        return -1;
    }
    
    if( fpDetectGetDebugPrintRuleGroupBuildDetails() )
      LogMessage("\nICMP-ANYANY ");
    
    if( fpCreatePortObject2PortGroup( po2, 0 ) )
    {
        LogMessage("fpCreatePorTablePortGroups failed-icmp any-any\n");
        return -1;
    }
    p->icmp_anyany->data = po2->data;
    p->icmp_anyany->data_free = fpDeletePortGroup;
    po2->data=0;
    //LogMessage("fpcreate: calling PortObjectFree2(po2), line = %d\n",__LINE__ );
    PortObject2Free( po2 );
   
    /* IP */ 
    po2 = PortObject2Dup( p->ip_anyany );
    if(!po2 )
       FatalError("Could not create a PortObject version 2 for ip-any-any rules\n!");
    
    if( fpDetectGetDebugPrintRuleGroupBuildDetails() )
      LogMessage("\nIP-SRC ");
    
    if( fpCreatePortTablePortGroups( p->ip_src, po2 ) )
    {
        LogMessage("fpCreatePorTablePortGroups failed-ip_src\n");
        return -1;
    }
    
    if( fpDetectGetDebugPrintRuleGroupBuildDetails() )
      LogMessage("\nIP-DST ");
    
    if( fpCreatePortTablePortGroups( p->ip_dst, po2 ) )
    {
        LogMessage("fpCreatePorTablePortGroups failed-ip_dst\n");
        return -1;
    }
    
    if( fpDetectGetDebugPrintRuleGroupBuildDetails() )
      LogMessage("\nIP-ANYANY ");
    
    if( fpCreatePortObject2PortGroup( po2, 0 ) )
    {
        LogMessage("fpCreatePorTablePortGroups failed-ip any-any\n");
        return -1;
    }
    
    p->ip_anyany->data = po2->data;
    p->ip_anyany->data_free = fpDeletePortGroup;
    po2->data=0;
    //LogMessage("fpcreate: calling PortObjectFree2(po2), line = %d\n",__LINE__ );
    PortObject2Free( po2 );
    
    return 0;
}



/*
 *  Scan the master otn lists and and pass
 *  
 *  
 *  enabled - if true requires otn to be enabled
 *  fcn - callback
 *  proto - IP,TCP,IDP,ICMP protocol flag
 *  otn   - OptTreeNode
 */
int fpWalkOtns(int enabled, OtnWalkFcn fcn ) 
{
    RuleListNode *rule;
    RuleTreeNode *rtn;
    OptTreeNode * otn;

    for (rule=RuleLists; rule; rule=rule->next)
    {
        if( !rule->RuleList )
            continue;

        /* TCP */
        for(rtn = rule->RuleList->TcpList; rtn != NULL; rtn = rtn->right)
        {
            for( otn = rtn->down; otn; otn=otn->next )
            {
              if ( enabled && (otn->rule_state != RULE_STATE_ENABLED) )
                 continue;

               fcn( IPPROTO_TCP, rtn,otn );
            }
        }
        
        /* UDP */
        for(rtn = rule->RuleList->UdpList; rtn != NULL; rtn = rtn->right)
        {
                for( otn = rtn->down; otn; otn=otn->next )
                {
                    if ( enabled && (otn->rule_state != RULE_STATE_ENABLED) )
                        continue;

                    fcn( IPPROTO_UDP, rtn,otn );
                }
        }

        /* ICMP */
        for(rtn = rule->RuleList->IcmpList; rtn != NULL; rtn = rtn->right)
        {
                for( otn = rtn->down; otn; otn=otn->next )
                {
                    if ( enabled && (otn->rule_state != RULE_STATE_ENABLED) )
                        continue;

                    fcn( IPPROTO_ICMP, rtn,otn );
                }
        }

        /* IP */
        for(rtn = rule->RuleList->IpList; rtn != NULL; rtn = rtn->right)
        {
                for( otn = rtn->down; otn; otn=otn->next )
                {
                    if ( enabled && (otn->rule_state != RULE_STATE_ENABLED) )
                        continue;

                    fcn( ETHERNET_TYPE_IP, rtn, otn );
                }
        }
    }
    return 0;
}

#ifdef TARGET_BASED
/*
 *  Scan the master otn lists and load the Service maps
 *  for service based rule grouping.
 */
int fpCreateServiceMaps() 
{
    RuleListNode *rule;
    RuleTreeNode *rtn;
    OptTreeNode * otn;

    for (rule=RuleLists; rule; rule=rule->next)
    {
        if( !rule->RuleList )
            continue;

        /* TCP */
        for(rtn = rule->RuleList->TcpList; rtn != NULL; rtn = rtn->right)
        {
                for( otn = rtn->down; otn; otn=otn->next )
                {
                    /* Non-content preprocessor or decoder rule.
                     * don't add it */
                    if (otn->sigInfo.rule_type != SI_RULE_TYPE_DETECT)
                    {
                        continue;
                    }
                    /* Not enabled, don't do the FP content */
                    if (otn->rule_state != RULE_STATE_ENABLED)
                        continue;

                    if( srvcmap_add_otn( IPPROTO_TCP, otn->sigInfo.service, otn ) )
                        return -1;
                }
        }
        /* UDP */
        for(rtn = rule->RuleList->UdpList; rtn != NULL; rtn = rtn->right)
        {
                for( otn = rtn->down; otn; otn=otn->next )
                {
                    /* Non-content preprocessor or decoder rule.
                     * don't add it */
                    if (otn->sigInfo.rule_type != SI_RULE_TYPE_DETECT)
                    {
                        continue;
                    }

                    /* Not enabled, don't do the FP content */
                    if (otn->rule_state != RULE_STATE_ENABLED)
                        continue;

                    if( srvcmap_add_otn( IPPROTO_UDP, otn->sigInfo.service, otn ) )
                        return -1;
                }
        }
        /* ICMP */
        for(rtn = rule->RuleList->IcmpList; rtn != NULL; rtn = rtn->right)
        {
                for( otn = rtn->down; otn; otn=otn->next )
                {
                    /* Non-content preprocessor or decoder rule.
                     * don't add it */
                    if (otn->sigInfo.rule_type != SI_RULE_TYPE_DETECT)
                    {
                        continue;
                    }

                    /* Not enabled, don't do the FP content */
                    if (otn->rule_state != RULE_STATE_ENABLED)
                        continue;

                    if( srvcmap_add_otn( IPPROTO_ICMP, otn->sigInfo.service, otn ) )
                        return -1;
                }
        }
        /* IP */
        for(rtn = rule->RuleList->IpList; rtn != NULL; rtn = rtn->right)
        {
                for( otn = rtn->down; otn; otn=otn->next )
                {
                    /* Non-content preprocessor or decoder rule.
                     * don't add it */
                    if (otn->sigInfo.rule_type != SI_RULE_TYPE_DETECT)
                    {
                        continue;
                    }

                    /* Not enabled, don't do the FP content */
                    if (otn->rule_state != RULE_STATE_ENABLED)
                        continue;

                    if( srvcmap_add_otn( ETHERNET_TYPE_IP, otn->sigInfo.service, otn ) )
                        return -1;
                }
        }
    }

    

    return 0;
}




/*
* Build a Port Group for this service based on the list of otns. The final 
* port_group pointer is stored using the service name as the key.
* 
* p   - hash table mapping services to port_groups
* srvc- service name, key used to store the port_group
*       ...could use a service id instead (bytes, fixed length,etc...)
* list- list of otns for this service
*/
void fpBuildServicePortGroupByServiceOtnList( SFGHASH * p, char * srvc, SF_LIST * list )
{
   OptTreeNode * otn;
   //SFGHASH_NODE * node;
   //unsigned sid,gid;
   PatternMatchData *pmd, *pmdor;
   PORT_GROUP * pg;
   int crules=0;  /* content rule count */
   int urules=0;  /* uri rule count */
   int ncrules=0; /* no content rules */
   int id=0;      /* for id'ing rules within this group for bitop */
   int hc;
   int huc;
   
   /* create a port_group */
   pg = (PORT_GROUP*)SnortAlloc(sizeof(PORT_GROUP));
   
   /* init content pattern matcher */
   pg->pgPatData    = mpseNew( fpDetect.search_method,
                               MPSE_INCREMENT_GLOBAL_CNT,
                               fpDeletePMX
#ifdef DETECTION_OPTION_TREE
                               , free_detection_option_root
#endif
                               );
   if( !pg->pgPatData )
   {
       FatalError("mpseNew failed\n");
   }
   if(fpDetect.search_opt)mpseSetOpt(pg->pgPatData,1);
  
   /* init uri pattern matcher */
   pg->pgPatDataUri = mpseNew( fpDetect.search_method,
                               MPSE_INCREMENT_GLOBAL_CNT,
                               fpDeletePMX
#ifdef DETECTION_OPTION_TREE
                               , free_detection_option_root
#endif
                               );
   if( !pg->pgPatDataUri )
   {
       FatalError("mpseNew failed\n");
   }
   if(fpDetect.search_opt)mpseSetOpt(pg->pgPatDataUri,1);

   /* 
    * add each rule to the port group pattern matchers, 
    * or to the no-content rule list 
    */
   for( otn = sflist_first(list);
        otn; 
        otn = sflist_next(list) )
   {
        hc = huc = 0; /* track if we have content or uri content in this rule */

        /* Not enabled, don't do the FP content */
        if (otn->rule_state != RULE_STATE_ENABLED)
        {
            continue;
        }

        if( OtnHasContent(otn) )
        {
           /* get the content pattern match data */
           pmd = otn->ds_list[PLUGIN_PATTERN_MATCH];

           /* add the longest AND content... */
           if( pmd ) //&& !IsPureNotRule( pmd ) )
               fpAddLongestContent( pg->pgPatData, otn, id, pmd );

           /* add ALL OR contents... */
           pmdor = otn->ds_list[PLUGIN_PATTERN_MATCH_OR];

           if( pmdor ) //&& !IsPureNotRule( pmdor ) ) /* ignore pure not rules */
               fpAddAllContents( pg->pgPatData, otn, id, pmdor );

           /* add content for shared object rules */
#ifdef DYNAMIC_PLUGIN
           fpAddDynamicContents( pg->pgPatData, otn, id, FASTPATTERN_NORMAL  );
#endif
           hc++;

           crules++;

           /* Add the rule to the port groups content RULE_NODE lists */
           fpAddPortGroupRule(pg,otn,id,PGCT_CONTENT);
        }
     
        if( OtnHasUriContent(otn) )
        {
           /* get the uri content pattern match data */
           pmd = otn->ds_list[PLUGIN_PATTERN_MATCH_URI];
        
           /* add ALL AND contents for HTTP... */
#ifdef DETECTION_OPTION_TREE
           if( pmd && !IsPureNotRule( pmd, otn ) )/* ignore pure not rules */
               fpAddAllContents( pg->pgPatDataUri, otn, id, pmd );
#else
           if( pmd && !IsPureNotRule( pmd ) )/* ignore pure not rules */
               fpAddAllContents( pg->pgPatDataUri, otn, id, pmd );
#endif

           /* add uri content for shared object rules */
#ifdef DYNAMIC_PLUGIN
           fpAddDynamicContents( pg->pgPatDataUri, otn, id, FASTPATTERN_URI  );
#endif
           huc++;

           urules++;
           
           /* Add the rule to the port groups uricontent RULE_NODE lists */
           fpAddPortGroupRule(pg,otn,id,PGCT_URICONTENT);
        }

        if( !hc && !huc )
        { 
          /* no content for this rule  - add into this port groups no-content rule list */ 
          fpAddPortGroupRule(pg,otn,id,PGCT_NOCONTENT);
            
          ncrules++; 
        }
        
        id++; /* inc rule node id, used for bitmap indexing */
   }
   
   /*
   **  Initialize the BITOP structure for this
   **  port group.
   */
   if( pg->pgContentCount &&  boInitBITOP(&(pg->boRuleNodeID),pg->pgContentCount) )
   {
       FatalError("boInitBITOP failed, content count=%d\n",pg->pgContentCount);
   }

   /* Compile the Content Pattern Machine */
   if( crules )
   {
      mpsePrepPatterns( pg->pgPatData
#ifdef DETECTION_OPTION_TREE
                      , pmx_create_tree
#endif
                      );
      if( fpDetect.debug ) mpsePrintInfo( pg->pgPatData );
   }
   else
   { 
      mpseFree( pg->pgPatData );
      pg->pgPatData = NULL;
   }
   
   /* Compile the UriContent Pattern Machine */
   if( urules )
   {
      mpsePrepPatterns( pg->pgPatDataUri
#ifdef DETECTION_OPTION_TREE
                      , pmx_create_tree
#endif
                      );
      if( fpDetect.debug ) mpsePrintInfo( pg->pgPatDataUri );
   }
   else
   {
      /* release  the pattern matcher */
      mpseFree( pg->pgPatDataUri );
      pg->pgPatDataUri = NULL;
   }

#ifdef DETECTION_OPTION_TREE
   if (ncrules)
   {
       RULE_NODE *ruleNode;
       
       for (ruleNode = pg->pgHeadNC; ruleNode; ruleNode = ruleNode->rnNext)
       {
           OTNX *otnx = (OTNX *)ruleNode->rnRuleData;
           otn_create_tree(otnx->otn, &pg->pgNonContentTree);
       }
       finalize_detection_option_tree((detection_option_tree_root_t*)pg->pgNonContentTree);
       num_nc_trees++;
   }
#endif

   /* Assign the port_group if we have content, uri-content, or even just  no-content rules */
   if( urules || crules || ncrules )
   {
      /* Add the port_group using it's service name */
      sfghash_add( p, srvc, pg );
   }
   else
   {
      free( pg ); /* no rules of any kind..mmm, clean it up */
   }
}

/*
 * For each service we create a PORT_GROUP based on the otn's defined to 
 * be applicable to that service by the metadata option.
 *
 * Than we lookup the protocol/srvc oridinal in the target-based area
 * and assign the PORT_GROUP for the srvc to it.
 * 
 * spg - service port group (lookup should be by service id/tag)
 *     - this table maintains a port_group ptr for each service
 * srm - service rule map table (lookup by ascii service name)
 *     - this table maintains a sf_list ptr (list of rule otns) for each service
 *
 */
void fpBuildServicePortGroups( SFGHASH * spg,  PORT_GROUP **sopg, SFGHASH * srm )  
{
    SFGHASH_NODE * n;
    char * srvc;
    SF_LIST * list;
    PORT_GROUP * pg;
    
    for(n=sfghash_findfirst(srm);
        n;
        n=sfghash_findnext(srm) )
    {
        list = (SF_LIST *)n->data;
        if(!list)continue;
        
        srvc = n->key;
        if(!srvc)continue;
        
        fpBuildServicePortGroupByServiceOtnList( spg, srvc, list );

        /* Add this PORT_GROUP to the protocol-ordinal -> port_group table */
        pg = sfghash_find( spg, srvc );
        if( pg )
        {
           int16_t id;
           id = FindProtocolReference(srvc);
           if(id==SFTARGET_UNKNOWN_PROTOCOL)
           {
               id = AddProtocolReference(srvc);
               if(id <=0 )
               {
                   FatalError("Could not AddProtocolReference!\n");
               }
               if( id >= MAX_PROTOCOL_ORDINAL )
               {
                 LogMessage("fpBuildServicePortGroups: protocol-ordinal=%d exceeds limit of %d for service=%s\n",id,MAX_PROTOCOL_ORDINAL,srvc);
               }
           }
           else if( id > 0 )
           {
             if( id < MAX_PROTOCOL_ORDINAL )
             {
               sopg[ id ] = pg;
               LogMessage("fpBuildServicePortGroups: adding protocol-ordinal=%d as service=%s\n",id,srvc);
             }
             else
             {
               LogMessage("fpBuildServicePortGroups: protocol-ordinal=%d exceeds limit of %d for service=%s\n",id,MAX_PROTOCOL_ORDINAL,srvc);
             }
           }
           else /* id < 0 */
           {
             LogMessage("fpBuildServicePortGroups: adding protocol-ordinal=%d for service=%s, can't use that !!!\n",id,srvc);
               
           }
        }
        else
        {
           LogMessage("*** fpBuildServicePortGroups: failed to create and find a port group for '%s' !!! \n",srvc );
        }
    }
}

/*
 * For each proto+dir+service build a PORT_GROUP  
 */
int fpCreateServiceMapPortGroups() 
{
  spgmm_init();
  sopg_init();

  fpBuildServicePortGroups( spgmmTable.tcp_to_srv,  sopgTable.tcp_to_srv, srmmTable.tcp_to_srv );
  fpBuildServicePortGroups( spgmmTable.tcp_to_cli,  sopgTable.tcp_to_cli,  srmmTable.tcp_to_cli );
  
  fpBuildServicePortGroups( spgmmTable.udp_to_srv,  sopgTable.udp_to_srv, srmmTable.udp_to_srv );
  fpBuildServicePortGroups( spgmmTable.udp_to_cli,  sopgTable.udp_to_cli, srmmTable.udp_to_cli );

  fpBuildServicePortGroups( spgmmTable.icmp_to_srv, sopgTable.icmp_to_srv, srmmTable.icmp_to_srv );
  fpBuildServicePortGroups( spgmmTable.icmp_to_cli, sopgTable.icmp_to_cli, srmmTable.icmp_to_cli );

  fpBuildServicePortGroups( spgmmTable.ip_to_srv,   sopgTable.ip_to_srv, srmmTable.ip_to_srv );
  fpBuildServicePortGroups( spgmmTable.ip_to_cli,   sopgTable.ip_to_srv, srmmTable.ip_to_cli );

  return 0;
}

PORT_GROUP * fpGetServicePortGroupByOrdinal( int proto, int dir, int16_t proto_ordinal )
{
   //SFGHASH_NODE * n;
   PORT_GROUP   * pg; 

   if( proto_ordinal >= MAX_PROTOCOL_ORDINAL)
       return (PORT_GROUP*)0;
   
   switch( proto )
   {
       case IPPROTO_TCP: 
           if( dir == TO_SERVER ) /* to srv */
             pg =  sopgTable.tcp_to_srv[ proto_ordinal ] ;
           else
             pg =  sopgTable.tcp_to_cli[ proto_ordinal ] ;
           break;

       case IPPROTO_UDP: 
           if( dir == TO_SERVER ) /* to srv */
             pg =  sopgTable.udp_to_srv[ proto_ordinal ] ;
           else
             pg =  sopgTable.udp_to_cli[ proto_ordinal ] ;
           break;
           
       case IPPROTO_ICMP: 
           if( dir == TO_SERVER ) /* to srv */
             pg =  sopgTable.icmp_to_srv[ proto_ordinal ] ;
           else
             pg =  sopgTable.icmp_to_cli[ proto_ordinal ] ;
           break;
           
       case ETHERNET_TYPE_IP: 
           if( dir == TO_SERVER ) /* to srv */
             pg =  sopgTable.ip_to_srv[ proto_ordinal ] ;
           else
             pg =  sopgTable.ip_to_cli[ proto_ordinal ] ;
           break;

       default:
             pg = (PORT_GROUP*)0;
   }

   return pg;
}


/*
 *  Print the rule gid:sid based onm the otn list
 */
void fpPrintRuleList( SF_LIST * list )
{
    OptTreeNode * otn;
    
    for( otn=(OptTreeNode*)sflist_first(list);
         otn;
         otn=(OptTreeNode*)sflist_next(list) )
    {
         LogMessage("|   %u:%u\n",otn->sigInfo.generator,otn->sigInfo.id);
    }
}
static
void fpPrintServiceRuleMapTable(  SFGHASH * p, char * msg )
{
     SFGHASH_NODE * n;

     if( !p || !p->count ) 
         return;

     LogMessage("| Protocol [%s] %d services\n",msg,p->count );
     LogMessage("----------------------------------------------------\n");
     
     for( n = sfghash_findfirst(p);
          n;
          n = sfghash_findnext(p) )
     {
          SF_LIST * list;
          
          list = (SF_LIST*)n->data;
          if( !list ) continue;

          if( !n->key ) continue;

          LogMessage("| Service [%s] %d rules, rule list follows as gid:sid.\n",n->key,list->count);
          
          fpPrintRuleList( list );
     }
     LogMessage("----------------------------------------------------\n");
}
void fpPrintServiceRuleMaps()
{
    LogMessage("+---------------------------------------------------\n");
    LogMessage("| Service Rule Maps\n");
    LogMessage("----------------------------------------------------\n");
    fpPrintServiceRuleMapTable( srmmTable.tcp_to_srv,  "tcp to server" );
    fpPrintServiceRuleMapTable( srmmTable.tcp_to_cli,  "tcp to client" );
    
    fpPrintServiceRuleMapTable( srmmTable.udp_to_srv,  "udp to server" );
    fpPrintServiceRuleMapTable( srmmTable.udp_to_cli,  "udp to client" );
    
    fpPrintServiceRuleMapTable( srmmTable.icmp_to_srv, "icmp to server" );
    fpPrintServiceRuleMapTable( srmmTable.icmp_to_cli, "icmp to client" );
    
    fpPrintServiceRuleMapTable( srmmTable.ip_to_srv,   "ip to server" );
    fpPrintServiceRuleMapTable( srmmTable.ip_to_cli,   "ip to client" );
}
/*
 *
 */
void fpPrintServicePortGroupSummary()
{
      
  LogMessage("+--------------------------------\n");
  LogMessage("| Service-PortGroup Table Summary \n");
  LogMessage("---------------------------------\n");
  
  if(spgmmTable.tcp_to_srv->count)
  LogMessage("| tcp to server  : %d services\n",spgmmTable.tcp_to_srv->count);
  if(spgmmTable.tcp_to_cli->count)
  LogMessage("| tcp to cient   : %d services\n",spgmmTable.tcp_to_cli->count);

  if(spgmmTable.udp_to_srv->count)
  LogMessage("| udp to server  : %d services\n",spgmmTable.udp_to_srv->count);
  if(spgmmTable.udp_to_cli->count)
  LogMessage("| udp to cient   : %d services\n",spgmmTable.udp_to_cli->count);
  
  if(spgmmTable.icmp_to_srv->count)
  LogMessage("| icmp to server : %d services\n",spgmmTable.icmp_to_srv->count);
  if(spgmmTable.icmp_to_cli->count)
  LogMessage("| icmp to cient  : %d services\n",spgmmTable.icmp_to_cli->count);
  
  if(spgmmTable.ip_to_srv->count)
  LogMessage("| ip to server   : %d services\n",spgmmTable.ip_to_srv->count);
  if(spgmmTable.ip_to_cli->count)
  LogMessage("| ip to cient    : %d services\n",spgmmTable.ip_to_cli->count);
  LogMessage("---------------------------------\n");
}

/*
 *  Build Service based PORT_GROUPs using the rules
 *  metadata option service parameter.
 */
int fpCreateServicePortGroups()
{
    
    srvcmap_init();

    if( fpCreateServiceMaps() )
        return -1;
    
    if( fpDetectGetDebugPrintRuleGroupBuildDetails() )
        fpPrintServiceRuleMaps();
  
    if( fpCreateServiceMapPortGroups() )
        return -1;

    if( fpDetectGetDebugPrintRuleGroupBuildDetails() )
        fpPrintServicePortGroupSummary();
        
    //srvcmap_term();
    
    return 0;
}
//TARGET_BASED
#endif

/*
*  Port list version 
*
*  7/2007 - man
*
*  Build Pattern Groups for 1st pass of content searching using
*  multi-pattern search method.
*/
int fpCreateFastPacketDetection()
{
    extern int rule_count;

    if(!rule_count )
        return 0;

   /* Use PortObjects to create PORT_GROUPs */
   if( fpDetectGetDebugPrintRuleGroupBuildDetails() )
     LogMessage("Creating Port Groups....\n");
   
   if(  fpCreatePortGroups( &portTables ) )
   {
      FatalError("Could not create PortGroup objects for PortObjects\n");
   }
   
   if( fpDetectGetDebugPrintRuleGroupBuildDetails() )
     LogMessage("Port Groups Done....\n");

   /* Create rule_maps */
   if( fpDetectGetDebugPrintRuleGroupBuildDetails() )
     LogMessage("Creating Rule Maps....\n");
   
   if(  fpCreateRuleMaps( &portTables ) )
   {
      FatalError("Could not create rule maps\n");
   }
   
   if( fpDetectGetDebugPrintRuleGroupBuildDetails() )
     LogMessage("Rule Maps Done....\n");
    
   //if(!pv.quiet_flag)
   //{
   LogMessage("\n[ Port Based Pattern Matching Memory ]\n" );
   mpsePrintSummary();
   //}
   
#ifdef TARGET_BASED 
   if( fpDetectGetDebugPrintRuleGroupBuildDetails() )
     LogMessage("Creating Service Based Rule Maps....\n");
   /* 
   * Build Service based port groups - rules require service metdata 
   * i.e. 'metatdata: service [=] service-name, ... ;' 
   *
   * Also requires a service attribute for lookup ...
   */
   if( fpCreateServicePortGroups() )
   {
      FatalError("Could not create service based port groups\n");
   }
   
   if( fpDetectGetDebugPrintRuleGroupBuildDetails() )
      LogMessage("Service Based Rule Maps Done....\n");
    
   // if(!pv.quiet_flag)
   // {
   LogMessage("[ Port and Service Based Pattern Matching Memory ]\n" );
   mpsePrintSummary();
   // }
#endif 
    
   return 0;
}

#ifdef SHUTDOWN_MEMORY_CLEANUP
void fpDeleteFastPacketDetection()
{
    if (portTables.tcp_src)
        PortTableFree(portTables.tcp_src);
    if (portTables.tcp_dst)
        PortTableFree(portTables.tcp_dst);
    if (portTables.udp_src)
        PortTableFree(portTables.udp_src);
    if (portTables.udp_dst)
        PortTableFree(portTables.udp_dst);
    if (portTables.icmp_src)
        PortTableFree(portTables.icmp_src);
    if (portTables.icmp_dst)
        PortTableFree(portTables.icmp_dst);
    if (portTables.ip_src)
        PortTableFree(portTables.ip_src);
    if (portTables.ip_dst)
        PortTableFree(portTables.ip_dst);

    if (portTables.tcp_anyany)
        PortObjectFree(portTables.tcp_anyany);
    if (portTables.udp_anyany)
        PortObjectFree(portTables.udp_anyany);
    if (portTables.icmp_anyany)
        PortObjectFree(portTables.icmp_anyany);
    if (portTables.ip_anyany)
        PortObjectFree(portTables.ip_anyany);

    if (portTables.tcp_nocontent)
        PortObjectFree(portTables.tcp_nocontent);
    if (portTables.udp_nocontent)
        PortObjectFree(portTables.udp_nocontent);
    if (portTables.icmp_nocontent)
        PortObjectFree(portTables.icmp_nocontent);
    if (portTables.ip_nocontent)
        PortObjectFree(portTables.ip_nocontent);

    if (nonamePortVarTable)
    {
        PortTableFree(nonamePortVarTable);
        nonamePortVarTable = NULL;
    }
    if (portVarTable)
    {
        PortVarTableFree(portVarTable);
        portVarTable = NULL;
    }

#ifdef DETECTION_OPTION_TREE
    /* Cleanup the detection option tree */
    delete_detection_hash_table();
    delete_detection_tree_hash_table();
#endif

    fpFreeRuleMaps();

    if (ruleIndexMap)
    {
        /* This sets the map to NULL */
        RuleIndexMapFree(&ruleIndexMap);
    }
#ifdef TARGET_BASED
    srvcmap_term();
    spgmm_term();
#endif

}
#endif /* SHUTDOWN_MEMORY_CLEANUP */

/* END PORTLIST VERSION */

#else   

/* ORIGINAL - NON PORT LIST BASED VERSION */

/*
**  Build a Pattern group for the Uri-Content rules in this group
**
**  The patterns added for each rule must be suffcient so if we find any of them
**  we proceed to fully analyze the OTN and RTN against the packet.
**
*/
void BuildMultiPatGroupsUri( PORT_GROUP * pg )
{
    OptTreeNode      *otn;
    RuleTreeNode     *rtn;
    OTNX             *otnx; /* otnx->otn & otnx->rtn */
    PatternMatchData *pmd;
    RULE_NODE        *rnWalk = NULL;
    PMX              *pmx;
    void             *mpse_obj;
    int               method;
#ifdef DYNAMIC_PLUGIN
    DynamicData      *dd;
    FPContentInfo    *fplist[PLUGIN_MAX_FPLIST_SIZE];
#endif

    if(!pg || !pg->pgCount)
        return;
      
    /* test for any Content Rules */
    if( !prmGetFirstRuleUri(pg) )
        return;

    method = fpDetect.search_method;
    
    mpse_obj = mpseNew(method,
                       MPSE_INCREMENT_GLOBAL_CNT,
                       fpDeletePMX
#ifdef DETECTION_OPTION_TREE
                       , free_detection_option_root
#endif
                       );

    if( !mpse_obj ) 
        FatalError("BuildMultiPatGroupUri: mpse_obj=mpseNew");
    if(fpDetect.search_opt)mpseSetOpt(mpse_obj,1);

    /*  
    **  Save the Multi-Pattern data structure for processing Uri's in this 
    **  group later during packet analysis.  
    */
    pg->pgPatDataUri = mpse_obj;
      
    /*
    **  Initialize the BITOP structure for this
    **  port group.  This is most likely going to be initialized
    **  by the non-uri BuildMultiPattGroup.  If for some reason there
    **  is only uri contents in a port group, then we miss the initialization
    **  in the content port groups and catch it here.
    */
    if( boInitBITOP(&(pg->boRuleNodeID),pg->pgCount) )
    {
        return;
    }

    /*
    *  Add in all of the URI contents, since these are effectively OR rules.
    *  
    */
    for( rnWalk=pg->pgUriHead; rnWalk; rnWalk=rnWalk->rnNext)
    {
        otnx = (OTNX *)rnWalk->rnRuleData;

        otn = otnx->otn;
        rtn = otnx->rtn;

        /* Add all of the URI contents */     
        pmd = otn->ds_list[PLUGIN_PATTERN_MATCH_URI];
        while( pmd )
        {
            if(pmd->pattern_buf) 
            {
               pmx = (PMX*)SnortAlloc(sizeof(PMX) );
               pmx->RuleNode    = rnWalk;
               pmx->PatternMatchData= pmd;

               /*
               **  Add the max content length to this otnx
               */
               if(otnx->content_length < pmd->pattern_size)
                   otnx->content_length = pmd->pattern_size;

                mpseAddPattern(mpse_obj, pmd->pattern_buf, pmd->pattern_size,
                pmd->nocase,  /* NoCase: 1-NoCase, 0-Case */
                pmd->offset,
                pmd->depth,
                pmx, //(unsigned)rnWalk,        /* rule ptr */ 
                //(unsigned)pmd,
                rnWalk->iRuleNodeID );
            }
            
            pmd = pmd->next;
        }
#ifdef DYNAMIC_PLUGIN
        /* 
        ** 
        ** Add in plugin contents for fast pattern matcher  
        **
        **/     
        dd =(DynamicData*) otn->ds_list[PLUGIN_DYNAMIC];
        if( dd )
        {
            int n,i;
            n = dd->fastPatternContents(dd->contextData,FASTPATTERN_URI,fplist,PLUGIN_MAX_FPLIST_SIZE);
        
            for(i=0;i<n;i++) 
            {
                pmd = (PatternMatchData*)SnortAlloc(sizeof(PatternMatchData) );
            
                pmx = (PMX*)SnortAlloc(sizeof(PMX) );
            
                pmx->RuleNode        = rnWalk;
                pmx->PatternMatchData= pmd;
            
                pmd->pattern_buf = fplist[i]->content;
                pmd->pattern_size= fplist[i]->length;
                pmd->nocase      = fplist[i]->noCaseFlag;
                pmd->offset      = 0;
                pmd->depth       = 0;
            
                mpseAddPattern( mpse_obj, 
                    pmd->pattern_buf, 
                    pmd->pattern_size,
                    pmd->nocase,  /* 1--NoCase, 0-Case */
                    pmd->offset,
                    pmd->depth,
                    pmx,  
                    rnWalk->iRuleNodeID );
            }
        }
#endif
    }

    mpsePrepPatterns( mpse_obj
#ifdef DETECTION_OPTION_TREE
                      , pmx_create_tree
#endif
                      );
    if( fpDetect.debug ) mpsePrintInfo( mpse_obj );
}

/*
*  Build Content-Pattern Information for this group
*/
void BuildMultiPatGroup( PORT_GROUP * pg )
{
    OptTreeNode      *otn;
    RuleTreeNode     *rtn;
    OTNX             *otnx; /* otnx->otn & otnx->rtn */
    PatternMatchData *pmd, *pmdmax;
    RULE_NODE        *rnWalk = NULL;
    PMX              *pmx;
    void             *mpse_obj;
    /*int maxpats; */
    int               method;
#ifdef DYNAMIC_PLUGIN
    DynamicData      *dd;
    FPContentInfo    *fplist[PLUGIN_MAX_FPLIST_SIZE];
#endif
    if(!pg || !pg->pgCount)
        return;
     
    /* test for any Content Rules */
    if( !prmGetFirstRule(pg) )
        return;
      
    method = fpDetect.search_method;

    mpse_obj = mpseNew(method,
                       MPSE_INCREMENT_GLOBAL_CNT,
                       fpDeletePMX
#ifdef DETECTION_OPTION_TREE
                       , free_detection_option_root
#endif
                       );

    if(!mpse_obj) 
        FatalError("BuildMultiPatGroup: memory error, mpseNew(%d,0) failed\n",fpDetect.search_method);
    if(fpDetect.search_opt)mpseSetOpt(mpse_obj,1);

    /* Save the Multi-Pattern data structure for processing this group later 
       during packet analysis.
    */
    pg->pgPatData = mpse_obj;

    /*
    **  Initialize the BITOP structure for this
    **  port group.
    */
    if( boInitBITOP(&(pg->boRuleNodeID),pg->pgCount) )
    {
        return;
    }
      
    /*
    *  For each content rule, add one of the AND contents,
    *  and all of the OR contents
    */
    for(rnWalk=pg->pgHead; rnWalk; rnWalk=rnWalk->rnNext)
    {
        otnx = (OTNX *)(rnWalk->rnRuleData);

        otn = otnx->otn;
        rtn = otnx->rtn;

        /* Add the longest AND patterns, 'content:' patterns*/
        pmd = otn->ds_list[PLUGIN_PATTERN_MATCH];

        /*
        **  Add all the content's for the Pure Not rules, 
        **  because we will check after processing the packet
        **  to see if these pure not rules were hit using the
        **  bitop functionality.  If they were hit, then there
        **  is no event, otherwise there is an event.
        */
#ifdef DETECTION_OPTION_TREE
        if( pmd && IsPureNotRule( pmd, otn ) )
#else
        if( pmd && IsPureNotRule( pmd ) )
#endif
        {
            /*
            **  Pure Not Rules are not supported.
            */
            LogMessage("SNORT DETECTION ENGINE: Pure Not Rule "
                       "'%s' not added to detection engine.  "
                       "These rules are not supported at this "
                       "time.\n", otn->sigInfo.message);

            while( pmd ) 
            {
                if( pmd->pattern_buf ) 
                {
                    pmx = (PMX*)SnortAlloc(sizeof(PMX) );
                    pmx->RuleNode   = rnWalk;
                    pmx->PatternMatchData= pmd;

                    mpseAddPattern( mpse_obj, pmd->pattern_buf, 
                      pmd->pattern_size, 
                      pmd->nocase,  /* NoCase: 1-NoCase, 0-Case */
                      pmd->offset, 
                      pmd->depth,
                      pmx,  
                      rnWalk->iRuleNodeID );
                }

                pmd = pmd->next;
            }

            /* Build the list of pure NOT rules for this group */
            prmAddNotNode( pg, (int)rnWalk->iRuleNodeID );
        }
        else
        {
            /* Add the longest content for normal or mixed contents */
#ifdef DETECTION_OPTION_TREE
           pmdmax = FindLongestPattern( pmd, otn );  
#else
           pmdmax = FindLongestPattern( pmd );  
#endif
           if( pmdmax )
           {
               pmx = (PMX*)SnortAlloc(sizeof(PMX) );
               pmx->RuleNode    = rnWalk;
               pmx->PatternMatchData= pmdmax;

               otnx->content_length = pmdmax->pattern_size;

               mpseAddPattern( mpse_obj, pmdmax->pattern_buf, pmdmax->pattern_size,
                 pmdmax->nocase,  /* NoCase: 1-NoCase, 0-Case */
                 pmdmax->offset, 
                 pmdmax->depth,
                 pmx,  
               rnWalk->iRuleNodeID );
           }
        }

        /* Add all of the OR contents 'file-list' content */     
        pmd = otn->ds_list[PLUGIN_PATTERN_MATCH_OR];
        while( pmd )
        {
            if(pmd->pattern_buf) 
            {
                pmx = (PMX*)SnortAlloc(sizeof(PMX) );
                pmx->RuleNode    = rnWalk;
                pmx->PatternMatchData= pmd;

                mpseAddPattern( mpse_obj, pmd->pattern_buf, pmd->pattern_size,
                pmd->nocase,  /* NoCase: 1-NoCase, 0-Case */
                pmd->offset,
                pmd->depth,
                pmx, //rnWalk,        /* rule ptr */ 
                //(unsigned)pmd,
                rnWalk->iRuleNodeID );
            }

            pmd = pmd->next;
        }

#ifdef DYNAMIC_PLUGIN
        /* 
        ** 
        ** Add in plugin contents for fast pattern matcher  
        **
        */     
        dd =(DynamicData*) otn->ds_list[PLUGIN_DYNAMIC];
        if( dd )
        {
            int n,i;
            n = dd->fastPatternContents(dd->contextData,FASTPATTERN_NORMAL,fplist,PLUGIN_MAX_FPLIST_SIZE);
            
            for(i=0;i<n;i++) 
            {
                pmd = (PatternMatchData*)SnortAlloc(sizeof(PatternMatchData) );
                
                pmx = (PMX*)SnortAlloc(sizeof(PMX) );
                pmx->RuleNode        = rnWalk;
                pmx->PatternMatchData= pmd;
                
                pmd->pattern_buf = fplist[i]->content;
                pmd->pattern_size= fplist[i]->length;
                pmd->nocase      = fplist[i]->noCaseFlag;
                pmd->offset      = 0;
                pmd->depth       = 0;
                
                mpseAddPattern( mpse_obj, 
                    pmd->pattern_buf, 
                    pmd->pattern_size,
                    pmd->nocase,  /* 1--NoCase, 0-Case */
                    pmd->offset,
                    pmd->depth,
                    pmx,  
                    rnWalk->iRuleNodeID );
            }
        }
#endif
    }
    /*
    **  We don't have PrepLongPatterns here, because we've found that
    **  the minimum length for the BM shift is not fulfilled by snort's
    **  ruleset.  We may add this in later, after initial performance
    **  has been verified.
    */
    
    mpsePrepPatterns( mpse_obj
#ifdef DETECTION_OPTION_TREE
                      , pmx_create_tree
#endif
                      );
    if( fpDetect.debug ) mpsePrintInfo( mpse_obj );

}

/*
**
**  NAME
**    BuildMultiPatternGroups::
**
**  DESCRIPTION
**    This is the main function that sets up all the
**    port groups for a given PORT_RULE_MAP.  We iterate
**    through the dst and src ports building up port groups
**    where possible, and then build the generic set.
**
**  FORMAL INPUTS
**    PORT_RULE_MAP * - the port rule map to build
**
**  FORMAL OUTPUTS
**    None
**
*/
void BuildMultiPatternGroups( PORT_RULE_MAP * prm )
{
    int i;
    PORT_GROUP * pg;
     
    for(i=0;i<MAX_PORTS;i++)
    {
        
        pg = prmFindSrcRuleGroup( prm, i );
        if(pg)
        {
            if( fpDetect.debug )
                printf("---SrcRuleGroup-Port %d\n",i);
            BuildMultiPatGroup( pg );
            if( fpDetect.debug )
                printf("---SrcRuleGroup-UriPort %d\n",i);
            BuildMultiPatGroupsUri( pg );
        }

        pg = prmFindDstRuleGroup( prm, i );
        if(pg)
        {
            BuildMultiPatGroup( pg );
            if( fpDetect.debug )
                printf("---DstRuleGroup-Port %d\n",i);
            BuildMultiPatGroupsUri( pg );
            if( fpDetect.debug )
                printf("---DstRuleGroup-UriPort %d\n",i);
        }
    }

    pg = prm->prmGeneric;
     
    if( fpDetect.debug )
        printf("---GenericRuleGroup \n");
    BuildMultiPatGroup( pg );
    BuildMultiPatGroupsUri( pg );
}


/*
**
**  NAME
**    fpCreateFastPacketDetection::
**
**  DESCRIPTION
**    fpCreateFastPacketDetection initializes and creates the whole
**    FastPacket detection engine.  It reads the list of RTNs and OTNs
**    that snort creates on startup, and adds the RTN/OTN pair for a
**    rule to the appropriate PORT_GROUP.  The routine builds up
**    PORT_RULE_MAPs for TCP, UDP, ICMP, and IP.  More can easily be
**    added if necessary.
**
**    After initialization and setup, stats are printed out about the
**    different PORT_GROUPS.  
**
**  FORMAL INPUTS
**    None
**
**  FORMAL OUTPUTS
**    int - 0 is successful, other is failure.
**
*/
int fpCreateFastPacketDetection()
{
    RuleListNode *rule;
    RuleTreeNode *rtn;
    int sport;
    int dport;
    OptTreeNode * otn;
    int iBiDirectional = 0;

    int ip_non_detect_cnt=0;
    int icmp_non_detect_cnt=0;
    int tcp_non_detect_cnt=0;
    int udp_non_detect_cnt=0;
    OTNX * otnx;

    extern RuleListNode *RuleLists;

    prmTcpRTNX = prmNewMap();
    if(prmTcpRTNX == NULL)
        return 1;

    prmUdpRTNX = prmNewMap();
    if(prmUdpRTNX == NULL)
        return 1;

    prmIpRTNX = prmNewMap();
    if(prmIpRTNX == NULL)
        return 1;

    prmIcmpRTNX = prmNewMap();
    if(prmIcmpRTNX == NULL)
        return 1;

    for (rule=RuleLists; rule; rule=rule->next)
    {
        if(!rule->RuleList)
            continue;

        /*
        **  Process TCP signatures
        */
        if(rule->RuleList->TcpList)
        {
            for(rtn = rule->RuleList->TcpList; rtn != NULL; rtn = rtn->right)
            {
#ifdef LOCAL_DEBUG
                printf("** TCP\n");
                printf("** bidirectional = %s\n",
                        (rtn->flags & BIDIRECTIONAL) ? "YES" : "NO");
                printf("** not sp_flag = %d\n", rtn->not_sp_flag);
                printf("** not dp_flag = %d\n", rtn->not_dp_flag);
                printf("** hsp = %u\n", rtn->hsp);
                printf("** lsp = %u\n", rtn->lsp);
                printf("** hdp = %u\n", rtn->hdp);
                printf("** ldp = %u\n", rtn->ldp);
#endif

                /*
                **  Check for bi-directional rules
                */
                if(rtn->flags & BIDIRECTIONAL)
                {
                    iBiDirectional = 1;
                }else{
                    iBiDirectional = 0;
                }


                sport = CheckPorts(rtn->hsp, rtn->lsp);

                if( rtn->flags & ANY_SRC_PORT ) sport = -1;

                if( sport > 0 &&  rtn->not_sp_flag > 0 )
                {
                    sport = -1;
                }

                dport = CheckPorts(rtn->hdp, rtn->ldp);

                if( rtn->flags & ANY_DST_PORT ) dport = -1;

                if( dport > 0 && rtn->not_dp_flag > 0 )
                {
                    dport = -1;
                }

                /* Walk OTN list -Add as Content/UriContent, or NoContent */
                for( otn = rtn->down; otn; otn=otn->next )
                {
                    /* skip preprocessor and decode event */
                    if( otn->sigInfo.rule_type  != SI_RULE_TYPE_DETECT )
                    {
                        tcp_non_detect_cnt++;
                        continue;
                    }
                 
                    /* Not enabled, don't do the FP content */
                    if (otn->rule_state != RULE_STATE_ENABLED)
                    {
                        continue;
                    }

                    otnx = SnortAlloc( sizeof(OTNX) );

                    otnx->otn = otn;
                    otnx->rtn = rtn;
                    otnx->content_length = 0;

                    if( OtnHasContent( otn ) )
                    {
                        if(fpDetect.debug)
                        {
                            printf("TCP Content-Rule[dst=%d,src=%d] %s\n",
                                    dport,sport,otn->sigInfo.message);
                        }
                        prmAddRule(prmTcpRTNX, dport, sport, otnx);

                        if(iBiDirectional && (sport!=dport))
                        {
                            /*
                            **  We switch the ports.
                            */
                            prmAddRule(prmTcpRTNX, sport, dport, otnx);
                        }
                    }
                    if( OtnHasUriContent( otn ) )
                    {
                        if(fpDetect.debug)
                        {
                            printf("TCP UriContent-Rule[dst=%d,src=%d] %s\n",
                                    dport,sport,otn->sigInfo.message);
                        }
                        prmAddRuleUri(prmTcpRTNX, dport, sport, otnx);

                        if(iBiDirectional && (sport!=dport) )
                        {
                            /*
                            **  We switch the ports.
                            */
                            prmAddRuleUri(prmTcpRTNX, sport, dport, otnx);
                        }
                    }
                    if( !OtnHasContent( otn ) &&  !OtnHasUriContent( otn ) )
                    {
                        if(fpDetect.debug)
                        {
                            printf("TCP NoContent-Rule[dst=%d,src=%d] %s\n",
                                    dport,sport,otn->sigInfo.message);
                        }
                        prmAddRuleNC(prmTcpRTNX, dport, sport, otnx);

                        if(iBiDirectional && (sport!=dport))
                        {
                            /*
                            **  We switch the ports.
                            */
                            prmAddRuleNC(prmTcpRTNX, sport, dport, otnx);
                        }
                    }
                }
            }
        }

        /*
        **  Process UDP signatures
        */
        if(rule->RuleList->UdpList)
        {
            for(rtn = rule->RuleList->UdpList; rtn != NULL; rtn = rtn->right)
            {
#ifdef LOCAL_DEBUG
                printf("** UDP\n");
                printf("** bidirectional = %s\n",
                        (rtn->flags & BIDIRECTIONAL) ? "YES" : "NO");
                printf("** not sp_flag = %d\n", rtn->not_sp_flag);
                printf("** not dp_flag = %d\n", rtn->not_dp_flag);
                printf("** hsp = %u\n", rtn->hsp);
                printf("** lsp = %u\n", rtn->lsp);
                printf("** hdp = %u\n", rtn->hdp);
                printf("** ldp = %u\n", rtn->ldp);
#endif

                /*
                **  Check for bi-directional rules
                */
                if(rtn->flags & BIDIRECTIONAL)
                {
                    iBiDirectional = 1;
                }else{
                    iBiDirectional = 0;
                }

                sport = CheckPorts(rtn->hsp, rtn->lsp);

                if( rtn->flags & ANY_SRC_PORT ) sport = -1;

                if(sport > 0 &&  rtn->not_sp_flag > 0 )
                {
                    sport = -1;
                }

                dport = CheckPorts(rtn->hdp, rtn->ldp);

                if( rtn->flags & ANY_DST_PORT ) dport = -1;


                if(dport > 0 && rtn->not_dp_flag > 0 )
                {
                    dport = -1;
                }

                /* Walk OTN list -Add as Content, or NoContent */
                for( otn = rtn->down; otn; otn=otn->next )
                {
                    /* skip preprocessor and decode event */
                    if( otn->sigInfo.rule_type  != SI_RULE_TYPE_DETECT )
                    {
                        udp_non_detect_cnt++;
                        continue;
                    }

                    /* Not enabled, don't do the FP content */
                    if (otn->rule_state != RULE_STATE_ENABLED)
                    {
                        continue;
                    }

                    otnx = SnortAlloc( sizeof(OTNX) );

                    otnx->otn = otn;
                    otnx->rtn = rtn;
                    otnx->content_length = 0;

                    if( OtnHasContent( otn ) )
                    {
                        if(fpDetect.debug)
                        {
                            printf("UDP Content-Rule[dst=%d,src=%d] %s\n",
                                    dport,sport,otn->sigInfo.message);
                        }
                        prmAddRule(prmUdpRTNX, dport, sport, otnx);

                        /*
                        **  If rule is bi-directional we switch
                        **  the ports.
                        */
                        if(iBiDirectional && (sport!=dport))
                        {
                            prmAddRule(prmUdpRTNX, sport, dport, otnx);
                        }
                    }
                    else
                    {
                        if(fpDetect.debug)
                        {
                            printf("UDP NoContent-Rule[dst=%d,src=%d] %s\n",
                                    dport,sport,otn->sigInfo.message);
                        }
                        prmAddRuleNC(prmUdpRTNX, dport, sport, otnx);

                        /*
                        **  If rule is bi-directional we switch
                        **  the ports.
                        */
                        if(iBiDirectional && (dport != sport) )
                        {
                            prmAddRuleNC(prmUdpRTNX, sport, dport, otnx);
                        }
                    }
                }
            }
        }

        /*
        **  Process ICMP signatures
        */
        if(rule->RuleList->IcmpList)
        {
            for(rtn = rule->RuleList->IcmpList; rtn != NULL; rtn = rtn->right)
            {
               /* Walk OTN list -Add as Content, or NoContent */
                for( otn = rtn->down; otn; otn=otn->next )
                {
                    int type;
                    IcmpTypeCheckData * IcmpType;

                    /* skip preprocessor and decode event */
                    if( otn->sigInfo.rule_type  != SI_RULE_TYPE_DETECT )
                    {
                       icmp_non_detect_cnt++;
                       continue;
                    }
                    /* Not enabled, don't do the FP content */
                    if (otn->rule_state != RULE_STATE_ENABLED)
                    {
                        continue;
                    }
                    otnx = SnortAlloc( sizeof(OTNX) );

                    otnx->otn = otn;
                    otnx->rtn = rtn;
                    otnx->content_length = 0;

                    IcmpType = (IcmpTypeCheckData *)otn->ds_list[PLUGIN_ICMP_TYPE];
                    if( IcmpType && (IcmpType->operator == ICMP_TYPE_TEST_EQ) )
                    {
                        type = IcmpType->icmp_type;
                    }
                    else
                    {
                        type = -1;
                    }

                    if( OtnHasContent( otn ) )
                    {
                        if(fpDetect.debug)
                        {
                            printf("ICMP Type=%d Content-Rule  %s\n",
                                    type,otn->sigInfo.message);
                        }
                        prmAddRule(prmIcmpRTNX, type, -1, otnx);
                    }
                    else
                    {
                        if(fpDetect.debug)
                        {
                            printf("ICMP Type=%d NoContent-Rule  %s\n",
                                    type,otn->sigInfo.message);
                        }
                        prmAddRuleNC(prmIcmpRTNX, type, -1, otnx);
                    }
                }
            }
        }

        /*
        **  Process IP signatures
        **
        **  NOTE:
        **  We may want to revisit this and add IP rules for TCP and
        **  UDP into the right port groups using the rule ports, instead
        **  of just using the generic port.
        */
        if(rule->RuleList->IpList)
        {
            for(rtn = rule->RuleList->IpList; rtn != NULL; rtn = rtn->right)
            {
                /* Walk OTN list -Add as Content, or NoContent */
                for( otn=rtn->down; otn; otn=otn->next )
                {
                    IpProtoData * IpProto;
                    int protocol;

                    /* skip preprocessor and decode event */
                    if( otn->sigInfo.rule_type  != SI_RULE_TYPE_DETECT )
                    {
                        ip_non_detect_cnt++;
                        continue;
                    }
                    /* Not enabled, don't do the FP content */
                    if (otn->rule_state != RULE_STATE_ENABLED)
                    {
                        continue;
                    }
                    otnx = SnortAlloc( sizeof(OTNX) );

                    otnx->otn = otn;
                    otnx->rtn = rtn;
                    otnx->content_length = 0;

                    IpProto =  
                        (IpProtoData *)otn->ds_list[PLUGIN_IP_PROTO_CHECK] ;

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

                    if( OtnHasContent( otn ) )
                    {
                        if(fpDetect.debug)
                        {
                            printf("IP Proto=%d Content-Rule %s\n",
                                    protocol,otn->sigInfo.message);
                        }
                        prmAddRule(prmIpRTNX, protocol, -1, otnx);

                        if(protocol == IPPROTO_TCP || protocol == -1)
                        {
                            prmAddRule(prmTcpRTNX, -1, -1, otnx);
                        }
                        
                        if(protocol == IPPROTO_UDP || protocol == -1)
                        {
                            prmAddRule(prmUdpRTNX, -1, -1, otnx);
                        }

                        if(protocol == IPPROTO_ICMP || protocol == -1)
                        {
                            prmAddRule(prmIcmpRTNX, -1, -1, otnx);
                        }
                    }
                    else
                    {
                        if(fpDetect.debug)
                        {
                            printf("IP Proto=%d NoContent-Rule %s\n",
                                    protocol,otn->sigInfo.message);
                        }
                        prmAddRuleNC(prmIpRTNX, protocol, -1, otnx);

                        if(protocol == IPPROTO_TCP || protocol == -1)
                        {
                            prmAddRuleNC(prmTcpRTNX, -1, -1, otnx);
                        }
                        
                        if(protocol == IPPROTO_UDP || protocol == -1)
                        {
                            prmAddRuleNC(prmUdpRTNX, -1, -1, otnx);
                        }

                        if(protocol == IPPROTO_ICMP || protocol == -1)
                        {
                            prmAddRuleNC(prmIcmpRTNX, -1, -1, otnx);
                        }
                    }
                }
            }
        }
    }

    prmCompileGroups(prmTcpRTNX);
    prmCompileGroups(prmUdpRTNX);
    prmCompileGroups(prmIcmpRTNX);
    prmCompileGroups(prmIpRTNX);

    if(fpDetect.debug)printf("\n** TCP Rule Group Stats -- ");
    BuildMultiPatternGroups(prmTcpRTNX);
    if(fpDetect.debug)printf("\n** UDP Rule Group Stats -- ");
    BuildMultiPatternGroups(prmUdpRTNX);
    if(fpDetect.debug)printf("\n** Icmp Rule Group Stats -- ");
    BuildMultiPatternGroups(prmIcmpRTNX);
    BuildMultiPatternGroups(prmIpRTNX);

    LogMessage("Preprocessor/Decoder Rule Count: %d\n",
          ip_non_detect_cnt+icmp_non_detect_cnt+tcp_non_detect_cnt+udp_non_detect_cnt);
    if(fpDetect.debug)printf("\n** Ip Rule Group Stats -- ");
    BuildMultiPatternGroups(prmIpRTNX) ;

    if(fpDetect.debug)
    {
        printf("\n** TCP Rule Group Stats -- ");
        prmShowStats(prmTcpRTNX);
    
        printf("\n** UDP Rule Group Stats -- ");
        prmShowStats(prmUdpRTNX);
    
        printf("\n** ICMP Rule Group Stats -- ");
        prmShowStats(prmIcmpRTNX);
    
        printf("\n** IP Rule Group Stats -- ");
        prmShowStats(prmIpRTNX);
    }

    return 0;
}
#endif

/*
**  Wrapper for prmShowEventStats
*/
int fpShowEventStats()
{
    /*
    **  If not debug, then we don't print anything.
    */
    if(!fpDetect.debug)
    {
        return 1;
    }

    printf("\n** TCP Event Stats -- ");  prmShowEventStats(prmTcpRTNX);
    printf("\n** UDP Event Stats -- ");  prmShowEventStats(prmUdpRTNX);
    printf("\n** ICMP Event Stats -- "); prmShowEventStats(prmIcmpRTNX);
    printf("\n** IP Event Stats -- ");    prmShowEventStats(prmIpRTNX);
    return 0;
}

