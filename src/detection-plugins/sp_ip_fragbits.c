/* $Id$ */
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

/* Snort Detection Plugin Source File for IP Fragment Bits plugin */

/* sp_ip_fragbits 
 * 
 * Purpose:
 *
 * Check the fragmentation bits of the IP header for set values.  Possible
 * bits are don't fragment (DF), more fragments (MF), and reserved (RB).
 *
 * Arguments:
 *   
 * The keyword to reference this plugin is "fragbits".  Possible arguments are
 * D, M and R for DF, MF and RB, respectively.  
 *
 * Effect:
 *
 * Inidicates whether any of the specified bits have been set.
 *
 * Comments:
 *
 * Ofir Arkin should be a little happier now. :)
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include "rules.h"
#include "plugbase.h"
#include "decode.h"
#include "parser.h"
#include "debug.h"
#include "util.h"
#include "plugin_enum.h"



#define GREATER_THAN            1
#define LESS_THAN               2


#define FB_NORMAL   0
#define FB_ALL      1
#define FB_ANY      2
#define FB_NOT      3

#define FB_RB  0x8000
#define FB_DF  0x4000
#define FB_MF  0x2000

#include "snort.h"
#include "profiler.h"
#ifdef PERF_PROFILING
PreprocStats fragBitsPerfStats;
PreprocStats fragOffsetPerfStats;
extern PreprocStats ruleOTNEvalPerfStats;
#endif

#ifdef DETECTION_OPTION_TREE
#include "sfhashfcn.h"
#include "detection_options.h"
#endif /* DETECTION_OPTION_TREE */

typedef struct _FragBitsData
{
    char mode;
    u_int16_t frag_bits;

} FragBitsData;


typedef struct _FragOffsetData
{
    u_int8_t  comparison_flag;
    u_int8_t  not_flag;
    u_int16_t offset;
} FragOffsetData;


void FragBitsInit(char *, OptTreeNode *, int);
void ParseFragBits(char *, OptTreeNode *);
#ifdef DETECTION_OPTION_TREE
int CheckFragBits(void *option_data, Packet *p);
#else
int CheckFragBits(Packet *, struct _OptTreeNode *, OptFpList *);
#endif

/* offset checks */
void FragOffsetInit(char *, OptTreeNode *, int);
void ParseFragOffset(char *, OptTreeNode *);
#ifdef DETECTION_OPTION_TREE
int CheckFragOffset(void *option_data, Packet *p);
#else
int CheckFragOffset(Packet *, struct _OptTreeNode *, OptFpList *);
#endif

static u_int16_t bitmask;

#ifdef DETECTION_OPTION_TREE
u_int32_t IpFragBitsCheckHash(void *d)
{
    u_int32_t a,b,c;
    FragBitsData *data = (FragBitsData *)d;

    a = data->mode;
    b = data->frag_bits;
    c = RULE_OPTION_TYPE_IP_FRAGBITS;

    final(a,b,c);

    return c;
}

int IpFragBitsCheckCompare(void *l, void *r)
{
    FragBitsData *left = (FragBitsData *)l;
    FragBitsData *right = (FragBitsData *)r;

    if (!left || !right)
        return DETECTION_OPTION_NOT_EQUAL;

    if ((left->mode == right->mode) &&
        (left->frag_bits == right->frag_bits))
    {
        return DETECTION_OPTION_EQUAL;
    }

    return DETECTION_OPTION_NOT_EQUAL;
}

u_int32_t IpFragOffsetCheckHash(void *d)
{
    u_int32_t a,b,c;
    FragOffsetData *data = (FragOffsetData *)d;

    a = data->comparison_flag || (data->not_flag << 8);
    b = data->offset;
    c = RULE_OPTION_TYPE_IP_FRAG_OFFSET;

    final(a,b,c);

    return c;
}

int IpFragOffsetCheckCompare(void *l, void *r)
{
    FragOffsetData *left = (FragOffsetData *)l;
    FragOffsetData *right = (FragOffsetData *)r;

    if (!left || !right)
        return DETECTION_OPTION_NOT_EQUAL;

    if ((left->comparison_flag == right->comparison_flag) &&
        (left->not_flag == right->not_flag) &&
        (left->offset == right->offset))
    {
        return DETECTION_OPTION_EQUAL;
    }

    return DETECTION_OPTION_NOT_EQUAL;
}
#endif /* DETECTION_OPTION_TREE */

/****************************************************************************
 * 
 * Function: SetupFragBits()
 *
 * Purpose: Assign the keyword to the rules parser.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetupFragBits(void)
{
    /* map the keyword to an initialization/processing function */
    RegisterPlugin("fragbits", FragBitsInit, OPT_TYPE_DETECTION);
#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("fragbits", &fragBitsPerfStats, 3, &ruleOTNEvalPerfStats);
#endif

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: FragBits Setup\n"););
}


/****************************************************************************
 * 
 * Function: FragBitsInit(char *, OptTreeNode *)
 *
 * Purpose: Initialize the detection function and parse the arguments.
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *            protocol => protocol that must be specified to use this plugin
 *
 * Returns: void function
 *
 ****************************************************************************/
void FragBitsInit(char *data, OptTreeNode *otn, int protocol)
{
    OptFpList *fpl;
    /* multiple declaration check */ 
    if(otn->ds_list[PLUGIN_FRAG_BITS])
    {
        FatalError("%s(%d): Multiple fragbits options in rule\n", file_name,
                file_line);
    }
        
    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_FRAG_BITS] = (FragBitsData *)
            SnortAlloc(sizeof(FragBitsData));

    /* this is where the keyword arguments are processed and placed into the 
       rule option's data structure */
    ParseFragBits(data, otn);

    /* 
     * set the bitmask needed to mask off the IP offset field 
     * in the check function
     */
    bitmask = htons(0xE000);

    /* finally, attach the option's detection function to the rule's 
       detect function pointer list */
    fpl = AddOptFuncToList(CheckFragBits, otn);
#ifdef DETECTION_OPTION_TREE
    fpl->type = RULE_OPTION_TYPE_IP_FRAGBITS;
    fpl->context = otn->ds_list[PLUGIN_FRAG_BITS];
#endif
}



/****************************************************************************
 * 
 * Function: ParseFragBits(char *, OptTreeNode *)
 *
 * Purpose: This is the function that is used to process the option keyword's
 *          arguments and attach them to the rule's data structures.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
void ParseFragBits(char *data, OptTreeNode *otn)
{
    char *fptr;
    char *fend;
    FragBitsData *ds_ptr;  /* data struct pointer */
#ifdef DETECTION_OPTION_TREE
    void *ds_ptr_dup;
#endif

    /* set the ds pointer to make it easier to reference the option's
       particular data struct */
    ds_ptr = otn->ds_list[PLUGIN_FRAG_BITS];

    /* manipulate the option arguments here */
    fptr = data;

    while(isspace((u_char) *fptr))
    {
        fptr++;
    }

    if(strlen(fptr) == 0)
    {
        FatalError("[!] ERROR Line %s (%d): No arguments to the fragbits keyword\n", file_name, file_line);
    }

    fend = fptr + strlen(fptr);

    ds_ptr->mode = FB_NORMAL;  /* default value */

    while(fptr < fend)
    {
        switch((*fptr&0xFF))
        {
            case 'd':
            case 'D': /* don't frag bit */
                ds_ptr->frag_bits |= FB_DF;
                break;

            case 'm':
            case 'M': /* more frags bit */
                ds_ptr->frag_bits |= FB_MF;
                break;
                
            case 'r':
            case 'R': /* reserved bit */
                ds_ptr->frag_bits |= FB_RB;
                break;

            case '!': /* NOT flag, fire if flags are not set */
                ds_ptr->mode = FB_NOT;
                break;
                    
            case '*': /* ANY flag, fire on any of these bits */
                ds_ptr->mode = FB_ANY;
                break;
                    
            case '+': /* ALL flag, fire on these bits plus any others */
                ds_ptr->mode = FB_ALL;
                break;

            default:
                FatalError("[!] ERROR Line %s (%d): Bad Frag Bits = \"%c\"\n"
                           "     Valid options are: RDM+!*\n", file_name, 
                           file_line, *fptr);
        }
        
        fptr++;
    }
                    
    /* put the bits in network order for fast comparisons */
    ds_ptr->frag_bits = htons(ds_ptr->frag_bits);

    /* set the final option arguments here */
#ifdef DETECTION_OPTION_TREE
    if (add_detection_option(RULE_OPTION_TYPE_IP_FRAGBITS, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
    {
        free(ds_ptr);
        ds_ptr = otn->ds_list[PLUGIN_FRAG_BITS] = ds_ptr_dup;
    }
#endif /* DETECTION_OPTION_TREE */

}


/****************************************************************************
 * 
 * Function: CheckFragBits(Packet *p, OptTreeNode *otn, OptFpList *fp_list)
 *
 * Purpose: This function checks the frag bits in the packets
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: If the mask matches return true, else return 0.
 *
 ****************************************************************************/
#ifdef DETECTION_OPTION_TREE
int CheckFragBits(void *option_data, Packet *p)
{
    FragBitsData *fb = (FragBitsData *)option_data;
    int rval = DETECTION_OPTION_NO_MATCH;
    PROFILE_VARS;

    if(!IPH_IS_VALID(p))
    {
        return rval;
    }

    PREPROC_PROFILE_START(fragBitsPerfStats);
    
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "           <!!> CheckFragBits: ");
           DebugMessage(DEBUG_PLUGIN, "[rule: 0x%X:%d   pkt: 0x%X] ",
                fb->frag_bits, fb->mode, (GET_IPH_OFF(p)&bitmask)););

    switch(fb->mode)
    {
        case FB_NORMAL:
            /* check if the rule bits match the bits in the packet */
            if(fb->frag_bits == (GET_IPH_OFF(p)&bitmask)) 
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Got Normal bits match\n"););
                rval = DETECTION_OPTION_MATCH;
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Normal test failed\n"););
            }
            break;

        case FB_NOT:
            /* check if the rule bits don't match the bits in the packet */
            if((fb->frag_bits & (GET_IPH_OFF(p)&bitmask)) == 0)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Got NOT bits match\n"););
                rval = DETECTION_OPTION_MATCH;
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"NOT test failed\n"););
            }
            break;
            
        case FB_ALL:
            /* check if the rule bits are present in the packet */
            if((fb->frag_bits & (GET_IPH_OFF(p)&bitmask)) == fb->frag_bits)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Got ALL bits match\n"););
                rval = DETECTION_OPTION_MATCH;
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"ALL test failed\n"););
            }
            break;
            
        case FB_ANY:
            /* check if any of the rule bits match the bits in the packet */
            if((fb->frag_bits & (GET_IPH_OFF(p)&bitmask)) != 0)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Got ANY bits match\n"););
                rval = DETECTION_OPTION_MATCH;
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"ANY test failed\n"););
            }
            break;
        default:
            break;
    }

    /* if the test isn't successful, this function *must* return 0 */
    PREPROC_PROFILE_END(fragBitsPerfStats);
    return rval;
}
#else
int CheckFragBits(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    FragBitsData *fb;
    PROFILE_VARS;

    if(!IPH_IS_VALID(p))
    {
        return 0;
    }

    PREPROC_PROFILE_START(fragBitsPerfStats);
    
    fb = otn->ds_list[PLUGIN_FRAG_BITS];

    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "           <!!> CheckFragBits: ");
           DebugMessage(DEBUG_PLUGIN, "[rule: 0x%X:%d   pkt: 0x%X] ",
                fb->frag_bits, fb->mode, (GET_IPH_OFF(p)&bitmask)););

    switch(fb->mode)
    {
        case FB_NORMAL:
            /* check if the rule bits match the bits in the packet */
            if(fb->frag_bits == (GET_IPH_OFF(p)&bitmask)) 
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Got Normal bits match\n"););
                PREPROC_PROFILE_END(fragBitsPerfStats);
                return fp_list->next->OptTestFunc(p, otn, fp_list->next);
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Normal test failed\n"););
            }
            break;

        case FB_NOT:
            /* check if the rule bits don't match the bits in the packet */
            if((fb->frag_bits & (GET_IPH_OFF(p)&bitmask)) == 0)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Got NOT bits match\n"););
                PREPROC_PROFILE_END(fragBitsPerfStats);
                return fp_list->next->OptTestFunc(p, otn, fp_list->next);
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"NOT test failed\n"););
            }
            break;
            
        case FB_ALL:
            /* check if the rule bits are present in the packet */
            if((fb->frag_bits & (GET_IPH_OFF(p)&bitmask)) == fb->frag_bits)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Got ALL bits match\n"););
                PREPROC_PROFILE_END(fragBitsPerfStats);
                return fp_list->next->OptTestFunc(p, otn, fp_list->next);
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"ALL test failed\n"););
            }
            break;
            
        case FB_ANY:
            /* check if any of the rule bits match the bits in the packet */
            if((fb->frag_bits & (GET_IPH_OFF(p)&bitmask)) != 0)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"Got ANY bits match\n"););
                PREPROC_PROFILE_END(fragBitsPerfStats);
                return fp_list->next->OptTestFunc(p, otn, fp_list->next);
            }
            else
            {
                DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"ANY test failed\n"););
            }
            break;
    }

    /* if the test isn't successful, this function *must* return 0 */
    PREPROC_PROFILE_END(fragBitsPerfStats);
    return 0;
}
#endif


/****************************************************************************
 * 
 * Function: SetupFragOffset()
 *
 * Purpose: Assign the keyword to the rules parser.
 *
 * Arguments: None.
 *
 * Returns: void function
 *
 ****************************************************************************/
void SetupFragOffset(void)
{
    /* map the keyword to an initialization/processing function */
    RegisterPlugin("fragoffset", FragOffsetInit, OPT_TYPE_DETECTION);

#ifdef PERF_PROFILING
    RegisterPreprocessorProfile("fragoffset", &fragOffsetPerfStats, 3, &ruleOTNEvalPerfStats);
#endif
    DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN, "Plugin: FragOffset Setup\n"););
}

/****************************************************************************
 * 
 * Function: FragOffsetInit(char *, OptTreeNode *)
 *
 * Purpose: Initialize the detection function and parse the arguments.
 *
 * Arguments: data => rule arguments/data
 *            otn => pointer to the current rule option list node
 *            protocol => protocol that must be specified to use this plugin
 * 
 * Returns: void function
 *
 ****************************************************************************/
void FragOffsetInit(char *data, OptTreeNode *otn, int protocol)
{
    OptFpList *fpl;
    /* allocate the data structure and attach it to the
       rule's data struct list */
    otn->ds_list[PLUGIN_FRAG_OFFSET] = (FragOffsetData *)SnortAlloc(sizeof(FragOffsetData));

    /* this is where the keyword arguments are processed and placed into the 
       rule option's data structure */
    ParseFragOffset(data, otn);

    /* finally, attach the option's detection function to the rule's 
       detect function pointer list */
    fpl = AddOptFuncToList(CheckFragOffset, otn);
#ifdef DETECTION_OPTION_TREE
    fpl->type = RULE_OPTION_TYPE_IP_FRAG_OFFSET;
    fpl->context = otn->ds_list[PLUGIN_FRAG_OFFSET];
#endif
}


/****************************************************************************
 * 
 * Function: ParseFragOffset(char *, OptTreeNode *)
 *
 * Purpose: This is the function that is used to process the option keyword's
 *          arguments and attach them to the rule's data structures.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: void function
 *
 ****************************************************************************/
void ParseFragOffset(char *data, OptTreeNode *otn)
{
    char *fptr;

    FragOffsetData *ds_ptr;  /* data struct pointer */
#ifdef DETECTION_OPTION_TREE
    void *ds_ptr_dup;
#endif

    /* set the ds pointer to make it easier to reference the option's
       particular data struct */
    ds_ptr = otn->ds_list[PLUGIN_FRAG_OFFSET];

    /* manipulate the option arguments here */
    fptr = data;

    while(isspace((u_char) *fptr))
    {
        fptr++;
    }

    if(strlen(fptr) == 0)
    {
        FatalError("[!] ERROR Line %s (%d): No arguments to the fragoffset keyword\n", file_name, file_line);
    }

    if(*fptr == '!')
    {
        ds_ptr->not_flag = 1;
        fptr++;
    }

    if(*fptr == '>')
    {
        ds_ptr->comparison_flag = GREATER_THAN; 
        fptr++;
    }

    if(*fptr == '<')
    {
        ds_ptr->comparison_flag = LESS_THAN; 
        fptr++;
    }

    if(isdigit((int)*fptr))
    {
        ds_ptr->offset = atoi(fptr);
    } else {
        FatalError("[!] ERROR Line %s (%d): Argument to fragoffset is not a number: %s\n",
           file_name, file_line, fptr);
    }

#ifdef DETECTION_OPTION_TREE
    if (add_detection_option(RULE_OPTION_TYPE_IP_FRAG_OFFSET, (void *)ds_ptr, &ds_ptr_dup) == DETECTION_OPTION_EQUAL)
    {
        free(ds_ptr);
        ds_ptr = otn->ds_list[PLUGIN_FRAG_OFFSET] = ds_ptr_dup;
    }
#endif /* DETECTION_OPTION_TREE */

}

/****************************************************************************
 * 
 * Function: CheckFragOffset(char *, OptTreeNode *)
 *
 * Purpose: Use this function to perform the particular detection routine
 *          that this rule keyword is supposed to encompass.
 *
 * Arguments: data => argument data
 *            otn => pointer to the current rule's OTN
 *
 * Returns: If the detection test fails, this function *must* return a zero!
 *          On success, it calls the next function in the detection list 
 *
 ****************************************************************************/
#ifdef DETECTION_OPTION_TREE
int CheckFragOffset(void *option_data, Packet *p)
{
    FragOffsetData *ipd = (FragOffsetData *)option_data;
    int p_offset = p->frag_offset * 8;
    int rval = DETECTION_OPTION_NO_MATCH;
    PROFILE_VARS;
    
    if(!IPH_IS_VALID(p))
    {
        return rval;
    }

    PREPROC_PROFILE_START(fragOffsetPerfStats);

    
#ifdef DEBUG
    DebugMessage(DEBUG_PLUGIN,
         "[!] Checking fragoffset %d against %d\n",
         ipd->offset, p->frag_offset * 8);

    if(p->frag_flag)
    {
        DebugMessage(DEBUG_PLUGIN, "Frag Offset: 0x%04X   Frag Size: 0x%04X\n",
             (p->frag_offset & 0x1FFF) * 8,
             (ntohs(GET_IPH_LEN(p)) - p->frag_offset - IP_HEADER_LEN));
    }
#endif


    if(!ipd->comparison_flag)
    {
        if((ipd->offset == p_offset) ^ ipd->not_flag)
        {
            rval = DETECTION_OPTION_MATCH;
        }
        else
        {
            /* you can put debug comments here or not */
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"No match\n"););
        }
    }
    else
    {
        if(ipd->comparison_flag == GREATER_THAN)
        {
            if(p_offset > ipd->offset)
            {
                rval = DETECTION_OPTION_MATCH;
            }
        }
        else
        {
            if(p_offset < ipd->offset)
            {
                rval = DETECTION_OPTION_MATCH;
            }
        }
    }
    
    /* if the test isn't successful, this function *must* return 0 */
    PREPROC_PROFILE_END(fragOffsetPerfStats);
    return rval;
}
#else
int CheckFragOffset(Packet *p, struct _OptTreeNode *otn, OptFpList *fp_list)
{
    FragOffsetData *ipd;  /* data struct pointer */
    int p_offset = p->frag_offset * 8;
    PROFILE_VARS;
    
    if(!IPH_IS_VALID(p))
    {
        return 0;
    }

    PREPROC_PROFILE_START(fragOffsetPerfStats);

    ipd = otn->ds_list[PLUGIN_FRAG_OFFSET];

    
#ifdef DEBUG
    DebugMessage(DEBUG_PLUGIN,
         "[!] Checking fragoffset %d against %d\n",
         ipd->offset, p->frag_offset * 8);

    if(p->frag_flag)
    {
        DebugMessage(DEBUG_PLUGIN, "Frag Offset: 0x%04X   Frag Size: 0x%04X\n",
             (p->frag_offset & 0x1FFF) * 8,
             (ntohs(GET_IPH_LEN(p)) - p->frag_offset - IP_HEADER_LEN));
    }
#endif


    if(!ipd->comparison_flag)
    {
        if((ipd->offset == p_offset) ^ ipd->not_flag)
        {
            PREPROC_PROFILE_END(fragOffsetPerfStats);
            return fp_list->next->OptTestFunc(p, otn, fp_list->next);
        }
        else
        {
            /* you can put debug comments here or not */
            DEBUG_WRAP(DebugMessage(DEBUG_PLUGIN,"No match\n"););
        }
    }
    else
    {
        if(ipd->comparison_flag == GREATER_THAN)
        {
            if(p_offset > ipd->offset)
            {
                PREPROC_PROFILE_END(fragOffsetPerfStats);
                return fp_list->next->OptTestFunc(p, otn, fp_list->next);
            }
        }
        else
        {
        if(p_offset < ipd->offset)
            {
                PREPROC_PROFILE_END(fragOffsetPerfStats);
                return fp_list->next->OptTestFunc(p, otn, fp_list->next);
            }
        }
    }
    
    /* if the test isn't successful, this function *must* return 0 */
    PREPROC_PROFILE_END(fragOffsetPerfStats);
    return 0;
}
#endif
