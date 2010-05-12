/* $Id$ */
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
**
**/

/**
**  @file        detection_options.h
**
**  @author      Steven Sturges
** 
**  @brief       Support functions for rule option tree
**
**  This implements tree processing for rule options, evaluating common
**  detection options only once per pattern match.
**
*/

#ifndef DETECTION_OPTIONS_H_
#define DETECTION_OPTIONS_H_

#include "sf_types.h"
#include "decode.h"

typedef enum _option_type_t
{
    RULE_OPTION_TYPE_LEAF_NODE,
    RULE_OPTION_TYPE_ASN1,
    RULE_OPTION_TYPE_BYTE_TEST,
    RULE_OPTION_TYPE_BYTE_JUMP,
    RULE_OPTION_TYPE_FLOW,
    RULE_OPTION_TYPE_CVS,
    RULE_OPTION_TYPE_DSIZE,
    RULE_OPTION_TYPE_FLOWBIT,
    RULE_OPTION_TYPE_FTPBOUNCE,
    RULE_OPTION_TYPE_ICMP_CODE,
    RULE_OPTION_TYPE_ICMP_ID,
    RULE_OPTION_TYPE_ICMP_SEQ,
    RULE_OPTION_TYPE_ICMP_TYPE,
    RULE_OPTION_TYPE_IP_FRAGBITS,
    RULE_OPTION_TYPE_IP_FRAG_OFFSET,
    RULE_OPTION_TYPE_IP_ID,
    RULE_OPTION_TYPE_IP_OPTION,
    RULE_OPTION_TYPE_IP_PROTO,
    RULE_OPTION_TYPE_IP_SAME,
    RULE_OPTION_TYPE_IP_TOS,
    RULE_OPTION_TYPE_IS_DATA_AT,
    RULE_OPTION_TYPE_CONTENT,
    RULE_OPTION_TYPE_CONTENT_URI,
    RULE_OPTION_TYPE_PCRE,
#if defined(ENABLE_RESPONSE) || defined(ENABLE_REACT)
    RULE_OPTION_TYPE_REACT,
#endif
#if defined(ENABLE_RESPONSE) && !defined(ENABLE_RESPONSE2)
    RULE_OPTION_TYPE_RESPOND,
#endif
#if defined(ENABLE_RESPONSE2) && !defined(ENABLE_RESPONSE)
    RULE_OPTION_TYPE_RESPOND2,
#endif
    RULE_OPTION_TYPE_RPC_CHECK,
    RULE_OPTION_TYPE_SESSION,
    RULE_OPTION_TYPE_TCP_ACK,
    RULE_OPTION_TYPE_TCP_FLAG,
    RULE_OPTION_TYPE_TCP_SEQ,
    RULE_OPTION_TYPE_TCP_WIN,
    RULE_OPTION_TYPE_TTL,
    RULE_OPTION_TYPE_URILEN,
    RULE_OPTION_TYPE_PREPROCESSOR,
    RULE_OPTION_TYPE_DYNAMIC
} option_type_t;

#define DETECTION_OPTION_EQUAL 0
#define DETECTION_OPTION_NOT_EQUAL 1

#define DETECTION_OPTION_NO_MATCH 0
#define DETECTION_OPTION_MATCH 1
#define DETECTION_OPTION_NO_ALERT 2
#define DETECTION_OPTION_FAILED_BIT 3

#include "sfutil/sfhashfcn.h"

typedef int (*eval_func_t)(void *option_data, Packet *p);

typedef struct _detection_option_tree_node
{
    void *option_data;
    option_type_t option_type;
    eval_func_t evaluate;
    int num_children;
    struct _detection_option_tree_node **children;
    int relative_children;
    struct 
    {
        struct timeval ts;
        UINT64 packet_number;
        int pipeline_number;
        u_int32_t rebuild_flag;
        char result;
        char is_relative;
        char flowbit_failed;
        char pad; /* Keep 4 byte alignment */
    } last_check;
#ifdef PERF_PROFILING
    UINT64 ticks;
    UINT64 ticks_start;
    UINT64 ticks_match;
    UINT64 ticks_no_match;
    UINT64 checks;
    UINT64 matches;
#endif
#ifdef PPM_MGR
    UINT64 ppm_disable_cnt; /*PPM */
    UINT64 ppm_enable_cnt; /*PPM */
#endif
} detection_option_tree_node_t;

typedef struct _detection_option_tree_root
{
    int num_children;
    detection_option_tree_node_t **children;

#ifdef PPM_MGR
    UINT64 ppm_suspend_time; /* PPM */
    UINT64 ppm_disable_cnt; /*PPM */
    int tree_state; 
#endif
} detection_option_tree_root_t;

typedef struct _detection_option_eval_data
{
    void *pomd;
    void *otnx;
    void *pmd;
    Packet *p;
    char flowbit_failed;
    char flowbit_noalert;
} detection_option_eval_data_t;

int add_detection_option(option_type_t type, void *option_data, void **existing_data);
int add_detection_option_tree(detection_option_tree_node_t *option_tree, void **existing_data);
int detection_option_node_evaluate(detection_option_tree_node_t *node, detection_option_eval_data_t *eval_data);
void delete_detection_hash_table();
void delete_detection_tree_hash_table();
#ifdef DEBUG_OPTION_TREE
void print_option_tree(detection_option_tree_node_t *node, int level);
#endif
#ifdef PERF_PROFILING
void detection_option_tree_update_otn_stats();
#endif
#endif /* DETECTION_OPTIONS_H_ */

