/****************************************************************************
 *
 * Copyright (C) 2006-2008 Sourcefire, Inc.
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

/*
** ppm.h  - packet performance monitor
** 
** Author: Marc Norton <mnorton@sourcefire.com>
**
*/

#ifndef __PACKET_PROCESSING_MONITOR_H__
#define __PACKET_PROCESSING_MONITOR_H__

#ifdef PPM_MGR

#include "sf_types.h"
#include "cpuclock.h"

#define cputime get_clockticks

typedef UINT64 PPM_TICKS;
typedef UINT64 PPM_USECS;
typedef unsigned int PPM_SECS;

typedef struct {

    /* config section */
    int enabled;

    PPM_TICKS max_pkt_ticks;  
    int pkt_log;     /* alert,console,syslog */
    int pkt_action;  /* suspend */
    int debug_pkts;

    PPM_TICKS max_rule_ticks;
    int rule_threshold; /* rules must fail this many times in a row to suspend */
    int rule_log;    /* alert,console,syslog */
    int rule_action; /* suspend */
    int debug_rules;

    /* temporary flags */
    int abort_this_pkt;
    int suspend_this_rule;
    
    /* stats section */
    unsigned int rule_event_cnt;
    unsigned int pkt_event_cnt;
   
    UINT64   tot_pkt_time; /* ticks */
    UINT64   tot_pkts;     
    
    UINT64   tot_rule_time; /* ticks */
    UINT64   tot_rules;     

    UINT64   tot_nc_rule_time; /* ticks */
    UINT64   tot_nc_rules;     
    
    UINT64   tot_pcre_rule_time; /* ticks */
    UINT64   tot_pcre_rules;     
    
    UINT64   max_suspend_ticks;
} ppm_cfg_t;

typedef struct {
    UINT64   pktcnt;
    UINT64   start, cur, tot;
    UINT64   subtract;
    PPM_TICKS max_pkt_ticks;
    unsigned int rule_tests;
    unsigned int pcre_rule_tests;
    unsigned int nc_rule_tests;
}ppm_pkt_timer_t;

typedef struct {
    UINT64 start, cur, tot;
    PPM_TICKS max_rule_ticks;
}ppm_rule_timer_t;

/* global data */
#define PPM_MAX_TIMERS 10
extern PPM_TICKS ppm_tpu;
extern ppm_pkt_timer_t   ppm_pkt_times[PPM_MAX_TIMERS];
extern ppm_pkt_timer_t  *ppm_pt;
extern unsigned int      ppm_pkt_index;
extern ppm_rule_timer_t  ppm_rule_times;
extern ppm_rule_timer_t *ppm_rt;
extern ppm_cfg_t         ppm_cfg;
extern UINT64            ppm_cur_time;

#define PPM_LOG_ALERT      1
#define PPM_LOG_MESSAGE    2
#define PPM_ACTION_SUSPEND 1

/* Config flags */
#define PPM_ENABLED()                (ppm_cfg.enabled > 0)
#define PPM_PKTS_ENABLED()            (ppm_cfg.max_pkt_ticks > 0)
#define PPM_RULES_ENABLED()           (ppm_cfg.max_rule_ticks > 0)

/* packet, rule event flags */
#define PPM_PACKET_ABORT_FLAG()       ppm_cfg.abort_this_pkt
#define PPM_RULE_SUSPEND_FLAG()       ppm_cfg.suspend_this_rule

#define PPM_INC_PKT_CNT()          ppm_cfg.tot_pkts++ 
#define PPM_PKT_CNT()              ppm_pt->pktcnt 
#define PPM_PKT_LOG()              if( ppm_cfg.abort_this_pkt ) ppm_pkt_log()
#define PPM_RULE_LOG(cnt,p)      ppm_rule_log(cnt,p)
#define PPM_ACCUM_PKT_TIME()       ppm_cfg.tot_pkt_time+=ppm_pt->tot;
#define PPM_ACCUM_RULE_TIME()      ppm_cfg.tot_rule_time+=ppm_rt->tot;ppm_cfg.tot_rules++;
#define PPM_ACCUM_NC_RULE_TIME()   ppm_cfg.tot_nc_rule_time+=ppm_rt->tot;ppm_cfg.tot_nc_rules++;
#define PPM_ACCUM_PCRE_RULE_TIME()  ppm_cfg.tot_pcre_rule_time+=ppm_rt->tot;ppm_cfg.tot_pcre_rules++;
#define PPM_GET_TIME()             cputime(ppm_cur_time)
#define PPM_PKT_RULE_TESTS()       ppm_pt->rule_tests
#define PPM_PKT_PCRE_RULE_TESTS()  ppm_pt->pcre_rule_tests
#define PPM_PKT_NC_RULE_TESTS()    ppm_pt->nc_rule_tests
#define PPM_INC_PKT_RULE_TESTS()      if(ppm_pt)ppm_pt->rule_tests++
#define PPM_INC_PKT_PCRE_RULE_TESTS() if(ppm_pt)ppm_pt->pcre_rule_tests++
#define PPM_INC_PKT_NC_RULE_TESTS()   if(ppm_pt)ppm_pt->nc_rule_tests++
#define PPM_DEBUG_PKTS()           ppm_cfg.debug_pkts

#define PPM_PRINT_PKT_TIME(a)    LogMessage(a, ppm_ticks_to_usecs((PPM_TICKS)ppm_pt->tot) );

#ifdef PPM_TEST
/* use usecs instead of ticks for rule suspension during pcap playback */
#define PPM_RULE_TIME(p) ((p->pkth->ts.tv_sec * 1000000) + p->pkth->ts.tv_usec)
#else
#define PPM_RULE_TIME(p) ppm_cur_time
#endif

#define PPM_RESET_PKT_TIMER() \
          if(ppm_pt)ppm_pt->start=ppm_cur_time
          
#define PPM_INIT_PKT_TIMER() \
        if(ppm_pkt_index < PPM_MAX_TIMERS) \
        { \
          ppm_pt = &ppm_pkt_times[ppm_pkt_index++]; \
          ppm_cfg.abort_this_pkt=0; \
          ppm_pt->pktcnt=ppm_cfg.tot_pkts; \
          ppm_pt->start=ppm_cur_time; \
          ppm_pt->subtract=(UINT64)0; \
          ppm_pt->rule_tests=0; \
          ppm_pt->pcre_rule_tests=0; \
          ppm_pt->nc_rule_tests=0; \
          ppm_pt->max_pkt_ticks=ppm_cfg.max_pkt_ticks; \
          ppm_init_rules(); \
        }

#define PPM_TOTAL_PKT_TIME() \
        if( ppm_pt) \
        { \
          ppm_pt->tot = ppm_cur_time - ppm_pt->start - ppm_pt->subtract; \
        }

#define PPM_END_PKT_TIMER() \
          if( (ppm_pkt_index > 0)  && ppm_pt) \
          { \
             ppm_pkt_index--; \
             if( ppm_pkt_index > 0 ) \
             { \
               /*ppm_pkt_times[ppm_pkt_index-1].subtract=ppm_pt->tot; */ \
               ppm_pt = &ppm_pkt_times[ppm_pkt_index-1]; \
             } \
             else \
             { \
               ppm_pt=0; \
             } \
          }

#define PPM_INIT_RULE_TIMER() \
          ppm_rt = &ppm_rule_times; \
          ppm_cfg.suspend_this_rule=0; \
          ppm_rt->start=ppm_cur_time; \
          ppm_rt->max_rule_ticks=ppm_cfg.max_rule_ticks;

#define PPM_END_RULE_TIMER() \
          if( ppm_rt ) ppm_rt=NULL

/* use PPM_GET_TIME; first to get the current time */
#define PPM_PACKET_TEST() \
        if( ppm_pt ) \
        { \
          ppm_pt->tot = ppm_cur_time - ppm_pt->start /*- ppm_pt->subtract*/; \
          if(ppm_pt->tot > ppm_pt->max_pkt_ticks) \
          { \
              if( ppm_cfg.pkt_action & PPM_ACTION_SUSPEND ) \
                  ppm_cfg.abort_this_pkt=1; \
          } \
        }

#if 0 && defined(PPM_TEST)
#define PPM_DBG_CSV(state, otn, when) \
    LogMessage( \
        "PPM, %u, %u, %s, %llu\n", \
        otn->sigInfo.generator, otn->sigInfo.id, state, when \
    )
#else
#define PPM_DBG_CSV(state, otn, when)
#endif

#ifdef DETECTION_OPTION_TREE
/* use PPM_GET_TIME; first to get the current time */
#define PPM_RULE_TEST(root,p) \
        if( ppm_rt ) \
        { \
          ppm_rt->tot = ppm_cur_time - ppm_rt->start; \
          if(ppm_rt->tot > ppm_rt->max_rule_ticks) \
          { \
             if( ppm_cfg.rule_action & PPM_ACTION_SUSPEND ) \
             { \
                 int ii; \
                 ppm_cfg.suspend_this_rule=1; \
                 (root)->ppm_disable_cnt++; \
                 for ( ii = 0; ii< root->num_children; ii++) \
                 { \
                     root->children[ii]->ppm_disable_cnt++; \
                 } \
                 if( (root)->ppm_disable_cnt >= ppm_cfg.rule_threshold ) \
                 { \
                   ppm_set_rule_event(root); \
                   (root)->tree_state=RULE_STATE_DISABLED; \
                   (root)->ppm_suspend_time=PPM_RULE_TIME(p); \
                   PPM_DBG_CSV("disabled", (root), (root)->ppm_suspend_time); \
                 } \
                 else \
                 { \
                   (root)->ppm_suspend_time=0; \
                 } \
             } \
             else \
             { \
                 (root)->ppm_suspend_time=0; \
                 if( (root)->ppm_disable_cnt > 0 ) \
                     (root)->ppm_disable_cnt--; \
             } \
          } \
        }

#define PPM_REENABLE_TREE(root,p) \
        if( (root)->ppm_suspend_time && ppm_cfg.max_suspend_ticks ) \
        { \
          PPM_TICKS now = PPM_RULE_TIME(p); \
          PPM_TICKS then = (root)->ppm_suspend_time + ppm_cfg.max_suspend_ticks; \
          if( now > then ) \
          { \
              (root)->ppm_suspend_time=0; \
              (root)->tree_state=RULE_STATE_ENABLED; \
              ppm_clear_rule_event(root); \
              PPM_DBG_CSV("enabled", (root), now); \
          } \
          else \
          { \
              PPM_DBG_CSV("pending", (root), then-now); \
          } \
        }
#else
/* use PPM_GET_TIME; first to get the current time */
#define PPM_RULE_TEST(otn,p) \
        if( ppm_rt ) \
        { \
          ppm_rt->tot = ppm_cur_time - ppm_rt->start; \
          if(ppm_rt->tot > ppm_rt->max_rule_ticks) \
          { \
             if( ppm_cfg.rule_action & PPM_ACTION_SUSPEND ) \
             { \
                 ppm_cfg.suspend_this_rule=1; \
                 (otn)->ppm_disable_cnt++; \
                 if( (otn)->ppm_disable_cnt >= ppm_cfg.rule_threshold ) \
                 { \
                   ppm_set_rule_event(otn); \
                   (otn)->rule_state=RULE_STATE_DISABLED; \
                   (otn)->ppm_suspend_time=PPM_RULE_TIME(p); \
                   PPM_DBG_CSV("disabled", (otn), (otn)->ppm_suspend_time); \
                 } \
                 else \
                 { \
                   (otn)->ppm_suspend_time=0; \
                 } \
             } \
             else \
             { \
                 (otn)->ppm_suspend_time=0; \
                 if( (otn)->ppm_disable_cnt > 0 ) \
                     (otn)->ppm_disable_cnt--; \
             } \
          } \
        }

#define PPM_REENABLE_OTN(otn,p) \
        if( (otn)->ppm_suspend_time && ppm_cfg.max_suspend_ticks ) \
        { \
          PPM_TICKS now = PPM_RULE_TIME(p); \
          PPM_TICKS then = (otn)->ppm_suspend_time + ppm_cfg.max_suspend_ticks; \
          if( now > then ) \
          { \
              (otn)->ppm_suspend_time=0; \
              (otn)->rule_state=RULE_STATE_ENABLED; \
              ppm_clear_rule_event(otn); \
              PPM_DBG_CSV("enabled", (otn), now); \
          } \
          else \
          { \
              PPM_DBG_CSV("pending", (otn), then-now); \
          } \
        }
#endif

void ppm_init(void);
void ppm_set_enabled( int flag );
void ppm_set_debug_rules(int flag);
void ppm_set_debug_pkts(int flag);

void ppm_set_pkt_action( int flag );
void ppm_set_pkt_log( int flag );

void ppm_set_rule_action( int flag );
void ppm_set_rule_threshold( unsigned int cnt );
void ppm_set_rule_log( int flag );

void ppm_set_max_pkt_time( PPM_USECS );
void ppm_set_max_rule_time( PPM_USECS );
void ppm_set_max_suspend_time( PPM_SECS );

void   ppm_print_cfg(void);
void   ppm_print_summary(void);
double ppm_ticks_to_usecs( PPM_TICKS );

void ppm_pkt_log(void);
#ifdef DETECTION_OPTION_TREE
void ppm_set_rule_event (detection_option_tree_root_t *root);
void ppm_clear_rule_event (detection_option_tree_root_t *root);
#else
void ppm_set_rule_event (OptTreeNode *otn);
void ppm_clear_rule_event (OptTreeNode *otn);
#endif
void ppm_rule_log(UINT64 pktcnt,Packet * p);

void ppm_init_rules(void);
#ifdef DETECTION_OPTION_TREE
void ppm_set_rule(detection_option_tree_root_t * root , PPM_TICKS ticks);
#else
void ppm_set_rule(OptTreeNode * otn , PPM_TICKS ticks);
#endif
void ppm_print_rules(unsigned int);

#define PPM_INIT()          ppm_init()
#define PPM_PRINT_CFG()     ppm_print_cfg()
#define PPM_PRINT_SUMMARY() ppm_print_summary()

#else /* !PPM_MGR */

#define PPM_GET_TIME() 
#define PPM_SET_TIME() 


#endif /* PPM_MGR */

#endif /* __PACKET_PROCESSING_MONITOR_H__ */

