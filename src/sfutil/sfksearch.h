/*
*   ksearch.h
*
*   Trie based multi-pattern matcher
*
*
*  Copyright (C) 2001 Marc Norton
** Copyright (C) 2003-2008 Sourcefire, Inc.
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

#ifndef KTRIE_H
#define KTRIE_H

#define ALPHABET_SIZE 256

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef WIN32
#define inline __inline
#endif

#define KTRIEMETHOD_STD 0
#define KTRIEMETHOD_QUEUE 1

/*
*
*/
typedef struct _ktriepattern {

  struct  _ktriepattern * next;  /* global list of all patterns */
  struct  _ktriepattern * mnext;  /* matching list of duplicate keywords */
  
  unsigned char * P;    /* no case */
  unsigned char * Pcase; /* case sensitive */
  int             n;
  int             nocase;
  void          * id;
#ifdef DETECTION_OPTION_TREE
  void          * rule_option_tree;
#endif

} KTRIEPATTERN;


/*
*
*/
typedef struct _ktrienode {

  int     edge; /* character */

  struct  _ktrienode * sibling; 
  struct  _ktrienode * child; 

  KTRIEPATTERN *pkeyword; 

} KTRIENODE;


#define KTRIE_ROOT_NODES     256

#define SFK_MAX_INQ 32
typedef struct 
{
    unsigned inq;
    unsigned inq_flush;
    void * q[SFK_MAX_INQ];
} SFK_PMQ;

/*
*
*/
typedef struct {

  KTRIEPATTERN * patrn; /* List of patterns, built as they are added */

  
  KTRIENODE    * root[KTRIE_ROOT_NODES];  /* KTrie nodes */
 
  int            memory;
  int            nchars;
  int            npats;
  int            duplicates;
  int            method;
  int            end_states; /* should equal npats - duplicates */

  int            bcSize;
  unsigned short bcShift[KTRIE_ROOT_NODES];  
  void           (*userfree)(void *p);
#ifdef DETECTION_OPTION_TREE
  void           (*optiontreefree)(void **p);
#endif
  SFK_PMQ        q;
 
} KTRIE_STRUCT;



KTRIE_STRUCT * KTrieNew(int method, void (*userfree)(void *p)
#ifdef DETECTION_OPTION_TREE
                        , void (*optiontreefree)(void **p)
#endif
                        );
int            KTrieAddPattern( KTRIE_STRUCT *ts, unsigned char * P, int n, int nocase,void*  id );
int            KTrieCompile(KTRIE_STRUCT * ts
#ifdef DETECTION_OPTION_TREE
             , int (*build_tree)(void * id, void **existing_tree)
#endif
);
int            KTrieSearch( KTRIE_STRUCT * ts, unsigned char * T,  int n,
#ifdef DETECTION_OPTION_TREE
               int(*match)(void * id, void *tree, int index, void *data),
#else
               int (*match)(void* id, int index,void* data),
#endif
               void *data );
unsigned int   KTrieMemUsed(void);
void           KTrieDelete(KTRIE_STRUCT *k);
int            KTriePatternCount(KTRIE_STRUCT *k);

void sfksearch_print_qinfo(void);

#endif
