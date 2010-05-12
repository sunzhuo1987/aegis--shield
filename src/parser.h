/*             
** Copyright (C) 2002-2008 Sourcefire, Inc.
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
** Copyright (C) 2000-2001 Andrew R. Baker <andrewb@uab.edu>
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

/* $Id$ */
#ifndef __PARSER_H__
#define __PARSER_H__


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rules.h"
#include "decode.h"
#include "sflsq.h"

#include <stdio.h>

/* parsing functions */ 
#define ONE_CHECK(_onevar,xxx)                                      \
   (_onevar)++;                                                     \
   if ((_onevar) > 1)                                               \
   {                                                                \
       FatalError("%s(%d) => Only one '%s' option per rule\n",\
                       file_name, file_line, xxx);                  \
   }

/* exported values */
extern char *file_name;
extern int file_line;

/* rule setup funcs */
void ParseRulesFile(char *, int, int);
int ContinuationCheck(char *);
void ParseRule(FILE*, char *, int, int);
void ParsePreprocessor(char *);
void ParseOutputPlugin(char *);
int ParseRuleOptions(char *, int, int);
void ParseMessage(char *);
void ParseLogto(char *);
void DumpRuleChains();
struct VarEntry *VarDefine(char *, char *);
void VarDelete(char *);
void IntegrityCheckRules();
void ParseListFile(char *, char *);
void LinkDynamicRules();
void ParseActivatedBy(char *);
void ParseActivates(char *);
void ParseCount(char *);
char *VarSearch(char *name);
/* XXX: implemented in detect.c */
void CreateDefaultRules();
void OrderRuleLists(char *);
void printRuleOrder();

#define PARSE_RULE_LINES      1


int CheckRule(char *);
int RuleType(char *);
int WhichProto(char *);
#if 0 /* Relocated to parser/IpAddrSet.h */
int ParseIP(char *, IpAddrSet *);
#endif /* Relocated to parser/IpAddrSet.h */
int ParsePort(char *, u_short *,  u_short *, char *, int *);
u_int16_t ConvPort(char *, char *);

char *VarGet(char *);
char *ExpandVars(char *);
char *CreateRule(char *, char *, char *);

struct VarEntry *VarAlloc();

/* XXX: Defined in detect.c */
ListHead *CreateRuleType(char *, int, int, ListHead *);

void ProcessAlertFileOption(char *);
char *ProcessFileOption(const char *);
void ParseConfig(char *);
void ParseRuleTypeDeclaration(FILE*, char *);
/*void ParseClassificationConfig(char *); */
char *ReadLine(FILE *);
int checkKeyword(char *);
void SetRuleStates();
#ifdef DYNAMIC_PLUGIN
void ConfigureDynamicPreprocessors();
#endif
void ParseIPv6Options(char *);
int GetOtnIpProto( OptTreeNode * otn );
int GetPcaps(SF_LIST *, SF_QUEUE *);

void ParserCleanup();
#endif /* __PARSER_H__ */

