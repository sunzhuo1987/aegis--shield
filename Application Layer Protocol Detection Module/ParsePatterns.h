#ifndef PARSE_PATTERNS_H
#define PARSE_PATTERNS_H

//#include <string.h>

#include <regex.h>

struct Pattern
{
	int mark;
	char* pattern_string;
	int eflags;
	int cflags;
	char* name;
	regex_t preg;
};


extern void ParseConfigurationFile(char* fileName);

extern char* homenet;
extern char* homenetmask;

#endif

