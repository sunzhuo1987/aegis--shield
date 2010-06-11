#ifndef LIST_H
#define LIST_H

#include <stdlib.h>

struct Pattern;

struct PatternNode
{
	struct Pattern* data;
	struct PatternNode* next;
};


extern struct PatternNode* patternHeader;

extern void InitPatternList();
extern void AddPattern(struct Pattern* newPattern);
extern void DeletePattern(char* name);
extern void DestroyPatternList();


struct InsertionNode
{
	char* insertionStatement;
	struct InsertionNode* next;
};

extern struct InsertionNode* front;

extern void InitInsertionQueue();
extern void InQueue(char* insertion);
extern char* OutQueue();
extern unsigned int GetLength();
extern void FlushQueue();

#endif
