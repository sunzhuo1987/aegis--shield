#include "list.h"
#include "ConnectionTrack.h"
#include "ParsePatterns.h"
#include "mysql.h"
#include <stdio.h>

struct PatternNode* patternHeader = NULL;

struct InsertionNode* front = NULL;
struct InsertionNode* rear  = NULL;

unsigned int len = 0;

void InitPatternList()
{
	patternHeader = (struct PatternNode*)malloc(sizeof(struct PatternNode));
	patternHeader->data = NULL;
	patternHeader->next = NULL;
}

void AddPattern(struct Pattern* newPattern)
{
	struct PatternNode* p = patternHeader;
	while (p->next)
	{
		p = p->next;
	}
	p->next = (struct PatternNode*)malloc(sizeof(struct PatternNode*));
	p->next->data = newPattern;
	p->next->next = NULL;
}

void DeletePattern(char* name)
{
	struct PatternNode* p = patternHeader;
	struct PatternNode* del = NULL;
	while (p->next)
	{
		if (!strcmp(p->next->data->name, name))
		{
			free(p->next->data->name);
			free(p->next->data->pattern_string);
			free(p->next->data);
			del = p->next;
			p->next = p->next->next;
			free(del);
		}
		p = p->next;
	}
}

void DestroyPatternList()
{
	struct PatternNode* del = NULL;
	while (patternHeader->next)
	{
		free(patternHeader->next->data->name);
		free(patternHeader->next->data->pattern_string);
		free(patternHeader->next->data);
		del = patternHeader->next;
		patternHeader->next = patternHeader->next->next;
		free(del);
	}

	free(patternHeader);
	patternHeader = NULL;
}

/*void InitInsertionQueue()
{
	front = (struct InsertionNode*)malloc(sizeof(struct InsertionNode));
	front->insertionStatement = NULL;
	front->next = NULL;
	rear = front;
}

void InQueue(char* insertion)
{
	struct InsertionNode* newNode;

	if (insertion == NULL)
	{
		return;
	}

	newNode = (struct InsertionNode*)malloc(sizeof(struct InsertionNode));
	newNode->insertionStatement = insertion;
	newNode->next = NULL;

	rear->next = newNode;
	rear = rear->next;

	++len;
}

char* OutQueue()
{
	struct InsertionNode* del = NULL;
	char* result = NULL;

	if (len == 0)
	{
		return NULL;
	}
	else
	{
		del = front->next;
		front->next = front->next->next;
		result = del->insertionStatement;
		if (del == rear)
			rear = front;
		free(del);
		--len;
		return result;
	}
}

unsigned int GetLength()
{
	return len;
}

extern MYSQL* g_sock;
void FlushQueue()
{
	char* insertion = NULL;
	while (NULL != (insertion = OutQueue()))
	{
		if (!mysql_query(g_sock, insertion))
		{
			fprintf(stderr, "insert into success\n");
		}
		else
		{
			fprintf(stderr, "error:%s\n", mysql_error(g_sock));
		}
		free(insertion);
		insertion = NULL;
	}

	free(front);
	front = NULL;
}*/

/*void InitPairList()
{
	pairHeader = (struct PairNode*)malloc(sizeof(struct PairNode));
	pairHeader->data = NULL;
	pairHeader->next = NULL;
}

void AddPair(struct Pair* newPair)
{
	struct PairNode* p = pairHeader;
	while (p->next)
	{
		p = p->next;
	}
	p->next = (struct PairNode*)malloc(sizeof(struct PairNode));
	p->next->data = newPair;
	p->next->next = NULL;
}

struct Connection* GetConnection(char* key)
{
	struct PairNode* p = pairHeader;
	while (p->next)
	{
		if (memcmp(p->next->data->key, key, 12) == 0)
		{
			return p->next->data->conn;
		}
		p = p->next;
	}

	return NULL;
}

void DestroyPairList()
{
	struct PairNode* del = NULL;
	while (pairHeader->next)
	{
		free(pairHeader->next->data);
		del = pairHeader->next;
		pairHeader->next = pairHeader->next->next;
		free(del);
	}

	free(pairHeader);
	pairHeader = NULL;
}*/
