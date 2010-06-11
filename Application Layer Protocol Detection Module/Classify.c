#include "Classify.h"
#include "ParsePatterns.h"
#include "list.h"
#include <stdio.h>

static int Matches(char* data, struct PatternNode* pattern)
{
	int rc = regexec(&pattern->data->preg, data, 0, NULL, pattern->data->eflags);
	if (rc == 0)
	{
		return pattern->data->mark;
	}
	else
	{
		return 0;//UNTOUCHED
	}
	
}

int Classify(char* data, int datalen, char** proto)
{
	int mark = 0;
	int i = 0;
	int j = 0;
	char* payload = NULL;
	struct PatternNode* p = patternHeader->next;

	payload = (char*)malloc(datalen);
	memset(payload, 0, datalen);
	for (; i < datalen; ++i)
	{
		if (data[i] != '\0')
		{
			payload[j++] = data[i];
		}
	}

	while (p)
	{
		mark = Matches(payload, p);
		if (mark > 2)
		{
			*proto = (char*)malloc(255);
			memset(*proto, 0, 255);
			strcpy(*proto, p->data->name);
			break;
		}
		p = p->next;
	}
	free(payload);
	return mark;
}
