#include <stdio.h>
#include <string.h>
#include "ParsePatterns.h"
#include "list.h"

#define MAX_LINE_LEN		1024
#define MAX_PATTERN_LEN		1024
#define MAX_PROTO_LEN		255
#define MAX_FILENAME_LEN	255

char* homenet     = NULL;
char* homenetmask = NULL;
int readFirstConfigFile = 0;

static int AddPatternFromFile(char* fileName, int mark);

static int Hex2dec(char c)
{
	switch (c)
	{
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
		return c - '0';
	case 'a':
	case 'b':
	case 'c':
	case 'd':
	case 'e':
	case 'f':
		return c - 'a' + 10;
	case 'A':
	case 'B':
	case 'C':
	case 'D':
	case 'E':
	case 'F':
		return c - 'A' + 10;
	default:
		fprintf(stderr, "Bad hex digit %c, in regular expression!\n", c);
		exit(1);
	}
}

static char* PreprocessRegex(char* s)
{
	int len = strlen(s);
	char * result = (char *)malloc(len + 1);
	unsigned int sindex = 0, rindex = 0;
	while( sindex < len ) 
	{
		if( sindex + 3 < len && s[sindex] == '\\' && s[sindex+1] == 'x' && 
			isxdigit(s[sindex + 2]) && isxdigit(s[sindex + 3]) )
		{
			result[rindex] = Hex2dec(s[sindex + 2])*16 + Hex2dec(s[sindex + 3]);
			switch ( result[rindex] ) 
			{
			case '$':
			case '(':
			case ')':
			case '*':
			case '+':
			case '.':
			case '?':
			case '[':
			case ']':
			case '^':
			case '|':
			case '{':
			case '}':
			case '\\':
				/*cerr << "Warning: regexp contains a regexp control character, "
					<< result[rindex] << ", in hex (\\x" << s[sindex + 2] 
				<< s[sindex+3] << ".\nI recommend that you write this as "
					<< result[rindex] << " or \\" << result[rindex] 
				<< " depending on what you meant.\n";*/
				fprintf(stderr, "Warning: regexp contains a regexp control character, %c, in hex(\\x %X.\nI recommend that you write this as %c or \\%c depenfing on what you meant.\n", result[rindex], s[sindex+2], s[sindex+3], result[rindex], result[rindex]);
				break;
			case '\0':
				/*cerr << "Warning: null (\\x00) in layer7 regexp. "
					<< "A null terminates the regexp string!\n";*/
				fprintf(stderr, "Warning: null(\\x00) in layer7 regexp. A null terminates the regexp string!\n");
				break;
			default:
				break;
			}
			sindex += 3; /* 4 total */
		}
		else
			result[rindex] = s[sindex];

		sindex++; 
		rindex++;
	}
	result[rindex] = '\0';

	return result;
}

static char* FindPatternFile(char* protoName)
{
	int c = 0;
	char* filename = (char*)malloc(MAX_FILENAME_LEN);
	memset(filename, 0, MAX_FILENAME_LEN);

	if (!readFirstConfigFile)
		c = sprintf(filename, "/etc/snort/regexps/%s.pat", protoName);
	else
		c = sprintf(filename, "/etc/snort/update_regexps/%s.pat", protoName);

	//fprintf(stderr, "%s\n", filename);
	if (c > MAX_FILENAME_LEN)
	{
		fprintf(stderr, "Filename beginning with %s is too long\n", filename);
		exit(1);
	}

	FILE* test = fopen(filename, "r");
	if (test)
	{
		fclose(test);
		return filename;
	}
	
	fprintf(stderr, "Couldn't find a pattern definition file for %s", protoName);
	exit(1);
}

static int IsComment(char* line)
{
	int i = 0;
	int len = strlen(line);
	if (len  == 0)
	{
		return 1;
	}
	if (line[0] == '#')
	{
		return 1;
	}
	for (; i < len; ++i)
	{
		if (!isspace(line[i]))
		{
			return 0;
		}
	}
	return 1;
}


void ParseConfigurationFile(char* fileName)
{
	char line[MAX_LINE_LEN] = {0};
	char proto[MAX_PROTO_LEN] = {0};
	char* protoFileName = NULL;
	static int mark = 3;
	int i = 0;
	int nothingbutspace = 1;

	FILE* conf = fopen(fileName, "r");
	if (conf == NULL)
	{
		fprintf(stderr, "Could not read from %s\n", fileName);
		exit(1);
	}

	if (patternHeader == NULL)
	{
		fgets(line, MAX_LINE_LEN, conf);
		homenet = (char*)malloc(strlen(line));
		memset(homenet, 0, strlen(line));
		memcpy(homenet, line, strlen(line) - 1);
	
		fprintf(stderr, "homenet:%s\n", homenet);

		fgets(line, MAX_LINE_LEN, conf);
		homenetmask = (char*)malloc(strlen(line));
		memset(homenetmask, 0, strlen(line));
		memcpy(homenetmask, line, strlen(line) - 1);

		fprintf(stderr, "homenetmask:%s\n", homenetmask);

		InitPatternList();
	}

	
	while (fgets(line, MAX_LINE_LEN, conf))
	{
		//lines starting with '#' are comments
		if (line[0] == '#')
		{
			continue;
		}

		//blank lines are ignored
		for (i = 0; i < strlen(line); ++i)
		{
			if (!isspace(line[0]))
			{
				nothingbutspace = 0;
				break;
			}
		}
		if (nothingbutspace)
		{
			continue;
		}

		/*if (!sscanf(line, "%s %d", proto, &mark))
		{
			fprintf(stderr, "Ignoring line because it isn't in the format 'protocol mark': %s\n", line);
			continue;
		}*/
		line[strlen(line) - 1] = '\0';
		strcpy(proto, line);

		/*if (mark <= 2)
		{
			fprintf(stderr, "Ignoring line because the mark should be greater than 2");
			continue;
		}*/

		protoFileName = FindPatternFile(proto);
		
		if (AddPatternFromFile(protoFileName, mark))
		{
			printf("AddPatternFromFile: %s %d success\n", protoFileName, mark);
		}
		
		++mark;
		free(protoFileName);
	}
	fclose(conf);
}

static int AddPatternFromFile(char* fileName, int mark)
{
	int cflags;
	int eflags;
	char pattern[MAX_PATTERN_LEN] = {0};
	char line[MAX_LINE_LEN] = {0};
	char proto[MAX_PROTO_LEN] = {0};
	char* preprocessed = NULL;
	int rc = 0;
	char* pos = pattern;
	int protoLen = 0;
	int patternLen = 0;

	enum{protocol, kpattern/*, userspace*/} state = protocol;

	FILE* theFile = fopen(fileName, "r");
	if (theFile == NULL)
	{
		fprintf(stderr,	"Could't read the file: %s\n", fileName);
		return 0;
	}
	
	cflags = REG_EXTENDED | REG_ICASE | REG_NOSUB;
	eflags = 0;

	while (fgets(line, MAX_LINE_LEN, theFile))
	{
		if (IsComment(line))
		{
			continue;
		}
		
		if (state == protocol)
		{
			memcpy(proto, line, strlen(line) -1);
			state = kpattern;
			continue;
		}
		if (state == kpattern)
		{
			memcpy(pattern, line, strlen(line) - 1);
			continue;
		}
	}

	protoLen = strlen(proto);
	patternLen = strlen(pattern);

	struct Pattern* newPattern = (struct Pattern*)malloc(sizeof(struct Pattern));
	newPattern->cflags = cflags;
	newPattern->eflags = eflags;
	newPattern->mark = mark;
	newPattern->name = (char*)malloc(protoLen + 1);
	memset(newPattern->name, 0, protoLen + 1);
	strcpy(newPattern->name, proto);
	newPattern->pattern_string = (char*)malloc(patternLen + 1);
	memset(newPattern->pattern_string, 0, patternLen + 1);
	strcpy(newPattern->pattern_string, pattern);

	preprocessed = PreprocessRegex(newPattern->pattern_string);
	rc = regcomp(&newPattern->preg, preprocessed, newPattern->cflags);
	if (rc != 0)
	{
		fprintf(stderr, "error compiling %s -- %s", newPattern->name, newPattern->pattern_string);
		exit(1);
	}
	
	AddPattern(newPattern);

	return 1;
}


