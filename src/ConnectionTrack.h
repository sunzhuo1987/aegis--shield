#ifndef CONNECTION_TRACKER_H
#define CONNECTION_TRACKER_H

#include <stdlib.h>
#include <sys/time.h>

#define UNTOUCHED		0              /*Tag a connection which has not yet been matched*/
#define NO_MATCH		1	       /*Tag a connection which can't be matched*/
#define MATCHED			2	       /*tag a connection which has been matched*/

#define MAX_PACKET		5	

#define MAX_CONNECTIONS  	655360	

#define MAX_INTERVAL_TIME       60

struct Connection
{
	unsigned int num_packets;
	unsigned int mark;
	char key[12];
};

struct Info
{
	time_t time;
	char* proto;
	struct Info* next;
};

extern int ParsePacket(char* buffer, unsigned int* srcip, unsigned short* srcport, char** proto);

extern int NeedToBeInserted(unsigned int srcip, char* proto);
extern void DestroyInfos();
#endif
