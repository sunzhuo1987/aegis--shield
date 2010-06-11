#include <stdio.h>
#include <netinet/ip.h>
#include <assert.h>
#include "c_map.h"
#include "ConnectionTrack.h"
#include "Classify.h"

c_map conns = {NULL};
c_map infos = {NULL};


static inline int KeyCompare(void* x, void* y)
{		
	return memcmp(x, y, 12);
}

static inline int IPCompare(void* x, void* y)
{
	return memcmp(x, y, 4);
}

static void InitMap()
{
	c_map_create(&conns, KeyCompare);
	assert(__c_rb_tree_verify(conns._l));
}

static struct Connection* GetConnection1(char* key)
{
	c_iterator target;
	c_iterator map_end;

	target = c_map_find(&conns, (void*)key);
	map_end = c_map_end(&conns);

	if (!ITER_EQUAL(map_end, target))
	{
		return (struct Connection*)(((c_ppair)ITER_REF(target))->second);
	}

	return NULL;
}

static struct Info* GetInfo(unsigned int ip)
{
	c_iterator target;
	c_iterator map_end;

	target = c_map_find(&infos, (void*)&ip);
	map_end = c_map_end(&infos);

	if (!ITER_EQUAL(map_end, target))
	{
		return (struct Info*)(((c_ppair)ITER_REF(target))->second);
	}

	return NULL;
}

void DestroyInfos()
{
	unsigned int* ip  = NULL;
	struct Info* info = NULL;
	struct Info* p    = NULL;
	if (infos._l == NULL)
		return;

	c_iterator iter = c_map_begin(&infos);
	c_iterator end  = c_map_end(&infos);
	c_iterator toErase;

	
	while (!ITER_EQUAL(iter, end)) 
	{
		ip = (unsigned int*)(((c_ppair)ITER_REF(iter))->first);
		free(ip);
		info = (struct Info*)(((c_ppair)ITER_REF(iter))->second);
		while (info)
		{
			p = info;
			info = info->next;
			free(p);
			p = NULL;
		}

		toErase = iter;
		ITER_INC(iter);
		c_map_erase(&infos, toErase);
	}
}

static void CleanConnections()
{
	c_iterator iter = c_map_begin(&conns);
	c_iterator end = c_map_end(&conns);
	c_iterator toErase;
	int packetNumbers = 0;
	int mark = 0;

	while (!ITER_EQUAL(iter, end))
	{
		packetNumbers = ((struct Connection*)(((c_ppair)ITER_REF(iter))->second))->num_packets;
		mark = ((struct Connection*)(((c_ppair)ITER_REF(iter))->second))->mark;
		if ( packetNumbers > MAX_PACKET && mark == NO_MATCH)
		{
			toErase = iter;
			ITER_INC(iter);
			c_map_erase(&conns, toErase);
			fprintf(stderr, "One Connection has been deleted\n");
		}
		else
		{
			ITER_INC(iter);
		}
	}
}


static char* MakeConnectionKey(char* buffer, int reverse)
{
	int iphdrLen = (buffer[0] & 0x0F) * 4;
	unsigned int srcip = *(int*)(buffer + 12);
	unsigned int dstip = *(int*)(buffer + 16);

	unsigned short srcport = *(short*)(buffer + iphdrLen);
	unsigned short dstport = *(short*)(buffer + iphdrLen + 2);

	char* key = (char*)malloc(12);
	if (!reverse)
	{
		memcpy(key, &srcip, 4);
		memcpy(key + 4, &srcport, 2);
		memcpy(key + 4 + 2, &dstip, 4);
		memcpy(key + 4 + 2 + 4, &dstport, 2);
	}
	else
	{
		memcpy(key, &dstip, 4);
		memcpy(key + 4, &dstport, 2);
		memcpy(key + 4 + 2, &srcip, 4);
		memcpy(key + 4 + 2 + 4, &srcport, 2);
	}

	return key;
}

static int GetDataOffset(char* buffer)
{
	int iphdrLen = (buffer[0] & 0x0F) * 4;
	char ipProto = buffer[9];
	int tcphdrLen;
	
	if (ipProto == IPPROTO_TCP)
	{
		tcphdrLen = (buffer[iphdrLen + 12] >> 4) * 4;
		return iphdrLen + tcphdrLen;
	}
	else if (ipProto == IPPROTO_UDP)
	{
		return iphdrLen + 8;
	}
}

int ParsePacket(char* buffer, unsigned int* srcip, unsigned short* srcport, char** proto)
{
	char* key = NULL;
	struct Connection* conn = NULL;
	c_pair* newPair = NULL;

	char* data = NULL;
	int dataoffset;
	int datalen = 0;

	char ipProto;

	int mark = UNTOUCHED;
	

	if (conns._l == NULL)
	{
		InitMap();
	}

	ipProto = buffer[9];
	
	if (ipProto == IPPROTO_TCP || ipProto == IPPROTO_UDP)
	{
		key = MakeConnectionKey(buffer, 0);

		conn = GetConnection1(key);

		if (!conn)
		{
			free(key);
			key = NULL;

			key = MakeConnectionKey(buffer, 1);
			conn = GetConnection1(key);

			if (!conn)
			{
				free(key);
				key = NULL;
				//create a new key
				key = MakeConnectionKey(buffer, 0);

				conn = (struct Connection*)malloc(sizeof(struct Connection));

				memset(conn, 0, sizeof(struct Connection));
				conn->mark = UNTOUCHED;
				conn->num_packets = 0;
				memcpy(conn->key, key, 12);

				newPair = (c_pair*)malloc(sizeof(c_pair));
				newPair->second = (void*)conn;
				newPair->first = (void*)malloc(12);
				memcpy(newPair->first, key, 12);

				if (c_map_size(&conns) >= MAX_CONNECTIONS)
				{
					CleanConnections();
					if (c_map_size(&conns) >= MAX_CONNECTIONS)
						c_map_clear(&conns);
				}

				free(key);
				key = NULL;

				c_map_insert(&conns, newPair);
			}
		}

		if (conn)
		{
			++conn->num_packets;

			dataoffset = GetDataOffset(buffer);
			datalen = ntohs(*(short*)(buffer + 2)) - dataoffset;
			data = buffer + dataoffset;
			
			if (datalen <= 0)
			{
			/*	mark = NO_MATCH;*/
				mark = UNTOUCHED;
			}
			else
			{
				if (conn->mark == NO_MATCH)
				{
					return NO_MATCH;
				}

				if (conn->mark != NO_MATCH && conn->mark != UNTOUCHED)
				{
					mark = MATCHED;
				}
				else if (conn->num_packets <= MAX_PACKET)
				{
					mark = Classify(data, datalen, proto);
					conn->mark = mark;
					if (conn->mark > 2)
					{
						*srcip = *(unsigned int*)conn->key;
						*srcport = *(unsigned short*)((char*)conn->key + 4);
					}
				}
				else
				{
					mark = NO_MATCH;
					conn->mark = mark;
				}
			}
		}
	}
	
	return mark;
}


int NeedToBeInserted(unsigned int srcip, char* proto)
{
	struct Info* info = NULL;
	struct Info* p    = NULL;
	c_pair* newPair = NULL;
	struct timeval tv = {0, 0};

	if (infos._l == NULL)
	{
		c_map_create(&infos, IPCompare);
		assert(__c_rb_tree_verify(infos._l));
	}

	info = GetInfo(srcip);
	if (info == NULL)
	{
		info = (struct Info*)malloc(sizeof(struct Info));
		gettimeofday(&tv, NULL);
		info->time = tv.tv_sec;
		info->proto = (char*)malloc(strlen(proto) + 1);
		strcpy(info->proto, proto);
		info->next = NULL;

		newPair = (struct c_pair*)malloc(sizeof(struct c_pair));
		newPair->first = malloc(4);
		memcpy(newPair->first, &srcip, 4);
		newPair->second = (void*)info;
		
		c_map_insert(&infos, newPair);

		return 1;
	}
	else
	{

		p = info;
		while (p)
		{
			if (!strcmp(p->proto, proto))
			{
				gettimeofday(&tv, NULL);
				if (tv.tv_sec - p->time > MAX_INTERVAL_TIME)
				{
					p->time = tv.tv_sec;//update the time
					return 1;
				}
				else
				{
					return 0;
				}
			}
			if (p->next == NULL)
			{
				info = (struct Info*)malloc(sizeof(struct Info));
				gettimeofday(&tv, NULL);
				info->time = tv.tv_sec;
				info->proto = (char*)malloc(strlen(proto) + 1);
				strcpy(info->proto, proto);
				info->next = NULL;

				p->next = info;
				
				return 1;
			}
			p = p->next;
		}
	}
}


