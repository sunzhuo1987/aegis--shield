/****************************************************************************
 *
 * Copyright (C) 2005-2008 Sourcefire, Inc.
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
 
#ifndef STREAM5_TCP_H_
#define STREAM5_TCP_H_

void Stream5CleanTcp(void);
void Stream5ResetTcp(void);
void Stream5InitTcp(void);
int Stream5VerifyTcpConfig(void);
void Stream5TcpPolicyInit(char *);
int Stream5ProcessTcp(Packet *p);
int Stream5FlushListener(Packet *p, Stream5LWSession *lwssn);
int Stream5FlushTalker(Packet *p, Stream5LWSession *lwssn);
int Stream5FlushClient(Packet *p, Stream5LWSession *lwssn);
int Stream5FlushServer(Packet *p, Stream5LWSession *lwssn);
void TcpUpdateDirection(Stream5LWSession *ssn, char dir,
                        snort_ip_p ip, u_int16_t port);
void Stream5TcpBlockPacket(Packet *p);
Stream5LWSession *GetLWTcpSession(SessionKey *key);
int GetTcpRebuiltPackets(Packet *p, Stream5LWSession *ssn,
        PacketIterator callback, void *userdata);
int Stream5AddSessionAlertTcp(Stream5LWSession *lwssn, Packet *p, u_int32_t gid, u_int32_t sid);
int Stream5CheckSessionAlertTcp(Stream5LWSession *lwssn, Packet *p, u_int32_t gid, u_int32_t sid);
char Stream5GetReassemblyDirectionTcp(Stream5LWSession *lwssn);
char Stream5SetReassemblyTcp(Stream5LWSession *lwssn, u_int8_t flush_policy, char dir, char flags);
char Stream5GetReassemblyFlushPolicyTcp(Stream5LWSession *lwssn, char dir);
char Stream5IsStreamSequencedTcp(Stream5LWSession *lwssn, char dir);
char Stream5MissingInReassembledTcp(Stream5LWSession *lwssn, char dir);
char Stream5PacketsMissingTcp(Stream5LWSession *lwssn, char dir);
#endif /* STREAM5_TCP_H_ */
