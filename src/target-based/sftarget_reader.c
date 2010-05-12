/*
** Copyright (C) 2006-2008 Sourcefire, Inc.
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

/*
 * Author: Steven Sturges
 * sftarget_reader.c
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef TARGET_BASED

#include <stdio.h>
#include "mstring.h"
#include "util.h"
#include "parser.h"
#include "sftarget_reader.h"
#include "sftarget_protocol_reference.h"
#include "sfutil/sfrt.h"
#include "sfutil/sfxhash.h"
#include "sfutil/util_net.h"
#include "sftarget_hostentry.h"

#include <signal.h>
#include <sys/types.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "snort.h"

#include "debug.h"

static table_t *attribute_lookup_table = NULL;
static SFXHASH *attribute_map_table = NULL;

static table_t *attribute_lookup_table_tmp = NULL;
static SFXHASH *attribute_map_table_tmp = NULL;

static table_t *attribute_lookup_table_old = NULL;
static SFXHASH *attribute_map_table_old = NULL;

static HostAttributeEntry *current_host = NULL;
static ApplicationEntry *current_app = NULL;
//static MapData *current_map_entry = NULL;
ServiceClient sfat_client_or_service;

extern char sfat_error_message[STD_BUF];
extern char sfat_grammar_error_printed;
int ParseTargetMap(char *filename);

extern char *sfat_saved_file;
/*****TODO: cleanup to use config directive *******/
#define ATTRIBUTE_MAP_MAX_ROWS 1024
u_int32_t SFAT_NumberOfHosts()
{
    if (attribute_lookup_table)
    {
        return sfrt_num_entries(attribute_lookup_table);
    }

    return 0;
}

int SFAT_AddMapEntry(MapEntry *entry)
{
    if (!attribute_map_table_tmp)
    {
        /* Attribute Table node includes memory for each entry,
         * as defined by sizeof(MapEntry).
         */
        attribute_map_table_tmp = sfxhash_new(ATTRIBUTE_MAP_MAX_ROWS,
                                          sizeof(int),
                                          sizeof(MapEntry),
                                          0,
                                          1,
                                          NULL,
                                          NULL,
                                          1);
        if (!attribute_map_table_tmp)
            FatalError("Failed to allocate attribute map table\n");
    }

    /* Memcopy MapEntry to newly allocated one and store in
     * a hash table based on entry->id for easy lookup.
     */

    DEBUG_WRAP(
        DebugMessage(DEBUG_ATTRIBUTE, "Adding Map Entry: %d %s\n",
            entry->l_mapid, entry->s_mapvalue););

    /* Data from entry will be copied into new node */
    sfxhash_add(attribute_map_table_tmp, &entry->l_mapid, entry);

    return SFAT_OK;
}

char *SFAT_LookupAttributeNameById(int id)
{
    MapEntry *entry;

    if (!attribute_map_table_tmp)
        return NULL;
    
    entry = sfxhash_find(attribute_map_table_tmp, &id);

    if (entry)
    {
        DEBUG_WRAP(
            DebugMessage(DEBUG_ATTRIBUTE, "Found Attribute Name %s for Id %d\n",
                entry->s_mapvalue, id););
        return entry->s_mapvalue;
    }
    DEBUG_WRAP(
        DebugMessage(DEBUG_ATTRIBUTE, "No Attribute Name for Id %d\n", id););

    return NULL;
}

void FreeApplicationEntry(ApplicationEntry *app)
{
    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Freeing ApplicationEntry: 0x%x\n",
        app););
    free(app);
}

ApplicationEntry * SFAT_CreateApplicationEntry()
{
    if (current_app)
    {
        /* Something went wrong */
        FreeApplicationEntry(current_app);
        current_app = NULL;
    }

    current_app = SnortAlloc(sizeof(ApplicationEntry));

    return current_app;
}

HostAttributeEntry * SFAT_CreateHostEntry()
{
    if (current_host)
    {
        /* Something went wrong */
        FreeHostEntry(current_host);
        current_host = NULL;
    }

    current_host = SnortAlloc(sizeof(HostAttributeEntry));

    return current_host;
}

void FreeHostEntry(HostAttributeEntry *host)
{
    ApplicationEntry *app = NULL, *tmp_app;

    if (!host)
        return;

    DEBUG_WRAP(DebugMessage(DEBUG_ATTRIBUTE, "Freeing HostEntry: 0x%x\n",
        host););

    /* Free the service list */
    if (host->services)
    {
        do
        {
            tmp_app = host->services;
            app = tmp_app->next;
            FreeApplicationEntry(tmp_app);
            host->services = app;
        } while (app);
    }

    /* Free the client list */
    if (host->clients)
    {
        do
        {
            tmp_app = host->clients;
            app = tmp_app->next;
            FreeApplicationEntry(tmp_app);
            host->clients = app;
        } while (app);
    }

    free(host);
}

void PrintAttributeData(char *prefix, AttributeData *data)
{
#ifdef DEBUG
    DebugMessage(DEBUG_ATTRIBUTE, "AttributeData for %s\n", prefix);
    if (data->type == ATTRIBUTE_NAME)
    {
        DebugMessage(DEBUG_ATTRIBUTE, "\ttype: %s\tname: %s\t confidence %d\n",
                "Name", data->value.s_value, data->confidence);
    }
    else
    {
        DebugMessage(DEBUG_ATTRIBUTE, "\ttype: %s\tid: %s\t confidence %d",
                "Id", data->value.l_value, data->confidence);
    }
#endif
}

int SFAT_SetHostIp4(char *ip)
{
    static HostAttributeEntry *tmp_host = NULL;
    struct in_addr ip4_inAddr;
    u_int32_t ipAddr = 0;
    u_int8_t bits = 32;
    char *ipMask;
    char *hasMask;

    SFAT_CHECKHOST;

    ipMask = strdup(ip); /* Don't use SnortStrdup, can't FatalError here */
    if (!ipMask)
    {
        return SFAT_ERROR;
    }

    hasMask = strchr(ipMask, '/');
    if (hasMask)
    {
        *hasMask = '\0';
        hasMask++;
        bits = (char)strtoul(hasMask, NULL, 10);
    }
    /* No mask, implicit 32 bits */

    /* this is terminated at end of
     * IP part if mask included */
    if (inet_pton(AF_INET, ipMask, &ip4_inAddr) == 0)
    {
        free(ipMask);
        return SFAT_ERROR;
    }
    ipAddr = ntohl(ip4_inAddr.s_addr);

    /*** : Lookup and set current_host via IP addr */
    tmp_host = sfrt_lookup(&ipAddr, attribute_lookup_table_tmp);

    /*** If found, free current_host and set current_host to the one found */
    if (tmp_host && 
        (tmp_host->ipAddr == ipAddr) &&
        (tmp_host->bits == bits))
    {
        /* Exact match. */
        FreeHostEntry(current_host);
        current_host = tmp_host;
    }
    else
    {
        /* New entry for this host/CIDR */
        current_host->ipAddr = ipAddr;
        current_host->bits = bits;
    }

    free(ipMask);

    return SFAT_OK;
}

int SFAT_SetOSPolicy(char *policy_name, int attribute)
{
    SFAT_CHECKHOST;

    switch (attribute)
    {
        case HOST_INFO_FRAG_POLICY:
            SnortStrncpy(current_host->hostInfo.fragPolicyName, policy_name, STD_BUF);
            break;
        case HOST_INFO_STREAM_POLICY:
            SnortStrncpy(current_host->hostInfo.streamPolicyName, policy_name, STD_BUF);
            break;
    }
    return SFAT_OK;
}

int SFAT_SetOSAttribute(AttributeData *data, int attribute)
{
    SFAT_CHECKHOST;

    switch (attribute)
    {
        case HOST_INFO_OS:
            memcpy(&current_host->hostInfo.operatingSystem, data, sizeof(AttributeData));
            break;
        case HOST_INFO_VENDOR:
            memcpy(&current_host->hostInfo.vendor, data, sizeof(AttributeData));
            break;
        case HOST_INFO_VERSION:
            memcpy(&current_host->hostInfo.version, data, sizeof(AttributeData));
            break;
    }
    return SFAT_OK;
}

static void AppendApplicationData(ApplicationList **list)
{
    if (!list)
        return;

    if (*list)
    {
        current_app->next = *list;
    }
    *list = current_app;
    current_app = NULL;
}

int SFAT_AddApplicationData()
{
    u_int8_t required_fields;
    SFAT_CHECKAPP;
    SFAT_CHECKHOST;

    if (sfat_client_or_service == ATTRIBUTE_SERVICE)
    {
        required_fields = (APPLICATION_ENTRY_PORT |
                          APPLICATION_ENTRY_IPPROTO |
                          APPLICATION_ENTRY_PROTO);
        if ((current_app->fields & required_fields) != required_fields)
        {
            struct in_addr host_addr;
            host_addr.s_addr = current_host->ipAddr;
            FatalError("%s(%d) ERROR: Missing required field in Service attribute table for host %s\n",
                file_name, file_line,
                inet_ntoa(host_addr));
        }

        AppendApplicationData(&current_host->services);
    }
    else
    {
        required_fields = (APPLICATION_ENTRY_PROTO);
        /* Currently, client data only includes PROTO, not IPPROTO */
        if ((current_app->fields & required_fields) != required_fields)
        {
            struct in_addr host_addr;
            host_addr.s_addr = current_host->ipAddr;
            FatalError("%s(%d) ERROR: Missing required field in Client attribute table for host %s\n",
                file_name, file_line,
                inet_ntoa(host_addr));
        }

        AppendApplicationData(&current_host->clients);
    }
    return SFAT_OK;
}

int SFAT_SetApplicationAttribute(AttributeData *data, int attribute)
{
    SFAT_CHECKAPP;

    switch(attribute)
    {
        case APPLICATION_ENTRY_PORT:
            /* Convert the port to a integer */
            if (data->type == ATTRIBUTE_NAME)
            {
                char *endPtr = NULL;
                unsigned long value = strtoul(data->value.s_value, &endPtr, 10);
                if ((endPtr == &data->value.s_value[0]) ||
                    (errno == ERANGE))
                {
                    current_app->port.value.l_value = 0;
                    return SFAT_ERROR;
                }
                current_app->port.value.l_value = value;
            }
            else
            {
                current_app->port.value.l_value = data->value.l_value;
            }
            break;
        case APPLICATION_ENTRY_IPPROTO:
            memcpy(&current_app->ipproto, data, sizeof(AttributeData));
            /* Add IP Protocol to the reference list */
            current_app->ipproto.attributeOrdinal = AddProtocolReference(data->value.s_value);
            break;
        case APPLICATION_ENTRY_PROTO:
            memcpy(&current_app->protocol, data, sizeof(AttributeData));
            /* Add Application Protocol to the reference list */
            current_app->protocol.attributeOrdinal = AddProtocolReference(data->value.s_value);
            break;
        case APPLICATION_ENTRY_APPLICATION:
            memcpy(&current_app->application, data, sizeof(AttributeData));
            break;
        case APPLICATION_ENTRY_VERSION:
            memcpy(&current_app->version, data, sizeof(AttributeData));
            break;
        default:
            attribute = 0;
    }
    current_app->fields |= attribute;

    return SFAT_OK;
}

#ifdef DEBUG
void PrintHostAttributeEntry(HostAttributeEntry *host)
{
    ApplicationEntry *app;
    int i = 0;

    if (!host)
        return;

    DebugMessage(DEBUG_ATTRIBUTE, "Host IP: %s/%d\n",
            inet_ntoax(ntohl(host->ipAddr)), host->bits);
    DebugMessage(DEBUG_ATTRIBUTE, "\tOS Information: %s(%d) %s(%d) %s(%d)\n",
            host->hostInfo.operatingSystem.value.s_value,
            host->hostInfo.operatingSystem.confidence,
            host->hostInfo.vendor.value.s_value,
            host->hostInfo.vendor.confidence,
            host->hostInfo.version.value.s_value,
            host->hostInfo.version.confidence);
    DebugMessage(DEBUG_ATTRIBUTE, "\tPolicy Information: frag:%s stream: %s\n",
            host->hostInfo.fragPolicyName,
            host->hostInfo.streamPolicyName);
    DebugMessage(DEBUG_ATTRIBUTE, "\tServices:\n");
    for (i=0, app = host->services; app; app = app->next,i++)
    {
        DebugMessage(DEBUG_ATTRIBUTE, "\tService #%d:\n", i);
        DebugMessage(DEBUG_ATTRIBUTE, "\t\tIPProtocol: %s(%d)\tPort: %s(%d)"
                "\tProtocol %s(%d)\n",
                app->ipproto.value.s_value,
                app->ipproto.confidence,
                app->port.value.s_value,
                app->port.confidence,
                app->protocol.value.s_value,
                app->protocol.confidence);

        if (app->fields & APPLICATION_ENTRY_APPLICATION)
        {
            DebugMessage(DEBUG_ATTRIBUTE, "\t\tApplication: %s(%d)\n",
                app->application.value.s_value,
                app->application.confidence);

            if (app->fields & APPLICATION_ENTRY_VERSION)
                DebugMessage(DEBUG_ATTRIBUTE, "\t\tVersion: %s(%d)\n",
                    app->version.value.s_value,
                    app->version.confidence);
        }
    }
    if (i==0)
        DebugMessage(DEBUG_ATTRIBUTE, "\t\tNone\n");

    DebugMessage(DEBUG_ATTRIBUTE, "\tClients:\n");
    for (i=0, app = host->clients; app; app = app->next,i++)
    {
        DebugMessage(DEBUG_ATTRIBUTE, "\tClient #%d:\n", i);
        DebugMessage(DEBUG_ATTRIBUTE, "\t\tIPProtocol: %s(%d)\tProtocol %s(%d)\n",
                app->ipproto.value.s_value,
                app->ipproto.confidence,
                app->protocol.value.s_value,
                app->protocol.confidence);

        if (app->fields & APPLICATION_ENTRY_PORT)
        {
            DebugMessage(DEBUG_ATTRIBUTE, "\t\tPort: %s(%d)\n",
                app->port.value.s_value,
                app->port.confidence);
        }

        if (app->fields & APPLICATION_ENTRY_APPLICATION)
        {
            DebugMessage(DEBUG_ATTRIBUTE, "\t\tApplication: %s(%d)\n",
                app->application.value.s_value,
                app->application.confidence);

            if (app->fields & APPLICATION_ENTRY_VERSION)
                DebugMessage(DEBUG_ATTRIBUTE, "\t\tVersion: %s(%d)\n",
                    app->version.value.s_value,
                    app->version.confidence);
        }
    }
    if (i==0)
    {
        DebugMessage(DEBUG_ATTRIBUTE, "\t\tNone\n");
    }
}
#endif

int SFAT_AddHostEntryToMap()
{
    HostAttributeEntry *host = current_host;
    int ret;
    u_int32_t ipAddr;

    SFAT_CHECKHOST;

    DEBUG_WRAP(PrintHostAttributeEntry(host););

    ipAddr = host->ipAddr;

    ret = sfrt_insert(&ipAddr, host->bits, host,
                        RT_FAVOR_SPECIFIC, attribute_lookup_table_tmp);

    if (ret != RT_SUCCESS)
    {
        if (ret == RT_POLICY_TABLE_EXCEEDED)
        {
            SnortSnprintf(sfat_error_message, STD_BUF,
                "AttributeTable insertion failed: %d Insufficient "
                "space in attribute table, only configured to store %d hosts\n",
                ret, pv.max_attribute_hosts);
            sfat_grammar_error_printed = 1;
        }
        else
        {
            SnortSnprintf(sfat_error_message, STD_BUF,
                "AttributeTable insertion failed: %d '%s'\n",
                ret, rt_error_messages[ret]);
            sfat_grammar_error_printed = 1;
        }
    }

    current_host = NULL;

    return ret == RT_SUCCESS ? SFAT_OK : SFAT_ERROR;
}

HostAttributeEntry *SFAT_LookupHostEntryByIp4Addr(u_int32_t ipAddr)
{
    HostAttributeEntry *host = NULL;

    host = sfrt_lookup(&ipAddr, attribute_lookup_table);

    if (host)
    {
        /* Set the policy values for Frag & Stream if not already set */
        //TODO: SetTargetBasedPolicy(host);
    }

    return host;
}

HostAttributeEntry *SFAT_LookupHostEntryBySrc(Packet *p)
{
    u_int32_t ipAddr;

    if (!p || !p->iph)
        return NULL;

    ipAddr = ntohl(p->iph->ip_src.s_addr);

    return SFAT_LookupHostEntryByIp4Addr(ipAddr);
}

HostAttributeEntry *SFAT_LookupHostEntryByDst(Packet *p)
{
    u_int32_t ipAddr;

    if (!p || !p->iph)
        return NULL;

    ipAddr = ntohl(p->iph->ip_dst.s_addr);

    return SFAT_LookupHostEntryByIp4Addr(ipAddr);
}

static GetPolicyIdFunc updatePolicyCallback;
static GetPolicyIdsCallbackList *updatePolicyCallbackList = NULL;
void SFAT_SetPolicyCallback(void *host_attr_ent)
{
    HostAttributeEntry *host_entry = (HostAttributeEntry*)host_attr_ent;

    if (!host_entry)
        return;

    updatePolicyCallback(host_entry);

    return;
}

void SFAT_SetPolicyIds(GetPolicyIdFunc policyCallback)
{
    GetPolicyIdsCallbackList *list_entry, *new_list_entry = NULL;
    updatePolicyCallback = policyCallback;

    sfrt_iterate(attribute_lookup_table, SFAT_SetPolicyCallback);

    if (!updatePolicyCallbackList)
    {
        /* No list present, so no attribute table... bye-bye */
        return;
    }

    /* Look for this callback in the list */
    list_entry = updatePolicyCallbackList;
    while (list_entry)
    {
        if (list_entry->policyCallback == policyCallback)
            return; /* We're done with this one */

        if (list_entry->next)
        {
            list_entry = list_entry->next;
        }
        else
        {
            /* Leave list_entry pointint to last node in list */
            break;
        }
    }

    /* Wasn't there, add it so that when we reload the table,
     * we can set those policy entries on reload. */
    new_list_entry = (GetPolicyIdsCallbackList *)SnortAlloc(sizeof(GetPolicyIdsCallbackList));
    new_list_entry->policyCallback = policyCallback;
    if (list_entry)
    {
        /* list_entry is valid here since there was at least an
         * empty head entry in the list. */
        list_entry->next = new_list_entry;
    }
}

void SFAT_CleanupCallback(void *host_attr_ent)
{
    HostAttributeEntry *host_entry = (HostAttributeEntry*)host_attr_ent;
    FreeHostEntry(host_entry);
}

void SFAT_Cleanup()
{
    GetPolicyIdsCallbackList *list_entry, *tmp_list_entry = NULL;
    if (attribute_map_table)
    {
        sfxhash_delete(attribute_map_table);
        attribute_map_table = NULL;
    }

    if (attribute_map_table_old)
    {
        sfxhash_delete(attribute_map_table_old);
        attribute_map_table_old = NULL;
    }

    if (attribute_map_table_tmp)
    {
        sfxhash_delete(attribute_map_table_tmp);
        attribute_map_table_tmp = NULL;
    }

    if (attribute_lookup_table)
    {
        sfrt_cleanup(attribute_lookup_table, SFAT_CleanupCallback);
        sfrt_free(attribute_lookup_table);
        attribute_lookup_table = NULL;
    }

    if (attribute_lookup_table_old)
    {
        sfrt_cleanup(attribute_lookup_table_old, SFAT_CleanupCallback);
        sfrt_free(attribute_lookup_table_old);
        attribute_lookup_table_old = NULL;
    }

    if (attribute_lookup_table_tmp)
    {
        sfrt_cleanup(attribute_lookup_table_tmp, SFAT_CleanupCallback);
        sfrt_free(attribute_lookup_table_tmp);
        attribute_lookup_table_tmp = NULL;
    }
    FreeProtoocolReferenceTable();

    if (sfat_saved_file)
    {
        free(sfat_saved_file);
        sfat_saved_file = NULL;
    }

    if (updatePolicyCallbackList)
    {
        list_entry = updatePolicyCallbackList;
        while (list_entry)
        {
            tmp_list_entry = list_entry->next;
            free(list_entry);
            list_entry = tmp_list_entry;
        }
        updatePolicyCallbackList = NULL;
    }
}

#define set_attribute_table_flag(flag) \
    pv.reload_attribute_table_flags |= flag;
#define clear_attribute_table_flag(flag) \
    pv.reload_attribute_table_flags &= ~flag;
#define check_attribute_table_flag(flag) \
    (pv.reload_attribute_table_flags & flag)

static void SigAttributeTableReloadHandler(int signal)
{
    /* If we're already reloading, don't do anything. */
    if (check_attribute_table_flag(ATTRIBUTE_TABLE_RELOADING_FLAG))
        return;

    /* Set flag to reload attribute table */
    set_attribute_table_flag(ATTRIBUTE_TABLE_RELOAD_FLAG);
}

void SFAT_VTAlrmHandler(int signal)
{
    /* Do nothing, just used to wake the sleeping dog... */
    return;
}

void *SFAT_ReloadAttributeTableThread(void *arg)
{
#ifndef WIN32
    sigset_t mtmask, oldmask;
    int ret;
    int reloads = 0;

    /* This seems to be necessary if Linuxthreads are being used
     * (as opposed to NPTL) since the child threads do not inherit
     * the parent thread's uid/gid if the parent thread did a
     * setuid()/setgid().  Found that threads would eventually get
     * hung up in __libc_free in the mutex locks if this wasn't done. */
    SetUidGid();

    sigemptyset(&mtmask);
    pv.attribute_reload_thread_pid = getpid();

    /* Get the current set of signals inherited from main thread.*/
    pthread_sigmask(SIG_UNBLOCK, &mtmask, &oldmask);

    /* Now block those signals from being delivered to this thread.
     * now Main receives all signals. */
    pthread_sigmask(SIG_BLOCK, &oldmask, NULL);

    /* And allow SIGVTALRM through */
    signal (SIGVTALRM, SFAT_VTAlrmHandler);  if(errno!=0) errno=0;
    sigemptyset(&mtmask);
    sigaddset(&mtmask, SIGVTALRM);
    pthread_sigmask(SIG_UNBLOCK, &mtmask, NULL);

    pv.attribute_reload_thread_running = 1;

    /* Checks the flag and terminates the attribute reload thread.
     *
     * Receipt of VTALRM signal pulls it out of the idle sleep (at
     * bottom of while().  Thread exits normally on next iteration
     * through its loop because stop flag is set.
     */
    while (!pv.attribute_reload_thread_stop)
    {
#ifdef DEBUG
        DebugMessage(DEBUG_ATTRIBUTE,
            "AttrReloadThread: Checking for new attr table...\n");
#endif
        ret = SFAT_ERROR;

        /* Is there an old table waiting to be cleaned up? */
        if (check_attribute_table_flag(ATTRIBUTE_TABLE_TAKEN_FLAG))
        {
            if (check_attribute_table_flag(ATTRIBUTE_TABLE_AVAILABLE_FLAG))
            {
#ifdef DEBUG
                DebugMessage(DEBUG_ATTRIBUTE,
                    "AttrReloadThread: Freeing old attr table...\n");
#endif
                /* Free the map and attribute tables that are stored in
                 * attribute_map_table_old and attribute_lookup_table_old */
                sfxhash_delete(attribute_map_table_old);
                attribute_map_table_old = NULL;
    
                sfrt_cleanup(attribute_lookup_table_old, SFAT_CleanupCallback);
                sfrt_free(attribute_lookup_table_old);
                attribute_lookup_table_old = NULL;
                clear_attribute_table_flag(ATTRIBUTE_TABLE_AVAILABLE_FLAG);
            }
            clear_attribute_table_flag(ATTRIBUTE_TABLE_PARSE_FAILED_FLAG);
            clear_attribute_table_flag(ATTRIBUTE_TABLE_TAKEN_FLAG);
            continue;
        }
        else if (check_attribute_table_flag(ATTRIBUTE_TABLE_RELOAD_FLAG) &&
                 !check_attribute_table_flag(ATTRIBUTE_TABLE_AVAILABLE_FLAG) &&
                 !check_attribute_table_flag(ATTRIBUTE_TABLE_PARSE_FAILED_FLAG))
        {
            /* Is there an new table ready? */
            set_attribute_table_flag(ATTRIBUTE_TABLE_RELOADING_FLAG);
#ifdef DEBUG
            DebugMessage(DEBUG_ATTRIBUTE,
                "AttrReloadThread: loading new attr table.\n");
#endif
            reloads++;
            if (sfat_saved_file)
            {
                /* Initialize a new lookup table */
                if (!attribute_lookup_table_tmp)
                {
                    /* Add 1 to max for table purposes */
                    attribute_lookup_table_tmp = sfrt_new(DIR_16_4x4, IPv4, pv.max_attribute_hosts+1, sizeof(HostAttributeEntry) * 200);
                    if (!attribute_lookup_table_tmp)
                    {
                        SnortSnprintf(sfat_error_message, STD_BUF,
                            "Failed to initialize memory for new attribute table\n");
                        clear_attribute_table_flag(ATTRIBUTE_TABLE_RELOAD_FLAG);
                        clear_attribute_table_flag(ATTRIBUTE_TABLE_RELOADING_FLAG);
                        set_attribute_table_flag(ATTRIBUTE_TABLE_PARSE_FAILED_FLAG);
                        continue;
                    }
                }
                ret = ParseTargetMap(sfat_saved_file);
                if (ret == SFAT_OK)
                {
                    GetPolicyIdsCallbackList *list_entry = NULL;
                    /* Set flag that a new table is available.  Main
                     * process will check that flag and do the swap.
                     * After the new table is in use, the available
                     * flag should be cleared, the taken flag gets set
                     * and we'll go off and free the old one.
                     */

                    /* Set the policy IDs in the new table... */
                    list_entry = (GetPolicyIdsCallbackList *)arg;
                    while (list_entry)
                    {
                        if (list_entry->policyCallback)
                        {
                            sfrt_iterate(attribute_lookup_table_tmp,
                                (void *)list_entry->policyCallback);
                        }
                        list_entry = list_entry->next;
    }

                    set_attribute_table_flag(ATTRIBUTE_TABLE_AVAILABLE_FLAG);
                }
                else
                {
                    /* Failed to parse, clean it up */
                    if (attribute_map_table_tmp)
                        sfxhash_delete(attribute_map_table_tmp);
                    attribute_map_table_tmp = NULL;

                    sfrt_cleanup(attribute_lookup_table_tmp, SFAT_CleanupCallback);
                    sfrt_free(attribute_lookup_table_tmp);
                    attribute_lookup_table_tmp = NULL;

                    set_attribute_table_flag(ATTRIBUTE_TABLE_PARSE_FAILED_FLAG);
                }
            }
            clear_attribute_table_flag(ATTRIBUTE_TABLE_RELOAD_FLAG);
            clear_attribute_table_flag(ATTRIBUTE_TABLE_RELOADING_FLAG);
        }
        else
        {
            /* Sleep for 60 seconds */
#ifdef DEBUG
            DebugMessage(DEBUG_ATTRIBUTE,
                "AttrReloadThread: Checked for new attr table... sleeping.\n");
#endif
            sleep(60);
        }
    }
#ifdef DEBUG
    DebugMessage(DEBUG_ATTRIBUTE,
        "AttrReloadThread: exiting... Handled %d reloads\n", reloads);
#endif

    pv.attribute_reload_thread_running = 0;
    pthread_exit(NULL);
#endif /* !Win32 */
    return NULL;
}

void AttributeTableReloadCheck()
{
    if (check_attribute_table_flag(ATTRIBUTE_TABLE_TAKEN_FLAG))
    {
        return; /* Nothing to do, waiting for thread to clear this
                 * flag... */
    }
    /* Swap the attribute table pointers. */
    else if (check_attribute_table_flag(ATTRIBUTE_TABLE_AVAILABLE_FLAG))
    {
        LogMessage("Swapping Attribute Tables.\n");
        /***Do this on receipt of new packet ****/
        /***Avoids need for mutex****/
        attribute_lookup_table_old = attribute_lookup_table;
        attribute_lookup_table = attribute_lookup_table_tmp;
        attribute_lookup_table_tmp = NULL;

        attribute_map_table_old = attribute_map_table;
        attribute_map_table = attribute_map_table_tmp;
        attribute_map_table_tmp = NULL;

        /* Set taken to indicate we've taken the new table */
        set_attribute_table_flag(ATTRIBUTE_TABLE_TAKEN_FLAG);

        sfPerf.sfBase.iAttributeHosts = SFAT_NumberOfHosts();
        sfPerf.sfBase.iAttributeReloads++;
        pc.attribute_table_reloads++;
    }
    else if (check_attribute_table_flag(ATTRIBUTE_TABLE_PARSE_FAILED_FLAG))
    {
        LogMessage(sfat_error_message);
        /* Set taken to indicate we've taken the error message */
        set_attribute_table_flag(ATTRIBUTE_TABLE_TAKEN_FLAG);
    }
}

int SFAT_ParseAttributeTable(char *args)
{
    char **toks;
    int num_toks;
    int ret;

    /* Initialize lookup table */
    if (!attribute_lookup_table_tmp)
    {
        /* Add 1 to max for table purposes */
        attribute_lookup_table_tmp = sfrt_new(DIR_16_4x4, IPv4, pv.max_attribute_hosts+1, sizeof(HostAttributeEntry) * 200);
        if (!attribute_lookup_table_tmp)
        {
            FatalError("Failed to initialize attribute table memory\n");
        }
    }

    /* Parse filename */
    toks = mSplit(args, " ", 4, &num_toks, 0);

    if (num_toks != 3)
    {
        FatalError("%s(%d) ==> attribute_table must have 2 parameters\n",
                file_name, file_line);
    }

    if (!(strcasecmp(toks[1], "filename") == 0))
    {
        FatalError("%s(%d) ==> attribute_table must have 2 arguments, the 1st "
                "is 'filename'\n",
                file_name, file_line);
    }

    ret = ParseTargetMap(toks[2]);

    if (ret == SFAT_OK)
    {
        attribute_lookup_table = attribute_lookup_table_tmp;
        attribute_lookup_table_tmp = NULL;
        attribute_map_table = attribute_map_table_tmp;
        attribute_map_table_tmp = NULL;
    }
    else
    {
        LogMessage(sfat_error_message);
        FatalError("%s(%d) ==> failed to load attribute table from %s\n",
            file_name, file_line, toks[2]);
    }
    mSplitFree(&toks, num_toks);

    /* Create Thread to handle reparsing stuff... */
    sfPerf.sfBase.iAttributeHosts = SFAT_NumberOfHosts();
    LogMessage("Attribute Table Loaded with " STDu64 " hosts\n", sfPerf.sfBase.iAttributeHosts);

    /* Set up the head (empty) node in the policy callback list to
     * pass to thread.*/
    updatePolicyCallbackList = (GetPolicyIdsCallbackList *)SnortAlloc(sizeof(GetPolicyIdsCallbackList));
#ifndef WIN32
    if (!pv.disable_attribute_reload_thread)
    {
        LogMessage("Attribute Table Reload Thread Starting...\n");
        /* Register signal handler for attribute table. */
        signal(SIGNAL_SNORT_READ_ATTR_TBL, SigAttributeTableReloadHandler);
        if(errno!=0) errno=0;

        if (pthread_create(&pv.attribute_reload_thread_id, NULL,
            SFAT_ReloadAttributeTableThread, updatePolicyCallbackList))
        {
            FatalError("Failed to start thread to handle reloading attribute table\n");
        }
        while (!pv.attribute_reload_thread_running)
        {
            sleep(1);
        }
        LogMessage("Attribute Table Reload Thread Started, thread %d (%d)\n",
            pv.attribute_reload_thread_id, pv.attribute_reload_thread_pid);
    }
#endif
    return SFAT_OK;
}

#endif /* TARGET_BASED */
