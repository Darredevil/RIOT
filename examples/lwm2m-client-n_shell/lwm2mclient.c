/*******************************************************************************
 *
 * Copyright (c) 2013, 2014 Intel Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * The Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    David Navarro, Intel Corporation - initial API and implementation
 *    Benjamin Cabé - Please refer to git log
 *    Fabien Fleutot - Please refer to git log
 *    Simon Bernard - Please refer to git log
 *    Julien Vermillard - Please refer to git log
 *    Axel Lorente - Please refer to git log
 *    Toby Jaffey - Please refer to git log
 *    Bosch Software Innovations GmbH - Please refer to git log
 *    Pascal Rieux - Please refer to git log
 *
 *******************************************************************************/

/*
 Copyright (c) 2013, 2014 Intel Corporation

 Redistribution and use in source and binary forms, with or without modification,
 are permitted provided that the following conditions are met:

     * Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above copyright notice,
       this list of conditions and the following disclaimer in the documentation
       and/or other materials provided with the distribution.
     * Neither the name of Intel Corporation nor the names of its contributors
       may be used to endorse or promote products derived from this software
       without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 THE POSSIBILITY OF SUCH DAMAGE.

 David Navarro <david.navarro@intel.com>
 Bosch Software Innovations GmbH - Please refer to git log

*/

#include "lwm2mclient.h"
#include "liblwm2m.h"
#include "commandline.h"
//#include "connection.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>

#include "connection-n_shell.h"


#include "shell.h"
#include "board_uart0.h"
#include "posix_io.h"

#include "thread.h"
#include "msg.h"
#include "kernel.h"
#include "net/ng_pktdump.h"
#include "net/ng_netbase.h"
#include "net/ng_ipv6/addr.h"
#include "net/ng_ipv6/hdr.h"
#include "net/ng_sixlowpan.h"
#include "net/ng_udp.h"
#include "net/ng_pkt.h"
#include "od.h"


/*
 * Bugfix: REST_MAX_CHUNK_SIZE is the size of the payload!
 * ensure sync with: er_coap_13.h COAP_MAX_PACKET_SIZE!
 * or internals.h LWM2M_MAX_PACKET_SIZE!
 */
#define MAX_PACKET_SIZE 198

#define DEFAULT_PORT "4242"
#define DEFAULT_PORT_INT 4242

static kernel_pid_t _pid = KERNEL_PID_UNDEF;
static char _stack[NG_PKTDUMP_STACKSIZE];

// static kernel_pid_t _pid_step = KERNEL_PID_UNDEF;
// static char _stack_step[NG_PKTDUMP_STACKSIZE];


static ng_netreg_entry_t client = {NULL, NG_NETREG_DEMUX_CTX_ALL,
                                   KERNEL_PID_UNDEF};
// static ng_netreg_entry_t client_step = {NULL, NG_NETREG_DEMUX_CTX_ALL,
//                                    KERNEL_PID_UNDEF};
lwm2m_context_t * lwm2mH = NULL;


int g_reboot = 0;
int batterylevelchanging = 0;
char * serverIp;
//char serverIp[26];

#ifdef LWM2M_BOOTSTRAP
    lwm2m_bootstrap_state_t previousBootstrapState = NOT_BOOTSTRAPPED;
#endif

#define OBJ_COUNT 9
lwm2m_object_t * objArray[OBJ_COUNT];

// only backup security and server objects
# define BACKUP_OBJECT_COUNT 2
lwm2m_object_t * backupObjectArray[BACKUP_OBJECT_COUNT];

typedef struct
{
    lwm2m_object_t * securityObjP;
    lwm2m_object_t * serverObject;
    int sock;
    connection_t * connList;
} client_data_t;

client_data_t data;

// static void prv_quit(char * buffer,
//                      void * user_data)
// {
//     g_quit = 1;
// }


static lwm2m_object_t * prv_find_object(lwm2m_context_t * contextP,
                                        uint16_t Id)
{
    int i;

    for (i = 0 ; i < contextP->numObject ; i++)
    {
        if (contextP->objectList[i]->objID == Id)
        {
            return contextP->objectList[i];
        }
    }

    return NULL;
}

void handle_value_changed(lwm2m_context_t * lwm2mH,
                          lwm2m_uri_t * uri,
                          const char * value,
                          size_t valueLength)
{
    lwm2m_object_t * object = prv_find_object(lwm2mH, uri->objectId);

    if (NULL != object)
    {
        if (object->writeFunc != NULL)
        {
            lwm2m_tlv_t * tlvP;
            int result;

            tlvP = lwm2m_tlv_new(1);
            if (tlvP == NULL)
            {
                fprintf(stderr, "Internal allocation failure !\n");
                return;
            }
            tlvP->flags = LWM2M_TLV_FLAG_STATIC_DATA | LWM2M_TLV_FLAG_TEXT_FORMAT;
#ifdef LWM2M_BOOTSTRAP
            if (lwm2mH->bsState == BOOTSTRAP_PENDING) {
                tlvP->flags |= LWM2M_TLV_FLAG_BOOTSTRAPPING;
            }
#endif
            tlvP->id = uri->resourceId;
            tlvP->length = valueLength;
            tlvP->value = (uint8_t*) value;

            result = object->writeFunc(uri->instanceId, 1, tlvP, object);
            if (COAP_405_METHOD_NOT_ALLOWED == result)
            {
                switch (uri->objectId)
                {
                case LWM2M_DEVICE_OBJECT_ID:
                    result = device_change(tlvP, object);
                    break;
                default:
                    break;
                }
            }

            if (COAP_204_CHANGED != result)
            {
                fprintf(stderr, "Failed to change value!\n");
            }
            else
            {
                fprintf(stderr, "value changed!\n");
                lwm2m_resource_value_changed(lwm2mH, uri);
            }
            lwm2m_tlv_free(1, tlvP);
            return;
        }
        else
        {
            fprintf(stderr, "write not supported for specified resource!\n");
        }
        return;
    }
    else
    {
        fprintf(stderr, "Object not found !\n");
    }
}

static void * prv_connect_server(uint16_t secObjInstID, void * userData)
{
    client_data_t * dataP;
    char * uri;
    char * host, *host_dup;
    char * portStr;
    int port, portLength = 0;
    char * ptr;
    connection_t * newConnP = NULL;

    dataP = (client_data_t *)userData;
    //TODO check wtf
    //dataP = (client_data_t *)((void*)lwm2mH);
    //dataP = &data;

    uri = get_server_uri(dataP->securityObjP, secObjInstID);
    //printf("uri = <%s>\n",uri);

    if (uri == NULL) return NULL;

    // parse uri in the form "coaps://[host]:[port]"
    if (0==strncmp(uri, "coaps://", strlen("coaps://"))) {
        host = uri+strlen("coaps://");
    }
    else if (0==strncmp(uri, "coap://",  strlen("coap://"))) {
        host = uri+strlen("coap://");
    }
    else {
        goto exit;
    }
    // portStr = strchr(host, ':');
    // if (portStr == NULL) goto exit;
    // // split strings
    // *portStr = 0;
    // portStr++;
    // port = strtol(portStr, &ptr, 10);

    host_dup = lwm2m_strdup(host);
    //printf(" host1 = <%s>\n",host_dup);
    portStr = get_end_of_arg(host);
    //printf(" host2 = <%s>\n",host_dup);
    while(*portStr != ':') {portStr--; portLength++; }
    portStr++;
    //printf("portStr = %s\n", portStr);
    port = strtol(portStr, &ptr, 10);
    //printf("port = <%d>\n", port);
    //while(*host_dup != ':') host_dup++;
    //*host_dup = '\0';
    host_dup[strlen(host_dup) - portLength] = '\0';

    //TODO repair this, hardcoded for testing
    //port = 4242;
    //char host2[26] = "fe80::1033:f2ff:fe77:46b7";
    //host2[25] = '\0';

    //printf(" host = <%s>\n",host_dup );

    // if (*ptr != 0) {
    //     goto exit;
    // }



    fprintf(stderr, "Trying to connect to LWM2M Server at %s:%d\r\n", host_dup, port);
    newConnP = connection_create(dataP->connList, host_dup, port);
    if (newConnP == NULL) {
        fprintf(stderr, "Connection creation failed.\r\n");
    }
    else {
        dataP->connList = newConnP;
    }

exit:
    lwm2m_free(uri);
    return (void *)newConnP;
}

static uint8_t prv_buffer_send(void * sessionH,
                               uint8_t * buffer,
                               size_t length,
                               void * userdata)
{
    (void)userdata;

    connection_t * connP = (connection_t*) sessionH;

    if (connP == NULL)
    {
        fprintf(stderr, "#> failed sending %zu bytes, missing connection\r\n", length);
        return COAP_500_INTERNAL_SERVER_ERROR ;
    }

    if (-1 == connection_send(connP, buffer, length))
    {
        fprintf(stderr, "#> failed sending %zu bytes\r\n", length);
        return COAP_500_INTERNAL_SERVER_ERROR ;
    }
    conn_s_updateTxStatistic(objArray[7], (uint16_t)length, false);
    fprintf(stderr, "#> sent %zu bytes\r\n", length);
    return COAP_NO_ERROR;
}

static int prv_output_servers(int argc, char** argv)
{
    //lwm2m_context_t * lwm2mH = (lwm2m_context_t *) user_data;
    lwm2m_server_t * targetP;

    (void)argc;
    (void)argv;

    targetP = lwm2mH->serverList;

    if (targetP == NULL)
    {
        fprintf(stdout, "No server.\r\n");
        return -1;
    }

    for (targetP = lwm2mH->serverList ; targetP != NULL ; targetP = targetP->next)
    {
        fprintf(stdout, "Server ID %d:\r\n", targetP->shortID);
        fprintf(stdout, "\tstatus: ");
        switch(targetP->status)
        {
        case STATE_DEREGISTERED:
            fprintf(stdout, "DEREGISTERED\r\n");
            break;
        case STATE_REG_PENDING:
            fprintf(stdout, "REGISTRATION PENDING\r\n");
            break;
        case STATE_REGISTERED:
            fprintf(stdout, "REGISTERED location: \"%s\"\r\n", targetP->location);
            fprintf(stdout, "\tLifetime: %lu s\r\n", (unsigned long)targetP->lifetime);
            break;
        case STATE_REG_UPDATE_PENDING:
            fprintf(stdout, "REGISTRATION UPDATE PENDING\r\n");
            break;
        case STATE_DEREG_PENDING:
            fprintf(stdout, "DEREGISTRATION PENDING\r\n");
            break;
        case STATE_REG_FAILED:
            fprintf(stdout, "REGISTRATION FAILED\r\n");
            break;
        }
        fprintf(stdout, "\r\n");
    }

    return 0;
}

static int prv_change(int argc, char** argv)
{
    //lwm2m_context_t * lwm2mH = (lwm2m_context_t *) user_data;
    lwm2m_uri_t uri;
    char * end = NULL;
    char *buffer;
    int result;

    if(argc < 2) goto syntax_error;

    end = get_end_of_arg(argv[1]);
    if (end[0] == 0) goto syntax_error;

    result = lwm2m_stringToUri(argv[1], end - argv[1], &uri);
    if (result == 0) goto syntax_error;

    //buffer = get_next_arg(end, &end);

    //if (buffer[0] == 0)
    if(argc == 2)
    {
        fprintf(stderr, "report change!\n");
        lwm2m_resource_value_changed(lwm2mH, &uri);
    }
    else
    {
        buffer = argv[2];
        handle_value_changed(lwm2mH, &uri, buffer, get_end_of_arg(buffer) - buffer);
    }
    return 0;

syntax_error:
    fprintf(stdout, "Syntax error !\n");
    return -1;
}

static int prv_object_list(int argc, char** argv)
{
    //lwm2m_context_t * lwm2mH = (lwm2m_context_t *)user_data;
    uint16_t i;

    (void)argc;
    (void)argv;

    for (i = 0 ; i < lwm2mH->numObject ; i++)
    {
        lwm2m_object_t * objectP;

        objectP = lwm2mH->objectList[i];
        if (objectP->instanceList == NULL)
        {
            fprintf(stdout, "/%d ", objectP->objID);
        }
        else
        {
            lwm2m_list_t * instanceP;

            for (instanceP = objectP->instanceList; instanceP != NULL ; instanceP = instanceP->next)
            {
                fprintf(stdout, "/%d/%d  ", objectP->objID, instanceP->id);
            }
        }
        fprintf(stdout, "\r\n");
    }

    return 0;
}

static void prv_instance_dump(lwm2m_object_t * objectP,
                              uint16_t id)
{
    int numData;
    lwm2m_tlv_t * dataArray;
    int size;
    uint8_t * buffer;
    int i;
    uint16_t res;

    numData = 0;
    res = objectP->readFunc(id, &numData, &dataArray, objectP);
    if (res != COAP_205_CONTENT)
    {
        printf("Error ");
        print_status(stdout, res);
        printf("\r\n");
        return;
    }

    dump_tlv(stdout, numData, dataArray, 0);

    size = lwm2m_tlv_serialize(numData, dataArray, &buffer);
    printf("char objectTlv[%d] = {", size);
    for (i = 0 ; i < size ; i++)
    {
        printf("0x%02X, ", buffer[i]);
    }
    printf("\b\b};\r\n");
    lwm2m_tlv_free(numData, dataArray);
    lwm2m_free(buffer);
}


static int prv_object_dump(int argc, char** argv)
{
    //lwm2m_context_t * lwm2mH = (lwm2m_context_t *) user_data;
    lwm2m_uri_t uri;
    char * end = NULL;
    int result;
    lwm2m_object_t * objectP;

    (void)argc;

    end = get_end_of_arg(argv[1]);
    if (end[0] == 0) goto syntax_error;

    result = lwm2m_stringToUri(argv[1], end - argv[1], &uri);
    if (result == 0) goto syntax_error;
    if (uri.flag & LWM2M_URI_FLAG_RESOURCE_ID) goto syntax_error;

    objectP = prv_find_object(lwm2mH, uri.objectId);
    if (objectP == NULL)
    {
        fprintf(stdout, "Object not found.\n");
        return 0;
    }

    if (uri.flag & LWM2M_URI_FLAG_INSTANCE_ID)
    {
        prv_instance_dump(objectP, uri.instanceId);
    }
    else
    {
        lwm2m_list_t * instanceP;

        for (instanceP = objectP->instanceList; instanceP != NULL ; instanceP = instanceP->next)
        {
            fprintf(stdout, "Instance %d:\r\n", instanceP->id);
            prv_instance_dump(objectP, instanceP->id);
            fprintf(stdout, "\r\n");
        }
    }

    return 0;

syntax_error:
    fprintf(stdout, "Syntax error !\n");
    return -1;
}

static int prv_update(int argc, char** argv)
{
    //lwm2m_context_t * lwm2mH = (lwm2m_context_t *)user_data;
    //if (buffer[0] == 0) goto syntax_error;

    if(argc != 2) goto syntax_error;

    uint16_t serverId = (uint16_t) atoi(argv[1]);
    int res = lwm2m_update_registration(lwm2mH, serverId);
    if (res != 0)
    {
        fprintf(stdout, "Registration update error: %d\n", res);
    }
    return 0;

syntax_error:
    fprintf(stdout, "Syntax error !\n");
    return -1;
}

static void update_battery_level(lwm2m_context_t * context)
{
    static time_t next_change_time = 0;
    time_t tv_sec;

    tv_sec = lwm2m_gettime();
    if (tv_sec < 0) return;

    if (next_change_time < tv_sec)
    {
        char value[15];
        int valueLength;
        lwm2m_uri_t uri;
        int level = rand() % 100;

        if (0 > level) level = -level;
        if (lwm2m_stringToUri("/3/0/9", 6, &uri))
        {
            valueLength = sprintf(value, "%d", level);
            fprintf(stderr, "New Battery Level: %d\n", level);
            handle_value_changed(context, &uri, value, valueLength);
        }
        level = rand() % 20;
        if (0 > level) level = -level;
        next_change_time = tv_sec + level + 10;
    }
}

#ifdef LWM2M_BOOTSTRAP

static int prv_initiate_bootstrap(int argc, char** argv)
{
    (void)argc;
    (void)argv;

    //lwm2m_context_t * lwm2mH = (lwm2m_context_t *)user_data;
    if ((lwm2mH->bsState != BOOTSTRAP_CLIENT_HOLD_OFF)
            && (lwm2mH->bsState != BOOTSTRAP_PENDING)) {
        lwm2mH->bsState = BOOTSTRAP_REQUESTED;
    }

    return 0;
}

static int prv_display_objects(int argc, char** argv)
{

    (void)argc;
    (void)argv;

    //lwm2m_context_t * lwm2mH = (lwm2m_context_t *)user_data;
    int i;
    if (NULL != lwm2mH->objectList) {
        for (i = 0; i < lwm2mH->numObject; i++) {
            lwm2m_object_t * object = lwm2mH->objectList[i];
            if (NULL != object) {
                switch (object->objID)
                {
                case LWM2M_SECURITY_OBJECT_ID:
                    display_security_object(object);
                    break;
                case LWM2M_SERVER_OBJECT_ID:
                    display_server_object(object);
                    break;
                case LWM2M_ACL_OBJECT_ID:
                    break;
                case LWM2M_DEVICE_OBJECT_ID:
                    display_device_object(object);
                    break;
                case LWM2M_CONN_MONITOR_OBJECT_ID:
                    break;
                case LWM2M_FIRMWARE_UPDATE_OBJECT_ID:
                    display_firmware_object(object);
                    break;
                case LWM2M_LOCATION_OBJECT_ID:
                    display_location_object(object);
                    break;
                case LWM2M_CONN_STATS_OBJECT_ID:
                    break;
                case TEST_OBJECT_ID:
                    display_test_object(object);
                    break;
                }
            }
        }
    }

    return 0;
}

static int prv_display_backup(int argc, char** argv)
{

    (void)argc;
    (void)argv;

    if (NULL != backupObjectArray) {
        int i;
        for (i = 0 ; i < BACKUP_OBJECT_COUNT ; i++) {
            lwm2m_object_t * object = backupObjectArray[i];
            if (NULL != object) {
                switch (object->objID)
                {
                case LWM2M_SECURITY_OBJECT_ID:
                    display_security_object(object);
                    break;
                case LWM2M_SERVER_OBJECT_ID:
                    display_server_object(object);
                    break;
                default:
                    break;
                }
            }
        }
    }

    return 0;
}

static void prv_display_bootstrap_state(lwm2m_bootstrap_state_t bootstrapState)
{
    switch (bootstrapState) {
    case NOT_BOOTSTRAPPED:
        fprintf(stderr, "NOT BOOTSTRAPPED\r\n");
        break;
    case BOOTSTRAP_REQUESTED:
        fprintf(stderr, "DI BOOTSTRAP REQUESTED\r\n");
        break;
    case BOOTSTRAP_CLIENT_HOLD_OFF:
        fprintf(stderr, "DI BOOTSTRAP CLIENT HOLD OFF\r\n");
        break;
    case BOOTSTRAP_INITIATED:
        fprintf(stderr, "DI BOOTSTRAP INITIATED\r\n");
        break;
    case BOOTSTRAP_PENDING:
        fprintf(stderr, "DI BOOTSTRAP PENDING\r\n");
        break;
    case BOOTSTRAP_FINISHED:
        fprintf(stderr, "DI BOOTSTRAP FINISHED\r\n");
        break;
    case BOOTSTRAP_FAILED:
        fprintf(stderr, "DI BOOTSTRAP FAILED\r\n");
        break;
    case BOOTSTRAPPED:
        fprintf(stderr, "BOOTSTRAPPED\r\n");
        break;
    default:
        break;
    }
}

static void prv_backup_objects(lwm2m_context_t * context)
{
    uint16_t i;

    for (i = 0; i < BACKUP_OBJECT_COUNT; i++) {
        if (NULL != backupObjectArray[i]) {
            backupObjectArray[i]->closeFunc(backupObjectArray[i]);
            lwm2m_free(backupObjectArray[i]);
        }
        backupObjectArray[i] = (lwm2m_object_t *)lwm2m_malloc(sizeof(lwm2m_object_t));
        memset(backupObjectArray[i], 0, sizeof(lwm2m_object_t));
    }

    /*
     * Backup content of objects 0 (security) and 1 (server)
     */
    for (i = 0; i < context->numObject; i++) {
        lwm2m_object_t * object = context->objectList[i];
        if (NULL != object) {
            switch (object->objID)
            {
            case LWM2M_SECURITY_OBJECT_ID:
                copy_security_object(backupObjectArray[0], object);
                break;
            case LWM2M_SERVER_OBJECT_ID:
                copy_server_object(backupObjectArray[1], object);
                break;
            default:
                break;
            }
        }
    }
}

static void prv_restore_objects(lwm2m_context_t * context)
{
    uint16_t i;

    /*
     * Restore content  of objects 0 (security) and 1 (server)
     */
    for (i = 0; i < context->numObject; i++) {
        lwm2m_object_t * object = context->objectList[i];
        if (NULL != object) {
            switch (object->objID)
            {
            case LWM2M_SECURITY_OBJECT_ID:
                // first delete internal content
                object->closeFunc(object);
                // then restore previous object
                copy_security_object(object, backupObjectArray[0]);
                break;
            case LWM2M_SERVER_OBJECT_ID:
                // first delete internal content
                object->closeFunc(object);
                // then restore previous object
                copy_server_object(object, backupObjectArray[1]);
                break;
            default:
                break;
            }
        }
    }

    // restart the old servers
    lwm2m_start(context);
    fprintf(stdout, "[BOOTSTRAP] ObjectList restored\r\n");
}

static void prv_connections_free(lwm2m_context_t * context)
{
    client_data_t * app_data;

    app_data = context->userData;
    if (NULL != app_data)
    {
        connection_free(app_data->connList);
        app_data->connList = NULL;
    }
}

static void update_bootstrap_info(lwm2m_bootstrap_state_t * previousBootstrapState,
        lwm2m_context_t * context)
{
    if (*previousBootstrapState != context->bsState)
    {
        *previousBootstrapState = context->bsState;
        switch(context->bsState)
        {
            case BOOTSTRAP_CLIENT_HOLD_OFF:
#ifdef WITH_LOGS
                fprintf(stdout, "[BOOTSTRAP] backup security and server objects\r\n");
#endif
                prv_backup_objects(context);
                break;
            case BOOTSTRAP_FINISHED:
#ifdef WITH_LOGS
                fprintf(stdout, "[BOOTSTRAP] free connections\r\n");
#endif
                prv_connections_free(context);
                break;
            case BOOTSTRAP_FAILED:
#ifdef WITH_LOGS
                fprintf(stdout, "[BOOTSTRAP] restore security and server objects\r\n");
#endif
                prv_connections_free(context);
                prv_restore_objects(context);
                break;
            default:
                break;
        }
    }

#ifdef WITH_LOGS
    prv_display_bootstrap_state(context->bsState);
#endif
}

static void close_backup_object(void)
{
    int i;
    for (i = 0; i < BACKUP_OBJECT_COUNT; i++) {
        if (NULL != backupObjectArray[i]) {
            backupObjectArray[i]->closeFunc(backupObjectArray[i]);
            lwm2m_free(backupObjectArray[i]);
        }
    }
}
#endif

void print_usage(void)
{
    fprintf(stdout, "Usage: lwm2mclient [OPTION]\r\n");
    fprintf(stdout, "Launch a LWM2M client.\r\n");
    fprintf(stdout, "Options:\r\n");
    fprintf(stdout, "  -n NAME\tSet the endpoint name of the Client. Default: testlwm2mclient\r\n");
    fprintf(stdout, "  -l PORT\tSet the local UDP port of the Client. Default: 56830\r\n");
    fprintf(stdout, "  -h HOST\tSet the hostname of the LWM2M Server to connect to. Default: localhost\r\n");
    fprintf(stdout, "  -p HOST\tSet the port of the LWM2M Server to connect to. Default: "LWM2M_STANDARD_PORT_STR"\r\n");
    fprintf(stdout, "  -t TIME\tSet the lifetime of the Client. Default: 300\r\n");
    fprintf(stdout, "  -b\t\tBootstrap requested.\r\n");
    fprintf(stdout, "  -c\t\tChange battery level over time.\r\n");
    fprintf(stdout, "\r\n");
}


// static void *_eventloop_step(void *arg)
// {
//     (void)arg;
//     // int result;
//     // struct timeval tv;

// //     while(1) {
// //         if (batterylevelchanging)
// //         {
// //             update_battery_level(lwm2mH);
// //             tv.tv_sec = 5;
// //         }
// //         else
// //         {
// //             tv.tv_sec = 60;
// //         }
// //         tv.tv_usec = 0;

// //         result = lwm2m_step(lwm2mH, &(tv.tv_sec));
// //         sleep(30);
// //         if (result != 0)
// //         {
// //             fprintf(stderr, "lwm2m_step() failed: 0x%X\r\n", result);
// //             return NULL;
// //         }
// // // #ifdef LWM2M_BOOTSTRAP
// // //         update_bootstrap_info(&previousBootstrapState, lwm2mH);
// // // #endif
// //     }

//     return NULL;
// }

static void *_eventloop(void *arg)
{
    (void)arg;
    msg_t msg, reply;
    msg_t msg_queue[1024];
    int result;
    connection_t * connP;
    ng_pktsnip_t * snip;
    ng_pktsnip_t * tmp;
    struct timeval tv;

    /* setup the message queue */
    msg_init_queue(msg_queue, 1024);

    reply.content.value = (uint32_t)(-ENOTSUP);
    reply.type = NG_NETAPI_MSG_TYPE_ACK;

    while (1) {
        result = lwm2m_step(lwm2mH, &(tv.tv_sec));
        if (result != 0)
        {
            fprintf(stderr, "lwm2m_step() failed: 0x%X\r\n", result);
            return NULL;
        }

        msg_receive(&msg);

        if (batterylevelchanging)
        {
            update_battery_level(lwm2mH);
            tv.tv_sec = 5;
        }
        else
        {
            tv.tv_sec = 60;
        }
        tv.tv_usec = 0;

#ifdef LWM2M_BOOTSTRAP
        update_bootstrap_info(&previousBootstrapState, lwm2mH);
#endif


        switch (msg.type) {
            case NG_NETAPI_MSG_TYPE_RCV:
                snip = (ng_pktsnip_t *)msg.content.ptr;
                tmp = snip->next;
                while (tmp && (tmp->type!= NG_NETTYPE_IPV6))
                    tmp = tmp->next;
                if(tmp == NULL) {
                    puts("ERROR: no ipv6 address found");
                    exit(0);
                }
                ng_ipv6_hdr_t *ip = (ng_ipv6_hdr_t *)tmp->data;
                ng_ipv6_addr_t *src = &(ip->src);
                connP = connection_find(data.connList, src, sizeof(ng_ipv6_addr_t));
                //TODO make new connection_t type with only what i need
                //TODO redo connection.c for the new connection_t
                if (connP != NULL)
                {
                    //connP->port = DEFAULT_PORT;
                    lwm2m_handle_packet(lwm2mH, snip->data, snip->size, connP); //TODO check is snip or snip->data
                    conn_s_updateRxStatistic(objArray[7], snip->size, false);
                }
                else
                {
                    fprintf(stderr, "received bytes ignored!\r\n");
                }
                //lwm2m_handle_packet(lwm2mH, snip, snip.size, connP);
                puts("PKTDUMP: data received:");
                output_buffer(stderr, snip->data, snip->size, 0);
                ng_pktbuf_release(snip);
                break;
            case NG_NETAPI_MSG_TYPE_SND:
                puts("PKTDUMP: data to send:");
                //_dump((ng_pktsnip_t *)msg.content.ptr);
                break;
            case NG_NETAPI_MSG_TYPE_GET:
            case NG_NETAPI_MSG_TYPE_SET:
                msg_reply(&msg, &reply);
                break;
            default:
                puts("PKTDUMP: received something unexpected");
                break;
        }
    }

    /* never reached */
    return NULL;
}

int prv_init(int argc, char** argv)
{
    // client_data_t data;
    int result;
    //const char * server = "localhost";
    const char * serverPort = DEFAULT_PORT;
    char * name = "testlwm2mclient";
    int lifetime = 300;
    // int batterylevelchanging = 0;
    bool bootstrapRequested = false;

    (void)argc;
    //(void)argv;

    serverIp = argv[1];

    printf("serverIp is now = %s\n",serverIp);

    memset(&data, 0, sizeof(client_data_t));


    char serverUri[50];
    int serverId = 123;
    sprintf (serverUri, "coap://%s:%s", serverIp, serverPort);
#ifdef LWM2M_BOOTSTRAP
    objArray[0] = get_security_object(serverId, serverUri, bootstrapRequested);
#else
    objArray[0] = get_security_object(serverId, serverUri, false);
#endif
    if (NULL == objArray[0])
    {
        fprintf(stderr, "Failed to create security object\r\n");
        return -1;
    }
    data.securityObjP = objArray[0];

    objArray[1] = get_server_object(serverId, "U", lifetime, false);
    if (NULL == objArray[1])
    {
        fprintf(stderr, "Failed to create server object\r\n");
        return -1;
    }

    objArray[2] = get_object_device();
    if (NULL == objArray[2])
    {
        fprintf(stderr, "Failed to create Device object\r\n");
        return -1;
    }

    objArray[3] = get_object_firmware();
    if (NULL == objArray[3])
    {
        fprintf(stderr, "Failed to create Firmware object\r\n");
        return -1;
    }

    objArray[4] = get_object_location();
    if (NULL == objArray[4])
    {
        fprintf(stderr, "Failed to create location object\r\n");
        return -1;
    }

    objArray[5] = get_test_object();
    if (NULL == objArray[5])
    {
        fprintf(stderr, "Failed to create test object\r\n");
        return -1;
    }

    objArray[6] = get_object_conn_m();
    if (NULL == objArray[6])
    {
        fprintf(stderr, "Failed to create connectivity monitoring object\r\n");
        return -1;
    }

    objArray[7] = get_object_conn_s();
    if (NULL == objArray[7])
    {
        fprintf(stderr, "Failed to create connectivity statistics object\r\n");
        return -1;
    }

    int instId = 0;
    objArray[8] = acc_ctrl_create_object();
    if (NULL == objArray[8])
    {
        fprintf(stderr, "Failed to create Access Control object\r\n");
        return -1;
    }
    else if (acc_ctrl_obj_add_inst(objArray[8], instId, 3, 0, serverId)==false)
    {
        fprintf(stderr, "Failed to create Access Control object instance\r\n");
        return -1;
    }
    //TODO substitute with hex constants
    else if (acc_ctrl_oi_add_ac_val(objArray[8], instId, 0, 0xF)==false)
    {
        fprintf(stderr, "Failed to create Access Control ACL default resource\r\n");
        return -1;
    }
    else if (acc_ctrl_oi_add_ac_val(objArray[8], instId, 999, 0x1)==false)
    {
        fprintf(stderr, "Failed to create Access Control ACL resource for serverId: 999\r\n");
        return -1;
    }

    lwm2mH = lwm2m_init(prv_connect_server, prv_buffer_send, &data);
    if (NULL == lwm2mH)
    {
        fprintf(stderr, "lwm2m_init() failed\r\n");
        return -1;
    }

#ifdef LWM2M_BOOTSTRAP
    /*
     * Bootstrap state initialization
     */
    if (bootstrapRequested)
    {
        lwm2mH->bsState = BOOTSTRAP_REQUESTED;
    }
    else
    {
        lwm2mH->bsState = NOT_BOOTSTRAPPED;
    }
#endif


    /*
     * We configure the liblwm2m library with the name of the client - which shall be unique for each client -
     * the number of objects we will be passing through and the objects array
     */
    result = lwm2m_configure(lwm2mH, name, NULL, NULL, OBJ_COUNT, objArray);
    if (result != 0)
    {
        fprintf(stderr, "lwm2m_configure() failed: 0x%X\r\n", result);
        return -1;
    }

    /*
     * This function start your client to the LWM2M servers
     */
    result = lwm2m_start(lwm2mH);
    if (result != 0)
    {
        fprintf(stderr, "lwm2m_start() failed: 0x%X\r\n", result);
        return -1;
    }

    /**
     * Initialize value changed callback.
     */
    init_value_change(lwm2mH);

    if (_pid == KERNEL_PID_UNDEF) {
    _pid = thread_create(_stack, sizeof(_stack), NG_PKTDUMP_PRIO,
                         CREATE_STACKTEST, _eventloop, NULL, "udp-listen");
    }

    // if (_pid_step == KERNEL_PID_UNDEF) {
    // _pid_step = thread_create(_stack_step, sizeof(_stack_step), NG_PKTDUMP_PRIO,
    //                      CREATE_STACKTEST, _eventloop_step, NULL, "l2mwm_step");
    // }

    client.pid = _pid;
    client.demux_ctx = DEFAULT_PORT_INT;
    ng_netreg_register(NG_NETTYPE_UDP, &client);

    // client_step.pid = _pid_step;
    // client_step.demux_ctx = DEFAULT_PORT_INT;
    // ng_netreg_register(NG_NETTYPE_UDP, &client_step);

    //lwm2m_set_monitoring_callback(lwm2mH, prv_monitor_callback, lwm2mH);

    return 0;
}

static int prv_quit(int argc, char** argv)
{

    (void)argc;
    (void)argv;

#ifdef LWM2M_BOOTSTRAP
        close_backup_object();
#endif
        lwm2m_close(lwm2mH);

    connection_free(data.connList);

    return 0;
}


static const shell_command_t commands[] =
{
            {"init", "Initialize the protocol.", prv_init},
            {"list", "List known servers.", prv_output_servers},
            {"change", "Change the value of resource.\n\n Long description:\n change URI [DATA]\r\n"
                                                        "   URI: uri of the resource such as /3/0, /3/0/2\r\n"
                                                        "   DATA: (optional) new value\r\n", prv_change},
            {"update", "Trigger a registration update \n\n Long description:\n update SERVER\r\n"
                                                        "   SERVER: short server id such as 123\r\n", prv_update},
#ifdef LWM2M_BOOTSTRAP
            {"bootstrap", "Initiate a DI bootstrap process", prv_initiate_bootstrap},
            {"disp", "Display current objects/instances/resources", prv_display_objects},
            {"dispb", "Display current backup of objects/instances/resources\r\n"
                    "\t(only security and server objects are backupped)", prv_display_backup},
#endif
            {"ls", "List Objects and Instances", prv_object_list},
            {"dump", "Dump an Object \n\n Long description:\ndump URI"
                                       "URI: uri of the Object or Instance such as /3/0, /1\r\n", prv_object_dump},
            {"quit", "Quit the client gracefully.", prv_quit},
            {"^C", "Quit the client abruptly (without sending a de-register message).", NULL},

            { NULL, NULL, NULL }
};

int main(int argc, char *argv[])
{

    // if(argc == 3) {
    //     if (strcmp(argv[1],"-ip") == 0)
    //         serverIp = argv[2];
    //     return -1;
    // }
    // else {
    //     printf("WTFFFFFFFFFF\n");
    //     return -1;
    // }
    // printf("servip ip = \n");
    // scanf("%s",&serverIp);
    // printf("serverIp is now = %s\n",serverIp);

    (void)argc;
    (void)argv;

    (void) posix_open(uart0_handler_pid, 0);
    /* ----------------- my variables ------------------- */
    shell_t shell;
    /* -------------------------------------------------- */




    shell_init(&shell, commands, UART0_BUFSIZE, uart0_readc, uart0_putc);
    shell_run(&shell);

    return 0;
}