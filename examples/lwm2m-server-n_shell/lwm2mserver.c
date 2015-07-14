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
 *    domedambrosio - Please refer to git log
 *    Simon Bernard - Please refer to git log
 *    Toby Jaffey - Please refer to git log
 *    Julien Vermillard - Please refer to git log
 *    Bosch Software Innovations GmbH - Please refer to git log
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

*/


#include "liblwm2m.h"

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
#include <inttypes.h>


#include "commandline.h"
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

/**
 * @brief   PID of the pktdump thread
 */
static kernel_pid_t _pid = KERNEL_PID_UNDEF;

/**
 * @brief   Stack for the pktdump thread
 */
static char _stack[NG_PKTDUMP_STACKSIZE];


/*
 * ensure sync with: er_coap_13.h COAP_MAX_PACKET_SIZE!
 * or internals.h LWM2M_MAX_PACKET_SIZE!
 */
#define MAX_PACKET_SIZE 198
#define DEFAULT_PORT 4242

static int g_quit = 0;
lwm2m_context_t * lwm2mH = NULL;
connection_t * connList = NULL;

static ng_netreg_entry_t server = {NULL, NG_NETREG_DEMUX_CTX_ALL,
                                   KERNEL_PID_UNDEF};

static void prv_print_error(uint8_t status)
{
    fprintf(stdout, "Error: ");
    print_status(stdout, status);
    fprintf(stdout, "\r\n");
}

static uint8_t prv_buffer_send(void * sessionH,
                               uint8_t * buffer,
                               size_t length,
                               void * userdata)
{
    connection_t * connP = (connection_t*) sessionH;

    if (-1 == connection_send(connP, buffer, length))
    {
        return COAP_500_INTERNAL_SERVER_ERROR;
    }
    return COAP_NO_ERROR;
}

static char * prv_dump_binding(lwm2m_binding_t binding)
{
    switch (binding)
    {
    case BINDING_UNKNOWN:
        return "Not specified";
    case BINDING_U:
        return "UDP";
    case BINDING_UQ:
        return "UDP queue mode";
    case BINDING_S:
        return "SMS";
    case BINDING_SQ:
        return "SMS queue mode";
    case BINDING_US:
        return "UDP plus SMS";
    case BINDING_UQS:
        return "UDP queue mode plus SMS";
    default:
        return "";
    }
}

static void prv_dump_client(lwm2m_client_t * targetP)
{
    lwm2m_client_object_t * objectP;

    fprintf(stdout, "Client #%d:\r\n", targetP->internalID);
    fprintf(stdout, "\tname: \"%s\"\r\n", targetP->name);
    fprintf(stdout, "\tbinding: \"%s\"\r\n", prv_dump_binding(targetP->binding));
    if (targetP->msisdn) fprintf(stdout, "\tmsisdn: \"%s\"\r\n", targetP->msisdn);
    if (targetP->altPath) fprintf(stdout, "\talternative path: \"%s\"\r\n", targetP->altPath);
    fprintf(stdout, "\tlifetime: %d sec\r\n", targetP->lifetime);
    fprintf(stdout, "\tobjects: ");
    for (objectP = targetP->objectList; objectP != NULL ; objectP = objectP->next)
    {
        if (objectP->instanceList == NULL)
        {
            fprintf(stdout, "/%d, ", objectP->id);
        }
        else
        {
            lwm2m_list_t * instanceP;

            for (instanceP = objectP->instanceList; instanceP != NULL ; instanceP = instanceP->next)
            {
                fprintf(stdout, "/%d/%d, ", objectP->id, instanceP->id);
            }
        }
    }
    fprintf(stdout, "\r\n");
}

// static void wrap_prv_output_clients(int argc, char** argv)
// {
//     prv_output_clients(NULL, (void*)lwm2mH);
// }

static void prv_output_clients(int argc, char** argv)
{
    //lwm2m_context_t * lwm2mH = (lwm2m_context_t *) user_data;
    lwm2m_client_t * targetP;

    targetP = lwm2mH->clientList;
    if (targetP == NULL)
    {
        fprintf(stdout, "No client.\r\n");
        return;
    }
    for (targetP = lwm2mH->clientList ; targetP != NULL ; targetP = targetP->next)
    {
        prv_dump_client(targetP);
    }

}

static int prv_read_id(char * buffer,
                       uint16_t * idP)
{
    int nb;
    int value;

    nb = sscanf(buffer, "%d", &value);
    if (nb == 1)
    {
        if (value < 0 || value > LWM2M_MAX_ID)
        {
            nb = 0;
        }
        else
        {
            *idP = value;
        }
    }

    return nb;
}

static void prv_result_callback(uint16_t clientID,
                                lwm2m_uri_t * uriP,
                                int status,
                                uint8_t * data,
                                int dataLength,
                                void * userData)
{
    fprintf(stdout, "\r\nClient #%d %d", clientID, uriP->objectId);
    if (LWM2M_URI_IS_SET_INSTANCE(uriP))
        fprintf(stdout, "/%d", uriP->instanceId);
    else if (LWM2M_URI_IS_SET_RESOURCE(uriP))
        fprintf(stdout, "/");
    if (LWM2M_URI_IS_SET_RESOURCE(uriP))
            fprintf(stdout, "/%d", uriP->resourceId);
    fprintf(stdout, " : ");
    print_status(stdout, status);
    fprintf(stdout, "\r\n");

    if (data != NULL)
    {
        fprintf(stdout, "%d bytes received:\r\n", dataLength);
        if (LWM2M_URI_IS_SET_RESOURCE(uriP))
        {
            output_buffer(stdout, data, dataLength, 1);
        }
        else
        {
            output_tlv(stdout, data, dataLength, 1);
        }
    }

    fprintf(stdout, "\r\n> ");
    fflush(stdout);
}

static void prv_notify_callback(uint16_t clientID,
                                lwm2m_uri_t * uriP,
                                int count,
                                uint8_t * data,
                                int dataLength,
                                void * userData)
{
    fprintf(stdout, "\r\nNotify from client #%d /%d", clientID, uriP->objectId);
    if (LWM2M_URI_IS_SET_INSTANCE(uriP))
        fprintf(stdout, "/%d", uriP->instanceId);
    else if (LWM2M_URI_IS_SET_RESOURCE(uriP))
        fprintf(stdout, "/");
    if (LWM2M_URI_IS_SET_RESOURCE(uriP))
            fprintf(stdout, "/%d", uriP->resourceId);
    fprintf(stdout, " number %d\r\n", count);

    if (data != NULL)
    {
        fprintf(stdout, "%d bytes received:\r\n", dataLength);
        output_buffer(stdout, data, dataLength, 0);
    }

    fprintf(stdout, "\r\n> ");
    fflush(stdout);
}

static void prv_read_client(int argc, char** argv)
{
    //lwm2m_context_t * lwm2mH = (lwm2m_context_t *) user_data;
    uint16_t clientId;
    lwm2m_uri_t uri;
    char* end = NULL;
    int result;
    char *buffer;

    if(argc != 3) goto syntax_error;

    //result = prv_read_id(buffer, &clientId);
    result = prv_read_id(argv[1], &clientId);
    if (result != 1) goto syntax_error;

    //buffer = get_next_arg(argv[2], &end);
    buffer = argv[2];
    if (buffer[0] == 0) goto syntax_error;

    result = lwm2m_stringToUri(buffer, get_end_of_arg(buffer) - buffer, &uri);
    if (result == 0) goto syntax_error;

    if (!check_end_of_args(end)) goto syntax_error;

    result = lwm2m_dm_read(lwm2mH, clientId, &uri, prv_result_callback, NULL);

    if (result == 0)
    {
        fprintf(stdout, "OK");
    }
    else
    {
        prv_print_error(result);
    }
    return;

syntax_error:
    fprintf(stdout, "Syntax error !");
}

static void prv_write_client(int argc, char** argv)
{
    //lwm2m_context_t * lwm2mH = (lwm2m_context_t *) user_data;
    uint16_t clientId;
    lwm2m_uri_t uri;
    char * end = NULL;
    int result;
    char *buffer;

    if(argc != 4) goto syntax_error;

    result = prv_read_id(argv[1], &clientId);
    if (result != 1) goto syntax_error;

    //buffer = get_next_arg(buffer, &end);
    buffer = argv[2];
    if (buffer[0] == 0) goto syntax_error;

    result = lwm2m_stringToUri(buffer, get_end_of_arg(buffer) - buffer, &uri);
    if (result == 0) goto syntax_error;

    //buffer = get_next_arg(end, &end);
    buffer = argv[3];
    if (buffer[0] == 0) goto syntax_error;

    if (!check_end_of_args(end)) goto syntax_error;

    result = lwm2m_dm_write(lwm2mH, clientId, &uri, (uint8_t *)buffer, get_end_of_arg(buffer) - buffer, prv_result_callback, NULL);

    if (result == 0)
    {
        fprintf(stdout, "OK");
    }
    else
    {
        prv_print_error(result);
    }
    return;

syntax_error:
    fprintf(stdout, "Syntax error !");
}


static void prv_exec_client(int argc, char** argv)
{
    //lwm2m_context_t * lwm2mH = (lwm2m_context_t *) user_data;
    uint16_t clientId;
    lwm2m_uri_t uri;
    char * end = NULL;
    char *buffer;
    int result;

    if(argc != 3) goto syntax_error;

    result = prv_read_id(argv[1], &clientId);
    if (result != 1) goto syntax_error;

    //buffer = get_next_arg(buffer, &end);
    buffer = argv[2];
    if (buffer[0] == 0) goto syntax_error;

    result = lwm2m_stringToUri(buffer, get_end_of_arg(buffer) - buffer, &uri);
    if (result == 0) goto syntax_error;

    //buffer = get_next_arg(end, &end);
    buffer = argv[3];


    if (buffer[0] == 0)
    {
        result = lwm2m_dm_execute(lwm2mH, clientId, &uri, NULL, 0, prv_result_callback, NULL);
    }
    else
    {
        if (!check_end_of_args(get_end_of_arg(buffer))) goto syntax_error;

        result = lwm2m_dm_execute(lwm2mH, clientId, &uri, (uint8_t *)buffer, get_end_of_arg(buffer) - buffer, prv_result_callback, NULL);
    }

    if (result == 0)
    {
        fprintf(stdout, "OK");
    }
    else
    {
        prv_print_error(result);
    }
    return;

syntax_error:
    fprintf(stdout, "Syntax error !");
}

static void prv_create_client(int argc, char** argv)
{
    //lwm2m_context_t * lwm2mH = (lwm2m_context_t *) user_data;
    uint16_t clientId;
    lwm2m_uri_t uri;
    char * end = NULL;
    char *buffer;
    int result;
    int64_t value;
    uint8_t temp_buffer[MAX_PACKET_SIZE];
    int temp_length = 0;

    if(argc != 4) goto syntax_error;

    //Get Client ID
    result = prv_read_id(argv[1], &clientId);
    if (result != 1) goto syntax_error;

    //Get Uri
    //buffer = get_next_arg(buffer, &end);
    buffer = argv[2];
    if (buffer[0] == 0) goto syntax_error;

    result = lwm2m_stringToUri(buffer, get_end_of_arg(buffer) - buffer, &uri);
    if (result == 0) goto syntax_error;

    //Get Data to Post
    //buffer = get_next_arg(end, &end);
    buffer = argv[3];
    if (buffer[0] == 0) goto syntax_error;

    if (!check_end_of_args(get_end_of_arg(buffer))) goto syntax_error;

   // TLV

   /* Client dependent part   */

    if (uri.objectId == 1024)
    {
        result = lwm2m_PlainTextToInt64((uint8_t *)buffer, get_end_of_arg(buffer) - buffer, &value);
        temp_length = lwm2m_intToTLV(LWM2M_TYPE_RESOURCE, value, (uint16_t) 1, temp_buffer, MAX_PACKET_SIZE);
    }
   /* End Client dependent part*/

    //Create
    result = lwm2m_dm_create(lwm2mH, clientId,&uri, temp_buffer, temp_length, prv_result_callback, NULL);

    if (result == 0)
    {
        fprintf(stdout, "OK");
    }
    else
    {
        prv_print_error(result);
    }
    return;

syntax_error:
    fprintf(stdout, "Syntax error !");
}

static void prv_delete_client(int argc, char** argv)
{
    //lwm2m_context_t * lwm2mH = (lwm2m_context_t *) user_data;
    uint16_t clientId;
    lwm2m_uri_t uri;
    char* end = NULL;
    char *buffer;
    int result;

    if(argc != 3) goto syntax_error;

    result = prv_read_id(argv[1], &clientId);
    if (result != 1) goto syntax_error;

    //buffer = get_next_arg(buffer, &end);
    buffer = argv[2];
    if (buffer[0] == 0) goto syntax_error;

    result = lwm2m_stringToUri(buffer, get_end_of_arg(buffer) - buffer, &uri);
    if (result == 0) goto syntax_error;

    if (!check_end_of_args(get_end_of_arg(buffer))) goto syntax_error;

    result = lwm2m_dm_delete(lwm2mH, clientId, &uri, prv_result_callback, NULL);

    if (result == 0)
    {
        fprintf(stdout, "OK");
    }
    else
    {
        prv_print_error(result);
    }
    return;

syntax_error:
    fprintf(stdout, "Syntax error !");
}

static void prv_observe_client(int argc, char** argv)
{
    //lwm2m_context_t * lwm2mH = (lwm2m_context_t *) user_data;
    uint16_t clientId;
    lwm2m_uri_t uri;
    char* end = NULL;
    char* buffer;
    int result;

    if(argc != 3) goto syntax_error;

    result = prv_read_id(argv[1], &clientId);
    if (result != 1) goto syntax_error;

    //buffer = get_next_arg(buffer, &end);
    buffer = argv[2];
    if (buffer[0] == 0) goto syntax_error;

    result = lwm2m_stringToUri(buffer, get_end_of_arg(buffer) - buffer, &uri);
    if (result == 0) goto syntax_error;

    if (!check_end_of_args(get_end_of_arg(buffer))) goto syntax_error;

    result = lwm2m_observe(lwm2mH, clientId, &uri, prv_notify_callback, NULL);

    if (result == 0)
    {
        fprintf(stdout, "OK");
    }
    else
    {
        prv_print_error(result);
    }
    return;

syntax_error:
    fprintf(stdout, "Syntax error !");
}

static void prv_cancel_client(int argc, char** argv)
{
    //lwm2m_context_t * lwm2mH = (lwm2m_context_t *) user_data;
    uint16_t clientId;
    lwm2m_uri_t uri;
    char* end = NULL;
    char *buffer;
    int result;

    result = prv_read_id(argv[1], &clientId);
    if (result != 1) goto syntax_error;

    //buffer = get_next_arg(buffer, &end);
    buffer = argv[2];
    if (buffer[0] == 0) goto syntax_error;

    result = lwm2m_stringToUri(buffer, get_end_of_arg(buffer) - buffer, &uri);
    if (result == 0) goto syntax_error;

    if (!check_end_of_args(get_end_of_arg(buffer))) goto syntax_error;

    result = lwm2m_observe_cancel(lwm2mH, clientId, &uri, prv_result_callback, NULL);

    if (result == 0)
    {
        fprintf(stdout, "OK");
    }
    else
    {
        prv_print_error(result);
    }
    return;

syntax_error:
    fprintf(stdout, "Syntax error !");
}

static void prv_monitor_callback(uint16_t clientID,
                                 lwm2m_uri_t * uriP,
                                 int status,
                                 uint8_t * data,
                                 int dataLength,
                                 void * userData)
{
    lwm2m_context_t * lwm2mH = (lwm2m_context_t *) userData;
    lwm2m_client_t * targetP;

    switch (status)
    {
    case COAP_201_CREATED:
        fprintf(stdout, "\r\nNew client #%d registered.\r\n", clientID);

        targetP = (lwm2m_client_t *)lwm2m_list_find((lwm2m_list_t *)lwm2mH->clientList, clientID);

        prv_dump_client(targetP);
        break;

    case COAP_202_DELETED:
        fprintf(stdout, "\r\nClient #%d unregistered.\r\n", clientID);
        break;

    case COAP_204_CHANGED:
        fprintf(stdout, "\r\nClient #%d updated.\r\n", clientID);

        targetP = (lwm2m_client_t *)lwm2m_list_find((lwm2m_list_t *)lwm2mH->clientList, clientID);

        prv_dump_client(targetP);
        break;

    default:
        fprintf(stdout, "\r\nMonitor callback called with an unknown status: %d.\r\n", status);
        break;
    }

    fprintf(stdout, "\r\n> ");
    fflush(stdout);
}


static void prv_quit(int argc, char** argv)
{
    g_quit = 1;
    lwm2m_close(lwm2mH);
    connection_free(connList);
    exit(1);
}


void print_usage(void)
{
    fprintf(stderr, "Usage: lwm2mserver\r\n");
    fprintf(stderr, "Launch a LWM2M server on localhost port "LWM2M_STANDARD_PORT_STR".\r\n\n");
}

/* ----------------- my methods --------------------- */

static void *_eventloop(void *arg)
{
    (void)arg;
    msg_t msg, reply;
    msg_t msg_queue[1024];
    connection_t * connP;
    ng_pktsnip_t * snip;
    ng_pktsnip_t * tmp;

    /* setup the message queue */
    msg_init_queue(msg_queue, 1024);

    reply.content.value = (uint32_t)(-ENOTSUP);
    reply.type = NG_NETAPI_MSG_TYPE_ACK;

    while (1) {
        printf("in while 1\n");
        msg_receive(&msg);
        //read ng_pkt.buff

        printf("got a message\n");


        switch (msg.type) {
            case NG_NETAPI_MSG_TYPE_RCV:
                snip = (ng_pktsnip_t *)msg.content.ptr;
                //TODO loop to get addr
                tmp = snip->next;
                while (tmp && (tmp->type!= NG_NETTYPE_IPV6));
                if(tmp == NULL) {
                    puts("ERROR: no ipv6 address found");
                    exit(0);
                }
                ng_ipv6_hdr_t *ip = (ng_ipv6_hdr_t *)tmp->data;
                ng_ipv6_addr_t *src = &(ip->src);
                connP = connection_find(connList, src, sizeof(ng_ipv6_addr_t));
                //TODO make new connection_t type with only what i need
                //TODO redo connection.c for the new connection_t
                if (connP == NULL)
                {
                    connP = connection_new_incoming(connList, src, sizeof(ng_ipv6_addr_t));
                    connP->port = DEFAULT_PORT;
                    if (connP != NULL)
                    {
                        connList = connP;
                    }
                }
                if (connP != NULL)
                {
                    connP->port = DEFAULT_PORT;
                    lwm2m_handle_packet(lwm2mH, snip->data, snip->size, connP);
                }
                //lwm2m_handle_packet(lwm2mH, snip, snip.size, connP);
                puts("PKTDUMP: data received:");
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
    lwm2mH = lwm2m_init(NULL, prv_buffer_send, NULL);
    if (NULL == lwm2mH)
    {
        fprintf(stderr, "lwm2m_init() failed\r\n");
        return -1;
    }

    if (_pid == KERNEL_PID_UNDEF) {
        printf("creating udp-listen thread\n");
    _pid = thread_create(_stack, sizeof(_stack), NG_PKTDUMP_PRIO,
                         CREATE_STACKTEST, _eventloop, NULL, "udp-listen");
    }

    server.pid = _pid;
    server.demux_ctx = DEFAULT_PORT;
    ng_netreg_register(NG_NETTYPE_UDP, &server);

    lwm2m_set_monitoring_callback(lwm2mH, prv_monitor_callback, lwm2mH);

    return 0;
}


static const shell_command_t commands[] =
{
        {"init", "Initialize the protocol.", prv_init},
        {"list", "List registered clients.", prv_output_clients},
        {"read", "Read from a client.\n\n Long description:\n read CLIENT# URI\r\n"
                                        "   CLIENT#: client number as returned by command 'list'\r\n"
                                        "   URI: uri to read such as /3, /3//2, /3/0/2, /1024/11, /1024//1\r\n"
                                        "Result will be displayed asynchronously.", prv_read_client},
        {"write", "Write to a client.\n\n Long description:\n write CLIENT# URI DATA\r\n"
                                        "   CLIENT#: client number as returned by command 'list'\r\n"
                                        "   URI: uri to write to such as /3, /3//2, /3/0/2, /1024/11, /1024//1\r\n"
                                        "   DATA: data to write\r\n"
                                        "Result will be displayed asynchronously.", prv_write_client},
        {"exec", "Execute a client resource.\n\n Long description:\n exec CLIENT# URI\r\n"
                                        "   CLIENT#: client number as returned by command 'list'\r\n"
                                        "   URI: uri of the resource to execute such as /3/0/2\r\n"
                                        "Result will be displayed asynchronously.", prv_exec_client},
        {"del", "Delete a client Object instance.\n\n Long description:\n del CLIENT# URI\r\n"
                                        "   CLIENT#: client number as returned by command 'list'\r\n"
                                        "   URI: uri of the instance to delete such as /1024/11\r\n"
                                        "Result will be displayed asynchronously.", prv_delete_client},
        {"create", "create an Object instance.\n\n Long description:\n create CLIENT# URI DATA\r\n"
                                        "   CLIENT#: client number as returned by command 'list'\r\n"
                                        "   URI: uri to which create the Object Instance such as /1024, /1024/45 \r\n"
                                        "   DATA: data to initialize the new Object Instance (0-255 for object 1024) \r\n"
                                        "Result will be displayed asynchronously.", prv_create_client},
        {"observe", "Observe from a client.\n\n Long description:\n observe CLIENT# URI\r\n"
                                        "   CLIENT#: client number as returned by command 'list'\r\n"
                                        "   URI: uri to observe such as /3, /3/0/2, /1024/11\r\n"
                                        "Result will be displayed asynchronously.", prv_observe_client},
        {"cancel", "Cancel an observe.\n\n Long description:\n cancel CLIENT# URI\r\n"
                                        "   CLIENT#: client number as returned by command 'list'\r\n"
                                        "   URI: uri on which to cancel an observe such as /3, /3/0/2, /1024/11\r\n"
                                        "Result will be displayed asynchronously.", prv_cancel_client},

        {"q", "Quit the server.", prv_quit},

        { NULL, NULL, NULL }
};
/* -------------------------------------------------- */

//send function TODO , remake udp.c send without parsing



int main(int argc, char** argv)
{
    //int sock;
    //fd_set readfds;
    //struct timeval tv;
    //int result;
    //lwm2m_context_t * lwm2mH = NULL;
    //int i;
    //connection_t * connList = NULL;



    (void) posix_open(uart0_handler_pid, 0);
    /* ----------------- my variables ------------------- */
    shell_t shell;
    /* -------------------------------------------------- */

    shell_init(&shell, commands, UART0_BUFSIZE, uart0_readc, uart0_putc);
    shell_run(&shell);



    return 0;
}
