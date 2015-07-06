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
 *    Pascal Rieux - Please refer to git log
 *
 *******************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "connection-n_shell.h"
#include "net/ng_ipv6/addr.h"
#include "net/ng_ipv6/hdr.h"
#include "net/ng_pkt.h"
#include "net/ng_netreg.h"
#include "net/ng_nettype.h"
#include "net/ng_pktbuf.h"
#include "net/ng_udp.h"
#include "net/ng_netapi.h"

int create_socket(const char * portStr)
{
    int s = -1;
    struct addrinfo hints;
    struct addrinfo *res;
    struct addrinfo *p;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    if (0 != getaddrinfo(NULL, portStr, &hints, &res))
    {
        return -1;
    }

    for(p = res ; p != NULL && s == -1 ; p = p->ai_next)
    {
        s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s >= 0)
        {
            if (-1 == bind(s, p->ai_addr, p->ai_addrlen))
            {
                close(s);
                s = -1;
            }
        }
    }

    freeaddrinfo(res);

    return s;
}

connection_t * connection_find(connection_t * connList,
                               ng_ipv6_addr_t * addr,
                               size_t addrLen)
{
    connection_t * connP;

    connP = connList;
    while (connP != NULL)
    {
        if ((connP->addrLen == addrLen)
         && (memcmp(&(connP->addr), addr, addrLen) == 0))
        {
            return connP;
        }
        connP = connP->next;
    }

    return connP;
}

connection_t * connection_new_incoming(connection_t * connList,
                                       ng_ipv6_addr_t * addr,
                                       size_t addrLen)
{
    connection_t * connP;

    connP = (connection_t *)malloc(sizeof(connection_t));
    if (connP != NULL)
    {
        memcpy(&(connP->addr), addr, addrLen);
        connP->addrLen = addrLen;
        connP->next = connList;
    }

    return connP;
}

connection_t * connection_create(connection_t * connList,
                                 char * host,
                                 uint16_t port)
{
    char portStr[6];
    struct addrinfo hints;
    struct addrinfo *servinfo = NULL;
    // struct addrinfo *p;
    // int s;
    // struct sockaddr *sa;
    // socklen_t sl;
    connection_t * connP = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    ng_ipv6_addr_t result;

    if (0 >= sprintf(portStr, "%hu", port)) return NULL;
    if (0 != getaddrinfo(host, portStr, &hints, &servinfo) || servinfo == NULL) return NULL;

    //TODO make another RIOT-style check
    // we test the various addresses
    // s = -1;
    // for(p = servinfo ; p != NULL && s == -1 ; p = p->ai_next)
    // {
    //     s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    //     if (s >= 0)
    //     {
    //         sa = p->ai_addr;
    //         sl = p->ai_addrlen;
    //         if (-1 == connect(s, p->ai_addr, p->ai_addrlen))
    //         {
    //             close(s);
    //             s = -1;
    //         }
    //     }
    // }
    // if (s >= 0)
    // {
   if(ng_ipv6_addr_from_str(&result,host) == NULL) {
        printf("ERROR getting address\n");
        return NULL;
   }
   else
        connP = connection_new_incoming(connList, &result, sizeof(ng_ipv6_addr_t));
        //close(s);
    //}
    if (NULL != servinfo) {
        free(servinfo);
    }

    return connP;
}

void connection_free(connection_t * connList)
{
    while (connList != NULL)
    {
        connection_t * nextP;

        nextP = connList->next;
        free(connList);

        connList = nextP;
    }
}

int connection_send(connection_t *connP,
                    uint8_t * buffer,
                    size_t length)
{
    /*
    int nbSent;
    size_t offset;

    offset = 0;
    while (offset != length)
    {
        nbSent = sendto(connP->sock, buffer + offset, length - offset, 0, (struct sockaddr *)&(connP->addr), connP->addrLen);
        if (nbSent == -1) return -1;
        offset += nbSent;
    }
    return 0;
*/

    ////////////////////////////


    uint8_t port[2];
    //uint16_t tmp;
    ng_pktsnip_t *payload, *udp, *ip;
    //ng_ipv6_addr_t addr;
    ng_netreg_entry_t *sendto;

    /* parse destination address
    if (ng_ipv6_addr_from_str(&addr, addr_str) == NULL) {
        puts("Error: unable to parse destination address");
        return;
    }
    // parse port
    tmp = (uint16_t)atoi(port_str);
    if (tmp == 0) {
        puts("Error: unable to parse destination port");
        return;
    }
    */
    port[0] = connP->port;
    port[1] = connP->port >> 8;

    /* allocate payload */
    //payload = ng_pktbuf_add(NULL, data, strlen(data), NG_NETTYPE_UNDEF);
    payload = ng_pktbuf_add(NULL, (void*)buffer, length, NG_NETTYPE_UNDEF);
    if (payload == NULL) {
        puts("Error: unable to copy data to packet buffer");
        return -1;
    }
    /* allocate UDP header, set source port := destination port */
    udp = ng_udp_hdr_build(payload, port, 2, port, 2);
    if (udp == NULL) {
        puts("Error: unable to allocate UDP header");
        ng_pktbuf_release(payload);
        return -1;
    }
    /* allocate IPv6 header */
    ip = ng_ipv6_hdr_build(udp, NULL, 0, (uint8_t *)&connP->addr, sizeof(ng_ipv6_addr_t));
    if (ip == NULL) {
        puts("Error: unable to allocate IPv6 header");
        ng_pktbuf_release(udp);
        return -1;
    }
    /* send packet */
    sendto = ng_netreg_lookup(NG_NETTYPE_UDP, NG_NETREG_DEMUX_CTX_ALL);
    if (sendto == NULL) {
        puts("Error: unable to locate UDP thread");
        ng_pktbuf_release(ip);
        return -1;
    }
    ng_pktbuf_hold(ip, ng_netreg_num(NG_NETTYPE_UDP,
                                     NG_NETREG_DEMUX_CTX_ALL) - 1);
    while (sendto != NULL) {
        ng_netapi_send(sendto->pid, ip);
        sendto = ng_netreg_getnext(sendto);
    }
    //printf("Success: send %i byte to %s:%u\n", payload->size, addr_str, tmp);
    printf("Success: sent %i byte \n", payload->size);

    return 0;
}
