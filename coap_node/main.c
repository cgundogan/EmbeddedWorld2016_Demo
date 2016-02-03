/*
 * Copyright (C) 2016 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     demo_embedded_world_2016
 * @{
 *
 * @file
 * @brief       Embedded World 2016 Demo: CoAP node
 *
 * @author      Hauke Petersen <hauke.petersen@fu-berlin.de>
 * @author      Cenk Gündoğan <cnkgndgn@gmail.com>
 *
 * @}
 */

#include "kernel.h"
#include "shell.h"
#include "xtimer.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include "coap.h"

#include "net/gnrc.h"
#include "net/gnrc/ipv6.h"
#include "net/gnrc/udp.h"
#include "net/conn.h"
#include "net/conn/udp.h"

#define P1              "berlin"
#define P2              "light"
#define P3              "01"

#define Q_SZ                (8)
#define PRIO                (THREAD_PRIORITY_MAIN - 1)
#define COAP_SERVER_PORT    (5683)
#define UDP_PORT            (7777)
#define MSG_BEACON_SEND     (0x3339)
#define BEACON_INTERVAL     (500)

static msg_t _main_msg_q[Q_SZ];
static msg_t _coap_msg_q[Q_SZ];
static msg_t _beac_msg_q[Q_SZ], beacon_msg = { .type = MSG_BEACON_SEND };
static char coap_stack[THREAD_STACKSIZE_MAIN];
static char beac_stack[THREAD_STACKSIZE_MAIN];
static xtimer_t beacon_timer;
static uint32_t beacon_interval = BEACON_INTERVAL * MS_IN_USEC;
static uint8_t _udp_buf[512];   /* udp read buffer (max udp payload size) */
uint8_t scratch_raw[1024];      /* microcoap scratch buffer */
coap_rw_buffer_t scratch_buf = { scratch_raw, sizeof(scratch_raw) };

const coap_endpoint_t endpoints[] =
{
    /* marks the end of the endpoints array: */
    { (coap_method_t)0, NULL, NULL, NULL }
};


static int udp_send(char *addr_str, uint8_t *data, size_t data_len)
{
    struct sockaddr_in6 src, dst;
    int s;
    src.sin6_family = AF_INET6;
    dst.sin6_family = AF_INET6;
    memset(&src.sin6_addr, 0, sizeof(src.sin6_addr));
    /* parse destination address */
    if (inet_pton(AF_INET6, addr_str, &dst.sin6_addr) != 1) {
        puts("error: unable to parse destination address");
        return 1;
    }

    dst.sin6_port = htons(UDP_PORT);
    src.sin6_port = htons(UDP_PORT);

    if ((s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        puts("error initializing socket");
        return 1;
    }

    if (sendto(s, data, data_len, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        puts("error: could not send message");
        close(s);
        return 1;
    }

    close(s);

    return 0;
}

void send_coap_post(char *addr_str, uint8_t *data, size_t len)
{
        uint8_t  snd_buf[128];
        size_t   req_pkt_sz;

        coap_header_t req_hdr = {
                .version = 1,
                .type    = COAP_TYPE_NONCON,
                .tkllen  = 0,
                .code    = COAP_METHOD_POST,
                .mid     = {5, 57}            // is equivalent to 1337 when converted to uint16_t
        };

        coap_buffer_t payload = {
                .p   = data,
                .len = len
        };

        coap_packet_t req_pkt = {
                .header  = req_hdr,
                .token   = (coap_buffer_t) { 0 },
                .numopts = 3,
                .opts    = { {{(uint8_t *)P1, 6}, (uint8_t)COAP_OPTION_URI_PATH},
                             {{(uint8_t *)P2, 5}, (uint8_t)COAP_OPTION_URI_PATH},
                             {{(uint8_t *)P3, 2}, (uint8_t)COAP_OPTION_URI_PATH} },
                .payload = payload
        };

        req_pkt_sz = sizeof(req_pkt);

        if (coap_build(snd_buf, &req_pkt_sz, &req_pkt) != 0) {
                printf("CoAP build failed :(\n");
                return;
        }

        udp_send(addr_str, snd_buf, req_pkt_sz);
}

void *microcoap_server(void *arg)
{
    (void) arg;
    msg_init_queue(_coap_msg_q, Q_SZ);

    uint8_t laddr[16] = { 0 };
    uint8_t raddr[16] = { 0 };
    size_t raddr_len;
    uint16_t rport;
    conn_udp_t conn;
    int rc = conn_udp_create(&conn, laddr, sizeof(laddr), AF_INET6, COAP_SERVER_PORT);

    while (1) {
        if ((rc = conn_udp_recvfrom(&conn, (char *)_udp_buf, sizeof(_udp_buf), raddr, &raddr_len, &rport)) < 0) {
            continue;
        }

        coap_packet_t pkt;
        /* parse UDP packet to CoAP */
        if (0 == (rc = coap_parse(&pkt, _udp_buf, rc))) {
            coap_packet_t rsppkt;

            /* handle CoAP request */
            coap_handle_req(&scratch_buf, &pkt, &rsppkt, false, false);

            /* build reply */
            size_t rsplen = sizeof(_udp_buf);
            if ((rc = coap_build(_udp_buf, &rsplen, &rsppkt)) == 0) {
                /* send reply via UDP */
                rc = conn_udp_sendto(_udp_buf, rsplen, NULL, 0, raddr, raddr_len, AF_INET6, COAP_SERVER_PORT, rport);
            }
        }
    }

    /* never reached */
    return NULL;
}

void *beaconing(void *arg)
{
    (void) arg;
    msg_init_queue(_beac_msg_q, Q_SZ);
    msg_t msg, reply = { .type = GNRC_NETAPI_MSG_TYPE_ACK };

    xtimer_set_msg(&beacon_timer, beacon_interval, &beacon_msg, thread_getpid());

    while(1) {
        msg_receive(&msg);
        switch (msg.type) {
            case MSG_BEACON_SEND:
                send_coap_post("ff02::1", NULL, 0);
                xtimer_set_msg(&beacon_timer, beacon_interval, &beacon_msg, thread_getpid());
                break;
            case GNRC_NETAPI_MSG_TYPE_GET:
            case GNRC_NETAPI_MSG_TYPE_SET:
                reply.content.value = -ENOTSUP;
                msg_reply(&msg, &reply);
                break;
            default:
                break;
        }
    }

    /* never reached */
    return NULL;
}

static const shell_command_t shell_commands[] = { { NULL, NULL, NULL } };

int main(void)
{
    msg_init_queue(_main_msg_q, Q_SZ);

    thread_create(coap_stack, sizeof(coap_stack), PRIO, THREAD_CREATE_STACKTEST, microcoap_server,
                  NULL, "coap");
    thread_create(beac_stack, sizeof(beac_stack), PRIO, THREAD_CREATE_STACKTEST, beaconing,
                  NULL, "beaconing");

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    return 0;
}
