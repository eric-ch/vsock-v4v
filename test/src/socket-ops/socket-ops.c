#include "project.h"

struct sockops_cmds {
    int (*ops)(int argc, char *argv[]);
    char *cmd;
    char *desc;
};

static int sockops_usage(int argc, char *argv[]);

struct sockops_cmds cmds[] = {
    { sockops_usage,        "help",         "Display help." },
    { sockops_socket,       "socket",       "<stream|dgram>		Create a VSOCK socket of given type." },
    { sockops_bind_dgram,   "bind_dgram",   "<addr>			Create a VSOCK socket and bind it to <addr>." },

    { sockops_recvfrom,     "recvfrom",     "<port>			Wait for a datagram to received on this port and print it." },
    { sockops_sendto,       "sendto",       "<id> <port> <message>	Send a datagram containing <message> to <id> on <port>." },

 #if 0
    { sockops_bind,     "bind",     "<addr> <port>	Create a V4V stream socket and binds the given address." },
    { sockops_listen,   "listen",   "<addr> <port>	Create a V4V stream socket, binds the given address and set it listening." },
#endif
};

static int sockops_usage(int argc, char *argv[])
{
    unused(argc);
    unused(argv);
    unsigned int i;

    INF("Usage: sockops <command> [...]");
    INF("Commands:");
    for (i = 0; i < ARRAY_LEN(cmds); ++i)
        INF("%s	%s", cmds[i].cmd, cmds[i].desc);

    return 0;
}

int main(int argc, char *argv[])
{
    unsigned int i;
    int rc;

    if (argc < 2) {
        sockops_usage(argc, argv);
        return EINVAL;
    }

    for (i = 0; i < ARRAY_LEN(cmds); ++i)
        if (!strcmp(argv[1], cmds[i].cmd)) {
            rc = cmds[i].ops(argc, argv);
            if (rc < 0)
                WRN("%s: failed (%s).", cmds[i].cmd, strerror(-rc));
            return -rc;
        }

    ERR("Command not found: `%s'", argv[1]);
    /* Unknown command. */
    return ENOTSUP;
}

