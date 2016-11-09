#include "project.h"

int sockops_socket(int argc, char *argv[])
{
    int s, type, rc = 0;

    if (argc != 3)
        return EINVAL;

    if (!strcmp(argv[2], "stream"))
        type = SOCK_STREAM;
    else if (!strcmp(argv[2], "dgram"))
        type = SOCK_DGRAM;
    else
        return EINVAL;

    s = socket(AF_VSOCK, type, 0);
    if (s < 0)
        rc = -errno;
    else
        close(s);

    return rc < 0 ? rc : 0;
}

int sockops_bind_dgram(int argc, char *argv[])
{
    int s, rc = 0;
    struct sockaddr_vm sa = { 0 };

    cmd_parse_sockaddr(argc, argv, &sa);
    s = __vsock_dgram();
    if (bind(s, (struct sockaddr*)&sa, sizeof (sa))) {
        rc = -errno;
        perror("bind");
    }
    return rc;
}

int sockops_recvfrom(int argc, char *argv[])
{
    int s, rc;
    unsigned long port;
    struct sockaddr_vm sa = { 0 };
    struct sockaddr_vm sa_peer = { 0 };
    socklen_t sa_len = sizeof (sa_peer);
    char msg[128] = { 0 };

    if (argc != 3)
        return -EINVAL;

    if (parse_ul(argv[2], &port))
        return -EINVAL;
    sa.svm_family = AF_VSOCK;
    sa.svm_cid = V4V_DOMID_ANY;
    sa.svm_port = port;
    s = __vsock_bdgram(&sa);
    rc = recvfrom(s, msg, sizeof (msg), 0,
            (struct sockaddr *)&sa_peer, &sa_len);
    if (rc < 0) {
        rc = -errno;
        perror("recvfrom");
    } else
        fprintf(stdout, "recvfrom(%u:%u): `%s'\n",
                sa_peer.svm_cid, sa_peer.svm_port, msg);
    close(s);
    return rc < 0 ? rc : 0;
}

int sockops_sendto(int argc, char *argv[])
{
    int s, rc;
    struct sockaddr_vm sa_local = {
        .svm_family = AF_VSOCK,
        .svm_cid = V4V_DOMID_ANY,
        .svm_port = 0,
        .svm_zero = { 0 },
    };
    struct sockaddr_vm sa_peer = { 0 };

    if (argc != 5)
        return -EINVAL;

    cmd_parse_sockaddr(argc, argv, &sa_peer);
    s = __vsock_bdgram(&sa_local);
    rc = sendto(s, argv[4], strlen(argv[4]) + 1, 0,
                (void*)&sa_peer, sizeof (sa_peer));
    if (rc < 0) {
        rc = -errno;
        perror("sendto");
    }
    close(s);
    return rc < 0 ? rc : 0;
}

#if 0
int sockops_bind(int argc, char *argv[])
{
    int s;
    struct sockaddr_v4v sa, osa;
    socklen_t osa_len = sizeof (sa);

    cmd_parse_sockaddr(argc, argv, &sa);
    s = __v4vsock_stream();

    if (bind(s, (struct sockaddr *)&sa, sizeof (sa))) {
        return errno;
    }

    if (getsockname(s, (struct sockaddr *)&osa, &osa_len)) {
        return errno;
    }
    if (osa_len != sizeof (sa) ||
        osa.sa_family != sa.sa_family ||
        //osa.sa_addr.domain != sa.sa_addr.domain ||
        // Actually we cannot bind any addr and without establishing connection, the ring->id.addr
        // structure will be used in .getname() callback.
        // The .domain field gets filled in Xen V4V code with d->domain_id, so we could only expect
        // our own domid to be returned here.
        // XXX: That is an interesting side effect.
        osa.sa_addr.port != sa.sa_addr.port) {
        INF("%u %u vs %u %u",
            osa.sa_addr.domain, osa.sa_addr.port, sa.sa_addr.domain, sa.sa_addr.port);
        return EINVAL;
    }
    return 0;
}

int sockops_listen(int argc, char *argv[])
{
    int s;
    struct sockaddr_v4v sa;

    cmd_parse_sockaddr(argc, argv, &sa);
    s = __v4vsock_bstream(&sa);

    if (listen(s, 1)) {
        return errno;
    }
    return 0;
}
#endif
