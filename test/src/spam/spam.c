#include "project.h"

struct spam_cmds {
    int (*ops)(int argc, char *argv[]);
    char *cmd;
    char *desc;
};

static int spam_usage(int argc, char *argv[]);
static int spam_sendto(int argc, char *argv[]);
static int spam_recvfrom(int argc, char *argv[]);
static int spam_sendto_one(int argc, char *argv[]);

struct spam_cmds cmds[] = {
    { spam_usage,       "help",     "Display help." },
    { spam_recvfrom,    "recvfrom", "<n> <port>		From <port> to <port> + n-1, wait for datagram to be received, then print the payload on stdout." },
    { spam_sendto,      "sendto",   "<id> <n> <port>	Open n threads, one for each port, from <port> to <port>+n-1 and keep sending random things ton domain <id> on each port." },
    { spam_sendto_one,  "sendto1",  "<id> <n> <port>	Open <n> threads and keep sending random things to domain <id> on <port>." },
};

static int spam_usage(int argc, char *argv[])
{
    unused(argc);
    unused(argv);
    unsigned int i;

    INF("Usage: spam <command> [...]");
    INF("Commands:");
    for (i = 0; i < ARRAY_LEN(cmds); ++i)
        INF("%s	%s", cmds[i].cmd, cmds[i].desc);

    return 0;
}

struct thread_info {
    pthread_t id;
    struct sockaddr_vm sa;
};

/*
 * General "halt" signal & lock.
 */
static bool threads_halt = false;
static pthread_rwlock_t threads_halt_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static inline void threads_trigger_halt(void)
{
    pthread_rwlock_wrlock(&threads_halt_rwlock);
    threads_halt = true;
    pthread_rwlock_unlock(&threads_halt_rwlock);
}

static inline bool threads_should_halt(void)
{
    bool ret;

    pthread_rwlock_rdlock(&threads_halt_rwlock);
    ret = threads_halt;
    pthread_rwlock_unlock(&threads_halt_rwlock);
    return ret;
}

static void signal_handler(int sig)
{
    printf("Signal %s.\n", strsignal(sig));
    threads_trigger_halt();
    signal(sig, &signal_handler);
}

static int signals_setup(void)
{
    struct sigaction act = { 0 };
    int sigs[] = { SIGINT, SIGTERM, SIGHUP };
    size_t i;
    int rc;

    for (i = 0; i < (sizeof (sigs) / sizeof (sigs[0])); ++i) {
        rc = sigaction(sigs[i], NULL, &act);
        if (rc < 0) {
            perror("sigaction");
            return -errno;
        }
        act.sa_handler = &signal_handler;
        act.sa_flags &= ~SA_RESTART;
        rc = sigaction(sigs[i], &act, NULL);
        if (rc < 0) {
            perror("sigaction");
            return -errno;
        }
    }
    return 0;
}

static const char *sentence_dict[] = {
    "I envy him his good fortune.",
    "That plumber grants him his wish.",
    "They bought her a gift.",
    "Those photographers made him some coffee.",
    "They gave him a book.",
    "I called him \"the student\".",
    "That manager had him drive.",
    "Those computer programmers hear the girl crying.",
    "That flight attendant finds the book interesting.",
    "They elected her chairperson.",
    "Those singers painted the room green.",
    "I keep the milk cold.",
    "They named the ship Titanic.",
    "Those singers get the TV repaired.",
    "That police officer finds the book interesting.",
};

static void *__spam_sendto(void *arg)
{
    struct thread_info *ti = arg;
    int s, rc = 0;
#define AUTOBIND
#ifndef AUTOBIND
    struct sockaddr_vm sa_local = {
        .svm_family = AF_VSOCK,
        .svm_cid = V4V_DOMID_ANY,
        .svm_port = 0,
        .svm_zero = { 0 },
    };
#endif
    const char *msg = sentence_dict[random() % (sizeof (sentence_dict) / sizeof (char *))];

    if (!ti)
        return NULL;

#ifndef AUTOBIND
    s = __vsock_bdgram(&sa_local);
#else /* !AUTOBIND */
    s = __vsock_dgram();
#endif /* AUTOBIND */

    while (!threads_should_halt()) {

        rc = sendto(s, msg, strlen(msg) + 1, 0,
                    (struct sockaddr *)&ti->sa, sizeof (ti->sa));
        if (rc < 0) {
            switch (errno) {
                case EAGAIN:
                    continue;
                default:
                    perror("sendto");
                    goto out;
            }
        }
    }

out:
    close(s);
    return NULL;
}

static int spam_sendto(int argc, char *argv[])
{
    struct thread_info *tis;
    pthread_attr_t attr;
    void *ret;
    size_t i, len;
    unsigned long domid;
    unsigned long first_port;
    int rc = 0;

    if (argc != 5)
        return -EINVAL;
    if (parse_ul(argv[2], &domid))
        return -EINVAL;
    if (parse_ul(argv[3], &len))
        return -EINVAL;
    if (parse_ul(argv[4], &first_port))
        return -EINVAL;

    /* Gracefuly quit when signaled. */
    rc = signals_setup();
    if (rc < 0)
        return -rc;

    if (pthread_attr_init(&attr)) {
        perror("pthread_attr_init");
        return -errno;
    }

    tis = calloc(len, sizeof (tis[0]));
    if (!tis) {
        rc = -errno;
        perror("calloc");
        goto out;
    }

    /* Start all. */
    INF("Starting %zu writer-threads to dom%lu port %lu to %lu.",
        len, domid, first_port, first_port + len - 1);
    for (i = 0; i < len; ++i) {
        tis[i].sa.svm_family = AF_VSOCK;
        tis[i].sa.svm_cid = domid;
        tis[i].sa.svm_port = first_port + i;
        if (pthread_create(&tis[i].id, &attr, &__spam_sendto, &tis[i])) {
            rc = -errno;
            perror("pthread_create");
            kill(getpid(), SIGINT); // Break blocking calls.
            break;
        }
    }
    /* Unwind and join all. */
    for (--i; i != ~0UL; --i)
        if (pthread_join(tis[i].id, &ret)) {
            rc = -errno;
            perror("pthread_join");
        }

    free(tis);
out:
    pthread_attr_destroy(&attr);
    return rc;
}

static int spam_sendto_one(int argc, char *argv[])
{
    struct thread_info *tis;
    pthread_attr_t attr;
    void *ret;
    size_t i, len;
    unsigned long domid, port;
    int rc = 0;

    if (argc != 5)
        return -EINVAL;
    if (parse_ul(argv[2], &domid))
        return -EINVAL;
    if (parse_ul(argv[3], &len))
        return -EINVAL;
    if (parse_ul(argv[4], &port))
        return -EINVAL;

    /* Gracefuly quit when signaled. */
    rc = signals_setup();
    if (rc < 0)
        return -rc;

    if (pthread_attr_init(&attr)) {
        perror("pthread_attr_init");
        return -errno;
    }

    tis = calloc(len, sizeof (tis[0]));
    if (!tis) {
        rc = -errno;
        perror("calloc");
        goto out;
    }

    /* Start all. */
    INF("Starting %zu writer-threads to dom%lu port %lu.", len, domid, port);
    for (i = 0; i < len; ++i) {
        tis[i].sa.svm_family = AF_VSOCK;
        tis[i].sa.svm_cid = domid;
        tis[i].sa.svm_port = port;
        if (pthread_create(&tis[i].id, &attr, &__spam_sendto, &tis[i])) {
            rc = -errno;
            perror("pthread_create");
            kill(getpid(), SIGINT); // Break blocking calls.
            break;
        }
    }
    /* Unwind and join all. */
    for (--i; i != ~0UL; --i)
        if (pthread_join(tis[i].id, &ret)) {
            rc = -errno;
            perror("pthread_join");
        }

    free(tis);
out:
    pthread_attr_destroy(&attr);
    return rc;
}

static void *__spam_recvfrom(void *arg)
{
    struct thread_info *ti = arg;
    int s, rc = 0;
    char msg[1024] = { 0 };
    struct sockaddr_vm sa = { 0 };
    socklen_t sa_len = 0;
    struct pollfd fd = { 0 };
    int to_ms = 750;

    if (!ti)
        return NULL;

    s = __vsock_bdgram(&ti->sa);

    fd.fd = s;
    fd.events = POLLIN;

    while (!threads_should_halt()) {
        /* Poll for values to be read every 750ms.  If a signal is received, we
         * can then gracefuly shutdown. */
        rc = poll(&fd, 1, to_ms);
        if (rc < 0) {
            perror("poll");
            goto out;
        } else if (rc == 0)
            continue;

        rc = recvfrom(s, msg, sizeof (msg), 0,
                      (struct sockaddr *)&sa, &sa_len);
        if (rc < 0) {
            switch (errno) {
                case EAGAIN:
                    break;
                default:
                    perror("recvfrom");
                    goto out;
            }
        } else
            INF("dom%u:%u: `%s'", sa.svm_cid, sa.svm_port, msg);
    }

out:
    close(s);
    return NULL;
}

static int spam_recvfrom(int argc, char *argv[])
{
    struct thread_info *tis;
    pthread_attr_t attr;
    void *ret;
    size_t i, len;
    unsigned long first_port;
    int rc = 0;

    if (argc != 4)
        return -EINVAL;
    if (parse_ul(argv[2], &len))
        return -EINVAL;
    if (parse_ul(argv[3], &first_port))
        return -EINVAL;

    /* Gracefuly quit when signaled. */
    rc = signals_setup();
    if (rc < 0)
        return -rc;

    if (pthread_attr_init(&attr)) {
        perror("pthread_attr_init");
        return -errno;
    }

    tis = calloc(len, sizeof (tis[0]));
    if (!tis) {
        rc = -errno;
        perror("calloc");
        goto out;
    }

    /* Start all. */
    INF("Starting %zu reader-threads from port %lu to %lu.",
        len, first_port, first_port + len - 1);
    for (i = 0; i < len; ++i) {
        tis[i].sa.svm_family = AF_VSOCK;
        tis[i].sa.svm_cid = V4V_DOMID_ANY;
        tis[i].sa.svm_port = first_port + i;
        if (pthread_create(&tis[i].id, &attr, &__spam_recvfrom, &tis[i])) {
            rc = -errno;
            perror("pthread_create");
            kill(getpid(), SIGINT); // Break blocking calls.
            break;
        }
    }
    /* Unwind and join all. */
    for (--i; i != ~0UL; --i)
        if (pthread_join(tis[i].id, &ret)) {
            rc = -errno;
            perror("pthread_join");
        }

    free(tis);
out:
    pthread_attr_destroy(&attr);
    return rc;
}

int main(int argc, char *argv[])
{
    unsigned int i;
    int rc;

    if (argc < 2) {
        spam_usage(argc, argv);
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

