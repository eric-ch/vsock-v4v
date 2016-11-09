/*
 * Copyright (c) 2016 Assured Information Security, Inc.
 *
 * Author:
 * Eric Chanudet <chanudete@ainfosec.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _PROJECT_INTERNALS_H_
# define _PROJECT_INTERNALS_H_

# define V4V_DOMID_ANY 0x7fffU

static inline int __vsock_stream(void)
{
    int s;

    s = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (s < 0) {
	perror("socket");
        exit(errno);
    }

    return s;
}

static inline int __vsock_bstream(struct sockaddr_vm *sa)
{
    int s;

    s = __vsock_stream();
    if (bind(s, (struct sockaddr *)sa, sizeof (*sa))) {
	perror("bind");
        exit(errno);
    }

    return s;
}

static inline int __vsock_dgram(void)
{
    int s;

    s = socket(AF_VSOCK, SOCK_DGRAM, 0);
    if (s < 0) {
	perror("socket");
        exit(errno);
    }

    return s;
}

static inline int __vsock_bdgram(struct sockaddr_vm *sa)
{
    int s;

    s = __vsock_dgram();
    if (bind(s, (struct sockaddr *)sa, sizeof (*sa))) {
	perror("bind");
        exit(errno);
    }

    return s;
}

static inline void cmd_parse_sockaddr(int argc, char *argv[],
                                      struct sockaddr_vm *sa)
{
    unsigned long domid, port;

    if (!sa)
        exit(EFAULT);

    if (argc < 4)
        exit(EINVAL);

    if (parse_ul(argv[2], &domid) || parse_ul(argv[3], &port))
        exit(EINVAL);

    if ((domid > V4V_DOMID_ANY) || (/*!port ||*/ (port > 65535)))
        exit(EINVAL);

    memset(sa, 0, sizeof (*sa));
    sa->svm_family = AF_VSOCK;
    sa->svm_cid = domid;
    sa->svm_port = port;
    INF("Parsed dom%ld:%ld.", domid, port);
}

#endif /* !_PROJECT_INTERNALS_H_ */

