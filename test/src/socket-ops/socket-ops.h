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

#ifndef _SOCKET_OPS_H_
# define _SOCKET_OPS_H_

# define V4V_DOMID_ANY 0x7fffU

int sockops_socket(int argc, char *argv[]);
int sockops_bind_dgram(int argc, char *argv[]);

int sockops_recvfrom(int argc, char *argv[]);
int sockops_sendto(int argc, char *argv[]);

#if 0
int sockops_bind(int argc, char *argv[]);
int sockops_listen(int argc, char *argv[]);
#endif

#endif /* !_SOCKET_OPS_H_ */

