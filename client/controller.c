/**
 * @file controller.c
 * rdp2tcp controller
 */
/*
 * This file is part of rdp2tcp
 *
 * Copyright (C) 2010-2011, Nicolas Collignon
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "r2tcli.h"
#include "nethelper.h"

#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#ifndef PTR_DIFF
#define PTR_DIFF(e,s) \
	        ((unsigned int)(((unsigned long)(e))-((unsigned long)(s))))
#endif

/**
 * send an answer to the controller client
 * @param[in] cli controller client socket
 * @param[in] fmt format string
 * @return -1 on error
 */
int controller_answer(netsock_t *cli, const char *fmt, ...)
{
	int ret;
	va_list va;
	char buf[256];

	assert(valid_netsock(cli) && fmt && *fmt);

	va_start(va, fmt);
	ret = vsnprintf(buf, sizeof(buf)-2, fmt, va);
	va_end(va);

	if (ret > 0) {
		buf[ret] = '\n';
		ret = netsock_write(cli, buf, ret+1);
	} else {
		ret = error("failed to prepare controller answer");
	}

	return ret;
}


/**
 * start controller server
 * @param[in] host local hostname
 * @param[in] port local tcp port
 * @return 0 on success
 */
int controller_start(const char *host, unsigned short port)
{
	netsock_t *ns;

	assert(host && *host && port);
	trace_ctrl("host=%s, port=%hu", host, port);

	ns = netsock_bind(NULL, host, port, 0);
	if (!ns)
		return -1;

	ns->type  = NETSOCK_CTRLSRV;
	info(0, "controller listening on %s:%hu", host, port);

	return 0;
}

/**
 * handle controller network accept-event
 * @param[in] ns controller socket
 */
void controller_accept_event(netsock_t *ns)
{
	netsock_t *cli;
	char buf[NETADDRSTR_MAXSIZE];

	assert(valid_netsock(ns) && (ns->type == NETSOCK_CTRLSRV));
	trace_ctrl("");

	cli = netsock_accept(ns);
	if (cli) {
		cli->type = NETSOCK_CTRLCLI;
		cli->tid  = 0xff;
		iobuf_init2(&cli->u.ctrlcli.ibuf, &cli->u.ctrlcli.obuf, "ctrl");
		info(1, "accepted controller %s", netaddr_print(&cli->addr, buf));
	}
}

/**
 * handle controller network read-event
 * @param[in] cli controller socket
 */
int controller_read_event(netsock_t *cli)
{
	char *data, *end;
	int ret;
	unsigned int avail, parsed;
	char host[NETADDRSTR_MAXSIZE];

	assert(valid_netsock(cli) && (cli->type == NETSOCK_CTRLCLI));
	trace_ctrl("");

	ret = netsock_read(cli, &cli->u.ctrlcli.ibuf, 0, NULL);
	if (ret)
		return ret;

	data   = iobuf_dataptr(&cli->u.ctrlcli.ibuf);
	avail  = iobuf_datalen(&cli->u.ctrlcli.ibuf);
	assert(avail);
	parsed = 0;

	// for each line
	do {

		end = memchr(data, '\n', avail-parsed);
		if (!end) {
			ret = 1;
			break;
		}
		*end = 0;
		if (!*data) goto badproto;

		parsed += PTR_DIFF(end, data) + 1;

		if (end[-1] == '\r')
			end[-1] = 0;

		info(0, "cmd=\"%s\"", data);

		if (channel_exec(data) < 0) {
			info(0, "channel_exec failed");
			return -1;
		}

		data = end + 1;

	} while (!ret && (parsed < avail));

	if (parsed > 0)
		iobuf_consume(&cli->u.ctrlcli.ibuf, parsed);

	return ret;

badproto:
	info(0, "closing controller %s (bad protocol)",
			netaddr_print(&cli->addr,host));
	return -1;
}

