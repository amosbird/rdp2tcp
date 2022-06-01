/**
 * @file tunnel.c
 * rdp2tcp tunnels management
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
#include "rdp2tcp.h"
#include "r2twin.h"
#include "print.h"

#include <stdio.h>

const char *r2t_errors[R2TERR_MAX] = {
	"",
	"generic error",
	"bad message",
	"connection refused",
	"forbidden",
	"address not available",
	"failed to resolve hostname",
	"executable not found"
};

/** global tunnels double-linked list */
LIST_HEAD_INIT(all_tunnels);

/** lookup rdp2tcp tunnel
 * @param[in] id rdp2tcp tunnel ID
 * @return NULL if tunnel is not found */
tunnel_t *tunnel_lookup(unsigned char id)
{
	tunnel_t *tun;

	//trace_tun("id=0x%02x", id);
	list_for_each(tun, &all_tunnels) {
		if (tun->id == id)
			return tun;
	}

	return NULL;
}

static unsigned char wsa_to_r2t_error(int err)
{
	switch (err) {
		case WSAEACCES: return R2TERR_FORBIDDEN;
		case WSAECONNREFUSED: return R2TERR_CONNREFUSED;
		case WSAEADDRNOTAVAIL: return R2TERR_NOTAVAIL;
		case WSAHOST_NOT_FOUND: return R2TERR_RESOLVE;
	}

	return R2TERR_GENERIC;
}

static unsigned int netaddr_to_connans(
			const netaddr_t *addr,
			r2tmsg_connans_t *msg)
{
	unsigned int msg_len;

	memset(msg, 0, sizeof(*msg));
	msg->err = R2TERR_SUCCESS;

	if (netaddr_af(addr) == AF_INET) {
		msg->af   = TUNAF_IPV4;
		msg->port = addr->ip4.sin_port;
		memcpy(&msg->addr, &addr->ip4.sin_addr, 4);
		msg_len = 8;
	} else {
		msg->af   = TUNAF_IPV6;
		msg->port = addr->ip6.sin6_port;
		memcpy(&msg->addr, &addr->ip6.sin6_addr, 16);
		msg_len = 20;
	}

	return msg_len;
}

static int host_bind(
		tunnel_t *tun,
		int pref_af,
		const char *host,
		unsigned short port)
{
	int ret, err;
	unsigned int ans_len;
	r2tmsg_connans_t ans;

	memset(&ans, 0, sizeof(ans));
	ans_len = 1;

	ret = net_server(pref_af, host, port, &tun->sock, &tun->addr, &err);
	debug(0, "bind %s:%hu ... %i/%i", host, port, ret, err);
	if (!ret) {
		info(0, "listening on %s:%hu", host, port);
		ans_len = netaddr_to_connans(&tun->addr, &ans);
		ans.err = 0;
		if (event_add_tunnel(tun->sock.evt, tun->id)) {
			ans.err = R2TERR_GENERIC;
			net_close(&tun->sock);
			ret = -1;
		}

	} else {
		ans.err = wsa_to_r2t_error(err);
		error("failed to bind %s:%hu (%i %s)", host, port, err, r2t_errors[ans.err]);
	}

	tun->connected = 1;
	tun->server = 1;
	return 0;
}


static tunnel_t *tunnel_alloc(unsigned char id)
{
	tunnel_t *tun;

	tun = calloc(1, sizeof(*tun));
	if (tun) {
		tun->id = id;
	} else {
		error("failed to allocate tunnel");
	}

	return tun;
}

/**
 * create rdp2tcp tunnel
 * @param[in] id rdp2tcp tunnel ID
 * @param[in] pref_af preferred address family
 * @param[in] host tunnel hostname or command line
 * @param[in] port tcp tunnel port or 0 for process tunnel
 * @param[in] bind_socket 1 for reverse connect tunnel
 */
void tunnel_create(
			unsigned char id,
			int pref_af,
			const char *host,
			unsigned short port,
			int bind_socket)
{
	tunnel_t *tun;
	int ret;

	assert(host && *host);
	trace_tun("id=0x%02x, pref_af=%i, host=%s, port=%hu", id, pref_af, host, port);

	tun = tunnel_alloc(id);
	if (!tun)
		return;

	ret = host_bind(tun, pref_af, host, port);

	if (ret >= 0) {
		list_add_tail(&tun->list, &all_tunnels);
		debug(0, "tunnel 0x%02x created", id);

	} else {
		debug(0, "failed to create tunnel 0x%02x", id);
		free(tun);
	}
}

/** close rdp2tcp tunnel
 * @param[in] tun established tunnel */
void tunnel_close(tunnel_t *tun)
{
	assert(valid_tunnel(tun));
	trace_tun("id=0x%02x", tun->id);

	list_del(&tun->list);

	event_del_tunnel(tun->id);

	net_close(&tun->sock);

	free(tun);
}

static int tunnel_sockrecv_event(tunnel_t *tun)
{
	int ret;
	unsigned int r;

	assert(valid_tunnel(tun));

	ret = net_read(&tun->sock, &tun->rio.buf, 0, &tun->rio.min_io_size, &r);
	trace_tun("id=0x%02x --> ret=%i, r=%u", tun->id, ret, r);
	if (ret < 0)
		return error("%s", net_error(NETERR_RECV, ret));

	if (r > 0) {
		print_xfer("tcp", 'r', r);
		if (channel_forward(tun) < 0)
			return error("failed to forward");

	//	if (net_update_watch(&tun->sock, &tun->wio.buf))
	//		return wsaerror("WSAEventSelect");
	}

	return 0;
}

/** handle tunnel event
 * @param[in] tun tunnel associated with event
 * @param[in] h event handle
 * @return 0 on success
 */
int tunnel_event(tunnel_t *tun, HANDLE h)
{
	int ret, evt;
	WSANETWORKEVENTS events;

	assert(valid_tunnel(tun) && h);
	trace_tun("id=0x%02x %s h=%x", tun->id, tun->proc ? "proc" : "tcp", h);

	ret = 0;
	events.lNetworkEvents = 0;

	if (!WSAEnumNetworkEvents(tun->sock.fd, tun->sock.evt, &events)) {

		evt = (int) events.lNetworkEvents;

		info(1, "close=%i, conn=%i/%i, read=%i, write=%i, accept=%i",
				!!(evt & FD_CLOSE), !!(evt & FD_CONNECT), tun->connected,
				!!(evt & FD_READ), !!(evt & FD_WRITE),
				!!(evt & FD_ACCEPT));

		if ((ret >= 0) && (evt & FD_READ)) {
			debug(0, "FD_READ");
			ret = tunnel_sockrecv_event(tun);
		}
	} else {
		if (WSAGetLastError() != ERROR_IO_PENDING)
			return wsaerror("WSAEnumNetworkEvents");
	}

	if (ret < 0)
		tunnel_close(tun);

	return 0;
}

/** destroy all tunnels */
void tunnels_kill(void)
{
	tunnel_t *tun, *bak;

	trace_tun("");

	list_for_each_safe(tun, bak, &all_tunnels) {
		tunnel_close(tun);
	}
}

