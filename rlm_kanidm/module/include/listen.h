/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */
#ifndef LISTEN_H
#define LISTEN_H
/**
 * $Id: 6e958f615377c5cae9960d28004de1ad62411bf1 $
 *
 * @file listen.h
 * @brief The listener API.
 *
 * @copyright 2015  The FreeRADIUS server project
 */

/*
 *	Types of listeners.
 *
 *	Ordered by priority!
 */
typedef enum RAD_LISTEN_TYPE {
	RAD_LISTEN_NONE = 0,
	RAD_LISTEN_PROXY,
	RAD_LISTEN_AUTH,
	RAD_LISTEN_ACCT,
	RAD_LISTEN_DETAIL,
	RAD_LISTEN_VQP,
	RAD_LISTEN_DHCP,
	RAD_LISTEN_COMMAND,
	RAD_LISTEN_COA,
	RAD_LISTEN_MAX
} RAD_LISTEN_TYPE;

typedef enum RAD_LISTEN_STATUS {
	RAD_LISTEN_STATUS_INIT = 0,		//!< starting up
	RAD_LISTEN_STATUS_KNOWN,		//!< alive and operating normally
	RAD_LISTEN_STATUS_PAUSE,		//!< TLS connection checking: don't read normal packets
	RAD_LISTEN_STATUS_RESUME,		//!< TLS connection checking: resume reading normal packets
	RAD_LISTEN_STATUS_DRAINING,		//!< alive, but we're not sending any more packets to it
	RAD_LISTEN_STATUS_EOL,			//!< we're trying to delete it.
	RAD_LISTEN_STATUS_REMOVE_NOW		//!< no request is using it, delete the listener.
} RAD_LISTEN_STATUS;

typedef struct rad_listen rad_listen_t;

typedef int (*rad_listen_recv_t)(rad_listen_t *);
typedef int (*rad_listen_send_t)(rad_listen_t *, REQUEST *);
typedef int (*rad_listen_print_t)(rad_listen_t const *, char *, size_t);
typedef int (*rad_listen_encode_t)(rad_listen_t *, REQUEST *);
typedef int (*rad_listen_decode_t)(rad_listen_t *, REQUEST *);

struct rad_listen {
	rad_listen_t *next; /* should be rbtree stuff */
	bool	     fd_updating;

	/*
	 *	For normal sockets.
	 */
	RAD_LISTEN_TYPE	type;
	int		fd;
	char const	*server;
	int		status;
	int		count;
#ifdef WITH_TCP
	rbtree_t	*children;
	rad_listen_t	*parent;

	bool		proxy_protocol;		//!< haproxy protocol
	bool		listen;			//! just calls listen()
	bool		blocked;		//!< writes are frozen until the socket is writable
#endif
	bool		dual;
	bool		nodup;
	bool		dead;
	bool		filter_proxy_state;	//!< Whether to filter Proxy-State
	uint32_t	proxy_state_random[2];	//!< seed for Proxy-State

#ifdef WITH_TLS
	fr_tls_server_conf_t *tls;
	bool		check_client_connections;

	fr_dlist_t		entry;		//!< for the home server free list

#ifdef WITH_RADIUSV11
	fr_radiusv11_t 	radiusv11;
#endif

#ifdef WITH_COA_TUNNEL
	char const	*key;		/* the first Originating-Realm-Key */
	uint32_t	num_keys;
	bool		send_coa;	/* to the NAS */

	uint32_t	coa_irt;
	uint32_t	coa_mrc;
	uint32_t	coa_mrt;
	uint32_t	coa_mrd;
	uint32_t	coa_max_keys;

	int		num_ids_used;	/* for proxying CoA packets */
#endif
#endif

	rad_listen_recv_t recv;
	rad_listen_send_t send;

	/*
	 *	We don't need a proxy_recv, because the main loop in
	 *	process.c calls listener->recv(), and we don't know
	 *	what kind of packet we're receiving until we receive
	 *	it.
	 */
	rad_listen_send_t proxy_send;


	rad_listen_encode_t encode;
	rad_listen_decode_t decode;
	rad_listen_encode_t proxy_encode;
	rad_listen_decode_t proxy_decode;
	rad_listen_print_t print;

	CONF_SECTION const *cs;
	void		*data;

#ifdef WITH_STATS
	fr_stats_t	stats;
#endif
};

/*
 *	This shouldn't really be exposed...
 */
typedef struct listen_socket_t {
	/*
	 *	For normal sockets.
	 */
	fr_ipaddr_t	my_ipaddr;
	uint16_t	my_port;

	uint32_t	backlog;

	char const	*interface;
#ifdef SO_BROADCAST
	int		broadcast;
#endif

	int		recv_buff;

	time_t		rate_time;
	uint32_t	rate_pps_old;
	uint32_t	rate_pps_now;
	uint32_t	max_rate;

	/* for outgoing sockets */
	home_server_t	*home;
	fr_ipaddr_t	other_ipaddr;
	uint16_t	other_port;

	int		proto;

#ifdef WITH_TCP
	/* for a proxy connecting to home servers */
	time_t		last_packet;
	time_t		opened;
	fr_event_t	*ev;

	fr_socket_limit_t limit;

	struct listen_socket_t *parent;
	RADCLIENT	*client;

	RADIUS_PACKET   *packet; /* for reading partial packets */

	fr_ipaddr_t	haproxy_src_ipaddr;	//!< for proxy_protocol
	fr_ipaddr_t	haproxy_dst_ipaddr;
	uint16_t	haproxy_src_port;
	uint16_t	haproxy_dst_port;

	bool		connection_counted;	//!< this connection is counted in home->active_connections
	bool		connected;		//!< was this socket connected?

	pthread_mutex_t *mutex;			//!< protects the buffered write state
	fr_event_fd_handler_t write_handler;	//!< installed when the socket joins the event loop

	uint8_t		*read_buf;		//!< one partial packet read from a proxy socket
	size_t		read_used;		//!< bytes in read_buf
	uint8_t		*write_buf;		//!< packets which write() did not accept
	size_t		write_used;		//!< bytes in write_buf
	bool		connecting;		//!< the connect timer has seen this socket unconnected
#endif

#ifdef WITH_TLS
	tls_session_t	*ssn;
	REQUEST		*request; /* horrible hacks */
	VALUE_PAIR	*certs;
	uint32_t	connect_timeout;
	uint8_t		*data;
	size_t		partial;

	enum {
		LISTEN_TLS_INIT = 0,
		LISTEN_TLS_CHECKING,
		LISTEN_TLS_SETUP,
		LISTEN_TLS_RUNNING,
	} state;

	bool		client_closed;

#ifdef WITH_RADIUSV11
	bool		alpn_checked;
	bool		radiusv11;		//!< defaults to "no"!
#endif
#endif

	RADCLIENT_LIST	*clients;
} listen_socket_t;

#ifdef WITH_PROXY
void proxy_stats(rad_listen_t *listener, home_server_t *home, int code, size_t offset, time_t when);
uint32_t proxy_state_hash(uint32_t seed[static 2], fr_ipaddr_t const *home_ip, int home_port);
bool proxy_state_hash_check(rad_listen_t *listener, RADIUS_PACKET *packet);

#ifdef WITH_TCP
void		home_server_active_connections_increment(rad_listen_t *listener);
void		home_server_active_connections_decrement(rad_listen_t *listener);
#endif
#endif

#endif /* LISTEN_H */

