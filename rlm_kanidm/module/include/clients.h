/*
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   the Free Software Foundation; either version 2 of the License, or (at
 *   your option) any later version. either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */
#ifndef CLIENTS_H
#define CLIENTS_H
/*
 * $Id: dfbc5e4010552d2ee0856207d547709a624bee53 $
 *
 * @file clients.h
 * @brief Function declarations and structures to manage clients.
 *
 * @author Arran Cudbard-Bell <a.cudbardb@freeradius.org>
 * @copyright 2015 The FreeRADIUS server project
 */

typedef struct radclient_list RADCLIENT_LIST;


/** Describes a host allowed to send packets to the server
 *
 */
typedef struct radclient {
	RADCLIENT_LIST		*list;			//!< parent list
	fr_ipaddr_t		ipaddr;			//!< IPv4/IPv6 address of the host.
	fr_ipaddr_t		src_ipaddr;		//!< IPv4/IPv6 address to send responses
							//!< from (family must match ipaddr).

	char const		*longname;		//!< Client identifier.
	char const		*shortname;		//!< Client nickname.

	char const		*secret;		//!< Secret PSK.

	fr_bool_auto_t 		require_ma;		//!< Require RADIUS message authenticator in requests.

	bool			dynamic_require_ma;	//!< for dynamic clients
	bool			protocol_error;		//!< can receive Protocol-Error replies
#ifdef WITH_COA_TUNNEL
	bool			reverse_coa;		//!< can receive CoA requests on its own connection
#endif

	fr_bool_auto_t 		limit_proxy_state;     	//!< Limit Proxy-State in requests

	char const		*nas_type;		//!< Type of client (arbitrary).

	char const		*login;			//!< Username to use for simultaneous use checks.
	char const		*password;		//!< Password to use for simultaneous use checks.

	char const 		*server;		//!< Virtual server client is associated with.

	int			number;			//!< Unique client number.

	CONF_SECTION	 	*cs;			//!< CONF_SECTION that was parsed to generate the client.

#ifdef WITH_STATS
	fr_stats_t		auth;			//!< Authentication stats.
#  ifdef WITH_ACCOUNTING
	fr_stats_t		acct;			//!< Accounting stats.
#  endif
#  ifdef WITH_COA
	fr_stats_t		coa;			//!< Change of Authorization stats.
	fr_stats_t		dsc;			//!< Disconnect-Request stats.
#  endif
#endif

	struct timeval		response_window;	//!< How long the client has to respond.

	int			proto;			//!< Protocol number.
#ifdef WITH_TCP
	fr_socket_limit_t	limit;			//!< Connections per client (TCP clients only).
#endif
#ifdef WITH_TLS
	bool			tls_required;		//!< whether TLS encryption is required.
	fr_tls_server_conf_t	*tls;
#ifdef WITH_RADIUSV11
	char const		*radiusv11_name;
	fr_radiusv11_t 		radiusv11;
#endif
#endif

#ifdef WITH_DYNAMIC_CLIENTS
	uint32_t		lifetime;		//!< How long before the client is removed.
	uint32_t		dynamic;		//!< Whether the client was dynamically defined.
	time_t			created;		//!< When the client was created.

	time_t			last_new_client;	//!< Used for relate limiting addition and deletion of
							//!< dynamic clients.

	char const		*client_server;		//!< Virtual server associated with this dynamic client.
							//!< Only used where client specifies a network of potential
							//!< clients.

	bool			rate_limit;		//!< Where addition of clients should be rate limited.
	fr_event_t		*ev;			//!< for deleting dynamic clients
#endif

#ifdef WITH_COA
	char const		*coa_name;		//!< Name of the CoA home server or pool.
	home_server_t		*coa_home_server;	//!< The CoA home_server_t the client is associated with.
							//!< Must be used exclusively from coa_pool.
	home_pool_t		*coa_home_pool;		//!< The CoA home_pool_t the client is associated with.
							//!< Must be used exclusively from coa_server.
	bool			defines_coa_server;	//!< Client also defines a home_server.
#endif
} RADCLIENT;

/** Callback for retrieving values when building client sections
 *
 * Example:
 @code{.c}
   int _client_value_cb(char **out, CONF_PAIR const *cp, void *data)
   {
   	my_result *result = data;
   	char *value;

   	value = get_attribute_from_result(result, cf_pair_value(cp));
   	if (!value) {
   		*out = NULL;
   		return 0;
   	}

   	*out = talloc_strdup(value);
   	free_attribute(value);

   	if (!*out) return -1;
   	return 0;
   }
 @endcode
 *
 * @param[out] out Where to write a pointer to the talloced value buffer.
 * @param[in] cp The value of the CONF_PAIR specifies the attribute name to retrieve from the result.
 * @param[in] data Pointer to the result struct to copy values from.
 * @return 0 on success -1 on failure.
 */
typedef int (*client_value_cb_t)(char **out, CONF_PAIR const *cp, void *data);

RADCLIENT_LIST	*client_list_init(CONF_SECTION *cs);

void		client_list_free(RADCLIENT_LIST *clients);

RADCLIENT_LIST	*client_list_parse_section(CONF_SECTION *section, bool tls_required);

void		client_free(RADCLIENT *client);

bool		client_add(RADCLIENT_LIST *clients, RADCLIENT *client);

#ifdef WITH_DYNAMIC_CLIENTS
void		client_delete(RADCLIENT_LIST *clients, RADCLIENT *client);

RADCLIENT	*client_afrom_request(RADCLIENT_LIST *clients, REQUEST *request);
#endif

int		client_map_section(CONF_SECTION *out, CONF_SECTION const *map, client_value_cb_t func, void *data);

RADCLIENT	*client_afrom_cs(TALLOC_CTX *ctx, CONF_SECTION *cs, bool in_server, bool with_coa);

RADCLIENT	*client_afrom_query(TALLOC_CTX *ctx, char const *identifier, char const *secret, char const *shortname,
				    char const *type, char const *server)
		CC_HINT(nonnull(2, 3));

RADCLIENT	*client_find(RADCLIENT_LIST const *clients, fr_ipaddr_t const *ipaddr, int proto);

RADCLIENT	*client_findbynumber(RADCLIENT_LIST const *clients, int number);

RADCLIENT	*client_find_old(fr_ipaddr_t const *ipaddr);

RADCLIENT	*client_add_dynamic(RADCLIENT_LIST *clients, RADCLIENT *master, RADCLIENT *c, bool can_free);

RADCLIENT	*client_read(char const *filename, int in_server, int flag);
#endif	/* CLIENTS_H */
