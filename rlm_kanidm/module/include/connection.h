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
#ifndef FR_CONNECTION_H
#define FR_CONNECTION_H
/**
 * $Id: 1fd4be4c8e79acc02961bb60437d688a15fb54ff $
 *
 * @file connection.h
 * @brief Structures, prototypes and global variables for server connection pools.
 *
 * @copyright 2012  The FreeRADIUS server project
 * @copyright 2012  Alan DeKok <aland@deployingradius.com>
 */

RCSIDH(connection_h, "$Id: 1fd4be4c8e79acc02961bb60437d688a15fb54ff $")

#include <freeradius-devel/conffile.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fr_connection_pool_t fr_connection_pool_t;

/** Create a new connection handle
 *
 * This function will be called whenever the connection pool manager needs
 * to spawn a new connection, and on reconnect.
 *
 * Memory should be talloced in the parent context to hold the module's
 * connection structure. The parent context is allocated in the NULL
 * context, but will be freed when fr_connection_t is freed.
 *
 * There is no delete callback, so operations such as closing sockets and
 * freeing library connection handles should be done by a destructor attached
 * to memory allocated beneath ctx.
 *
 * @note A function pointer matching this prototype must be passed
 * to fr_connection_pool_init.
 *
 * @param[in,out] ctx to allocate memory in.
 * @param[in] opaque pointer passed to fr_connection_pool_init.
 * @return NULL on error, else a connection handle.
 */
typedef void *(*fr_connection_create_t)(TALLOC_CTX *ctx, void *opaque);

/** Check a connection handle is still viable
 *
 * Should check the state  of a connection handle.
 *
 * @note NULL may be passed to fr_connection_pool_init, if there is no way to check
 * the state of a connection handle.
 * @note Not currently use by connection pool manager.
 * @param[in] opaque pointer passed to fr_connection_pool_init.
 * @param[in] connection handle returned by fr_connection_create_t.
 * @return < 0 on error or if the connection is unusable, else 0.
 */
typedef int (*fr_connection_alive_t)(void *opaque, void *connection);

/*
 *	Pool allocation/initialisation
 */
fr_connection_pool_t	*fr_connection_pool_module_init(CONF_SECTION *module,
							void *opaque,
							fr_connection_create_t c,
							fr_connection_alive_t a,
							char const *prefix);

/*
 *	Pool getters
 */
int	fr_connection_pool_get_num(fr_connection_pool_t *pool);

int	fr_connection_pool_get_retries(fr_connection_pool_t *pool);

/*
 *	Pool management
 */
void	fr_connection_pool_free(fr_connection_pool_t *pool);

/*
 *	Connection lifecycle
 */
void	*fr_connection_get(fr_connection_pool_t *pool);

void	fr_connection_release(fr_connection_pool_t *pool, void *conn);

void	*fr_connection_reconnect(fr_connection_pool_t *pool, void *conn);

int	fr_connection_close(fr_connection_pool_t *pool, void *conn, char const *msg);

typedef struct {
	time_t		last_checked;		//!< Last time we pruned the connection pool.
	time_t		last_opened;		//!< Last time we opened a connection.
	time_t		last_closed;		//!< Last time we closed a connection.
	time_t		last_failed;		//!< Last time we tried to spawn a connection but failed.
	time_t		last_throttled;		//!< Last time we refused to spawn a connection because
						//!< the last connection failed, or we were already spawning
						//!< a connection.
	time_t		last_at_max;		//!< Last time we hit the maximum number of allowed
						//!< connections.

	uint64_t	opened;	       		//!< Number of connections opened over the lifetime
						//!< of the pool.
	uint64_t	closed;			//!< Number of connections which were closed for this pool
	uint64_t	failed;			//!< Number of failed connections for this pool.

	uint32_t       	num;			//!< Number of connections in the pool.
	uint32_t	active;	 		//!< Number of currently reserved connections.
} fr_connection_pool_stats_t;

fr_connection_pool_stats_t const *fr_connection_pool_stats(CONF_SECTION *cs);

#ifdef __cplusplus
}
#endif

#endif /* FR_CONNECTION_H*/
