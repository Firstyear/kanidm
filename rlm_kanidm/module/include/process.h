#ifndef FR_PROCESS_H
#define FR_PROCESS_H

/*
 * process.h	State machine for a server to process packets.
 *
 * Version:	$Id: 75fc50463d14933c21ab641deab50c42ec9eeab9 $
 *
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
 *
 * Copyright 2012 The FreeRADIUS server project
 * Copyright 2012 Alan DeKok <aland@deployingradius.com>
 */

RCSIDH(process_h, "$Id: 75fc50463d14933c21ab641deab50c42ec9eeab9 $")

#include <freeradius-devel/clients.h>
#include <freeradius-devel/listen.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_SYSTEMD_WATCHDOG
extern struct timeval sd_watchdog_interval;
#endif

typedef enum fr_state_action_t {	/* server action */
	FR_ACTION_INVALID = 0,
	FR_ACTION_RUN,
	FR_ACTION_DONE,
	FR_ACTION_DUP,
	FR_ACTION_TIMER,
#ifdef WITH_PROXY
	FR_ACTION_PROXY_REPLY,
#endif
	FR_ACTION_CANCELLED,
	FR_ACTION_CONFLICT,
	FR_ACTION_MAX_TIME,
	FR_ACTION_INTERNAL_FAILURE,
	FR_ACTION_CLEANUP_DELAY,
	FR_ACTION_COA_CANCELLED,
} fr_state_action_t;
#define FR_ACTION_MAX (FR_ACTION_COA_CANCELLED + 1)

/*
 *  Function handler for requests.
 */
typedef	int (*RAD_REQUEST_FUNP)(REQUEST *);
typedef	void (*fr_request_process_t)(REQUEST *, int);

extern time_t fr_start_time;

#ifdef HAVE_PTHREAD_H
/*
 *	In threads.c
 */
int request_enqueue(REQUEST *request);
#endif

int request_receive(TALLOC_CTX *ctx, rad_listen_t *listener, RADIUS_PACKET *packet,
		    RADCLIENT *client, RAD_REQUEST_FUNP fun);
void request_inject(REQUEST *request);

bool radius_event_fd_full(void);

#ifdef WITH_PROXY
int request_proxy_reply(rad_listen_t *listener, RADIUS_PACKET *packet);
#endif

#ifdef WITH_TCP
void tcp_socket_freeze(rad_listen_t *listener, fr_event_fd_handler_t write_handler);
void tcp_socket_thaw(rad_listen_t *listener);
#endif

#ifdef __cplusplus
}
#endif

#endif /* FR_PROCESS_H */
