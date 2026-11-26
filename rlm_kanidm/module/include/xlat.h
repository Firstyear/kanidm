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
#ifndef XLAT_H
#define XLAT_H

/**
 * $Id: 535dd81ee4e07a4e0f1e2cfa3f2eb613b17fd38b $
 *
 * @file xlat.h
 * @brief Structures and prototypes for templates
 *
 * @copyright 2015  The FreeRADIUS server project
 */

RCSIDH(xlat_h, "$Id: 535dd81ee4e07a4e0f1e2cfa3f2eb613b17fd38b $")

#ifdef __cplusplus
extern "C" {
#endif

#include <freeradius-devel/conffile.h>

typedef struct xlat_exp xlat_exp_t;

typedef size_t (*xlat_escape_t)(REQUEST *, char *out, size_t outlen, char const *in, void *arg);
typedef ssize_t (*xlat_func_t)(void *instance, REQUEST *, char const *, char *, size_t);

ssize_t radius_xlat(char *out, size_t outlen, REQUEST *request, char const *fmt, xlat_escape_t escape,
		    void *escape_ctx)
	CC_HINT(nonnull (1 ,3 ,4));

ssize_t radius_xlat_struct(char *out, size_t outlen, REQUEST *request, xlat_exp_t const *xlat,
			   xlat_escape_t escape, void *ctx)
	CC_HINT(nonnull (1 ,3 ,4));

ssize_t radius_axlat(char **out, REQUEST *request, char const *fmt, xlat_escape_t escape, void *escape_ctx)
	CC_HINT(nonnull (1, 2, 3));

ssize_t radius_axlat_struct(char **out, REQUEST *request, xlat_exp_t const *xlat, xlat_escape_t escape,
			    void *ctx)
	CC_HINT(nonnull (1, 2, 3));

ssize_t xlat_tokenize(TALLOC_CTX *ctx, char *fmt, xlat_exp_t **head, char const **error);

size_t xlat_sprint(char *buffer, size_t bufsize, xlat_exp_t const *node);

int		xlat_register(char const *module, xlat_func_t func, xlat_escape_t escape,
			      void *instance);
void		xlat_unregister(char const *module, xlat_func_t func, void *instance);
void		xlat_unregister_module(void *instance);
bool		xlat_register_redundant(CONF_SECTION *cs);
ssize_t		xlat_fmt_to_ref(uint8_t const **out, REQUEST *request, char const *fmt);
void		xlat_free(void);

#ifdef __cplusplus
}
#endif
#endif	/* TMPL_H */
