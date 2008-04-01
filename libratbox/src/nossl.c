/* 
 *  libratbox: a library used by ircd-ratbox and other things
 *  nossl.c: ssl stub code
 *
 *  Copyright (C) 2007-2008 ircd-ratbox development team
 *  Copyright (C) 2007-2008 Aaron Sethman <androsyn@ratbox.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *    
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
 *  USA
 * 
 *  $Id: commio.c 24808 2008-01-02 08:17:05Z androsyn $
 */


#include <libratbox_config.h>
#include <ratbox_lib.h>

#ifndef HAVE_OPENSSL

#include <commio-int.h>
#include <commio-ssl.h>

int 
rb_setup_ssl_server(const char *cert, const char *keyfile, const char *dhfile)
{
	errno = ENOSYS;
	return 0;
}

int
rb_init_ssl(void)
{
	errno = ENOSYS;
	return -1;

}

int
rb_ssl_listen(rb_fde_t *F, int backlog)
{
	errno = ENOSYS;
	return -1;
}

int rb_init_prng(const char *path, prng_seed_t seed_type)
{
	return -1;
}

int
rb_get_random(void *buf, size_t length)
{
	return -1;
}

const char *
rb_get_ssl_strerror(rb_fde_t *F)
{
	static const char *nosupport = "SSL/TLS not supported";
	return nosupport;
}

void 
rb_ssl_start_accepted(rb_fde_t *new_F, ACCB *cb, void *data, int timeout)
{
	return;
}

void 
rb_ssl_start_connected(rb_fde_t *F, CNCB *callback, void *data, int timeout)
{
	return;
}

void
rb_connect_tcp_ssl(rb_fde_t *F, struct sockaddr *dest, 
                     struct sockaddr *clocal, int socklen, CNCB *callback, void *data, int timeout)
{
	return;
}

int
rb_supports_ssl(void)
{
	return 0;
}

void
rb_ssl_shutdown(rb_fde_t * F)
{  
	return;
}        
#endif /* !HAVE_OPENSSL */
