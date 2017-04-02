/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_webirc.c: Makes CGI:IRC users appear as coming from their real host
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2006 ircd-ratbox development team
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 *
 *  $Id: m_webirc.c 3458 2007-05-18 19:51:22Z jilles $
 */
/* Usage:
 * auth {
 *   user = "webirc@<cgiirc ip>"; # if identd used, put ident username instead
 *   password = "<password>"; # encryption possible
 *   spoof = "webirc."
 *   class = "users";
 * };
 * Possible flags:
 *   encrypted - password is encrypted (recommended)
 *   kline_exempt - klines on the cgiirc ip are ignored
 * dlines are checked on the cgiirc ip (of course).
 * k/d/x lines, auth blocks, user limits, etc are checked using the
 * real host/ip.
 * The password should be specified unencrypted in webirc_password in
 * cgiirc.config
 *
 * Usage for WEBIRC v2:
 * auth {
 *   user = "<service|*>@<certfp>"; # service should be e.g. 'kiwiirc'
 *   flags = ~encrypted;
 *   password = "*";
 *   spoof = "webirc.";
 *   class = "users";
 * };
 * certfp is required for WEBIRC v2 authentication. This is a quick hack to
 * implement a reference implementation of WEBIRC v2; future implementations
 * will likely add a fingerprint= to auth{} blocks to restrict them to clients
 * with the specified certificate fingerprint, webirc or otherwise.
 * See also "Changes for WEBIRC v2" below.
 */

#include "stdinc.h"
#include "client.h"		/* client struct */
#include "match.h"
#include "hostmask.h"
#include "send.h"		/* sendto_one */
#include "numeric.h"		/* ERR_xxx */
#include "ircd.h"		/* me */
#include "msg.h"
#include "parse.h"
#include "modules.h"
#include "s_serv.h"
#include "hash.h"
#include "s_conf.h"
#include "reject.h"

static int mr_webirc(struct Client *, struct Client *, int, const char **);

struct Message webirc_msgtab = {
	"WEBIRC", 0, 0, 0, MFLG_SLOW | MFLG_UNREG,
	{{mr_webirc, 5}, mg_reg, mg_ignore, mg_ignore, mg_ignore, mg_reg}
};

mapi_clist_av1 webirc_clist[] = { &webirc_msgtab, NULL };
DECLARE_MODULE_AV1(webirc, NULL, NULL, webirc_clist, NULL, NULL, "$Revision: 20702 $");

/*
 * mr_webirc - webirc message handler
 *      parv[1] = password
 *      parv[2] = gateway service name (e.g. mibbit or kiwiirc)
 *	parv[3] = fake hostname
 *	parv[4] = fake ip
 *
 * Changes for WEBIRC v2:
 *  - All errors are fatal and will result in the client being disconnected.
 *  - All WEBIRC errors start with "ERROR :WEBIRC".
 *  - Password "*" is used to specify that the WEBIRC client wishes to
 *    authenticate via certfp.
 *  - Gateway service name is now used as the username to search for ilines.
 *  - Failing to find a WEBIRC block after receiving a WEBIRC message is a
 *    fatal error.
 */
static int
mr_webirc(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct ConfItem *aconf = NULL;
	const char *encr;
	struct rb_sockaddr_storage addr;
	const char *passwd = parv[1];
	const char *svc_name = parv[2];

	if ((!strchr(parv[4], '.') && !strchr(parv[4], ':')) ||
			strlen(parv[4]) + (*parv[4] == ':') >=
			sizeof(source_p->sockhost))
	{
		sendto_one(source_p, "ERROR :WEBIRC invalid IP");
		exit_client(client_p, client_p, client_p, "WEBIRC invalid IP");
		return 0;
	}

	if (strcmp(passwd, "*") == 0) {
		if (client_p->certfp) {
			aconf = find_address_conf(client_p->certfp, NULL,
					svc_name, svc_name,
					(struct sockaddr *) &client_p->localClient->ip,
					client_p->localClient->ip.ss_family, NULL);
			if (strcasecmp(aconf->host, client_p->certfp) != 0) {
				sendto_realops_snomask(SNO_DEBUG, L_ALL,
					"certfp mismatch for WEBIRC client %s: %s != %s",
					svc_name, client_p->certfp, aconf->host);
				aconf = NULL;
			}
		} else {
			sendto_one(source_p, "ERROR :WEBIRC fingerprint authentication "
				   "requires a TLS client certificate and TLS connection");
			exit_client(client_p, client_p, client_p, "WEBIRC no certfp");
			return 0;
		}
	} else {
		aconf = find_address_conf(client_p->host, client_p->sockhost,
					IsGotId(client_p) ? client_p->username : "webirc",
					IsGotId(client_p) ? client_p->username : "webirc",
					(struct sockaddr *) &client_p->localClient->ip,
					client_p->localClient->ip.ss_family, NULL);
	}
	if (aconf == NULL || !(aconf->status & CONF_CLIENT) ||
		!IsConfDoSpoofIp(aconf) || irccmp(aconf->info.name, "webirc."))
	{
		/* XXX */
		sendto_one(source_p, "ERROR :WEBIRC failed to locate a matching "
			"WEBIRC configuration");
		exit_client(client_p, client_p, client_p, "WEBIRC not configured");
		return 0;
	}
	if (EmptyString(aconf->passwd))
	{
		sendto_one(source_p, "ERROR :WEBIRC configuration is invalid");
		exit_client(client_p, client_p, client_p,
			"WEBIRC invalid configuration");
		return 0;
	}

	if (EmptyString(parv[1]))
		encr = "";
	else if (IsConfEncrypted(aconf))
		encr = rb_crypt(parv[1], aconf->passwd);
	else
		encr = parv[1];

	if (encr == NULL || strcmp(encr, aconf->passwd))
	{
		sendto_one(source_p, "ERROR :WEBIRC password incorrect");
		exit_client(client_p, client_p, client_p, "WEBIRC bad password");
		return 0;
	}

	if (rb_inet_pton_sock(parv[4], (struct sockaddr *)&addr) <= 0)
	{
		sendto_one(source_p, "ERROR :WEBIRC invalid IP");
		exit_client(client_p, client_p, client_p, "WEBIRC invalid IP");
		return 0;
	}

	if (*parv[4] == ':')
	{
		source_p->sockhost[0] = '0';
		rb_strlcpy(source_p->sockhost + 1, parv[4],
				sizeof(source_p->sockhost) - 1);
	}
	else
		rb_strlcpy(source_p->sockhost, parv[4],
				sizeof(source_p->sockhost));

	if(strlen(parv[3]) <= HOSTLEN)
		rb_strlcpy(source_p->host, parv[3], sizeof(source_p->host));
	else
		rb_strlcpy(source_p->host, source_p->sockhost, sizeof(source_p->host));

	source_p->localClient->ip = addr;

	/* Check dlines now, klines will be checked on registration */
	if((aconf = find_dline((struct sockaddr *)&source_p->localClient->ip,
			       source_p->localClient->ip.ss_family)))
	{
		if(!(aconf->status & CONF_EXEMPTDLINE))
		{
			exit_client(client_p, source_p, &me, "D-lined");
			return 0;
		}
	}

	sendto_one(source_p, "NOTICE * :WEBIRC setting host and IP to %s %s", parv[3], parv[4]);
	return 0;
}
