/*
 * mpathsend.c
 *
 * Copyright (C) 2005 Hannes Reinecke <hare@suse.de>
 *
 * based on
 *
 * udevsend.c
 * which carries the following copyright:
 *
 * Copyright (C) 2004 Ling, Xiaofeng <xiaofeng.ling@intel.com>
 * Copyright (C) 2004 Kay Sievers <kay.sievers@vrfy.org>
 *
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 * 
 *	This program is distributed in the hope that it will be useful, but
 *	WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *	General Public License for more details.
 * 
 *	You should have received a copy of the GNU General Public License along
 *	with this program; if not, write to the Free Software Foundation, Inc.,
 *	675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <linux/stddef.h>

#ifndef MPATH_SOCKNAME
#define MPATH_SOCKNAME "/org/kernel/udev/mpathevent"
#endif

size_t strlcpy(char *dst, const char *src, size_t size)
{
	size_t bytes = 0;
	char *q = dst;
	const char *p = src;
	char ch;

	while ((ch = *p++)) {
		if (bytes+1 < size)
			*q++ = ch;
		bytes++;
	}

	/* If size == 0 there is no space for a final null... */
	if (size)
		*q = '\0';

	return bytes;
}

int pass_env_to_socket(int sock, const char *sockname,
		       const char *devpath, const char *action)
{
	struct sockaddr_un saddr;
	socklen_t addrlen;
	char buf[2048];
	size_t bufpos = 0;
	int i;
	ssize_t count;
	int retval = 0;

	memset(&saddr, 0x00, sizeof(struct sockaddr_un));
	saddr.sun_family = AF_LOCAL;
	/* only abstract namespace is supported */
	strcpy(&saddr.sun_path[1], sockname);
	addrlen = offsetof(struct sockaddr_un, sun_path) + strlen(saddr.sun_path+1) + 1;

	bufpos = snprintf(buf, sizeof(buf)-1, "%s@%s", action, devpath);
	bufpos++;
	for (i = 0; environ[i] != NULL && bufpos < sizeof(buf); i++) {
		bufpos += strlcpy(&buf[bufpos], environ[i], sizeof(buf) - bufpos-1);
		bufpos++;
	}

	count = sendto(sock, &buf, bufpos, 0, (struct sockaddr *)&saddr, addrlen);
	if (count < 0)
		retval = -1;

	return retval;
}

int main(int argc, char* argv[])
{
	int sock;
	char *action;
	char *devpath;
	int retval = 1;

	devpath = getenv("DEVPATH");
	if (devpath == NULL) {
#ifdef _DEBUG_
		fprintf(stderr,"no devpath");
#endif
		goto exit;
	}

	action = getenv("ACTION");
	if (action == NULL) {
#ifdef _DEBUG_
		fprintf(stderr,"no action");
#endif
		goto exit;
	}

	sock = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (sock == -1) {
#ifdef _DEBUG_
		fprintf(stderr,"error getting socket: %s\n",strerror(errno));
#endif
		goto exit;
	}

	retval = pass_env_to_socket(sock, MPATH_SOCKNAME, devpath, action);
#ifdef _DEBUG_
	if (retval < 0)
		fprintf(stderr,"failed to send event: %s\n",
			strerror(errno));
#endif
	close(sock);

 exit:
	return (retval < 0)? 1 : 0;
}
