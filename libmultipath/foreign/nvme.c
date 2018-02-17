/*
  Copyright (c) 2018 Martin Wilck, SUSE Linux GmbH

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
  USA.
*/

#include <stdlib.h>
#include <libudev.h>
#include <pthread.h>
#include "vector.h"
#include "generic.h"
#include "foreign.h"
#include "lock.h"
#include "debug.h"

const char THIS[] = "nvme";

struct context {
	pthread_mutex_t mutex;
	vector mpvec;
};

void cleanup(struct context *ctx)
{
	if (ctx == NULL)
		return;

	if (ctx->mpvec != NULL)
		vector_free(ctx->mpvec);
	pthread_mutex_destroy(&ctx->mutex);
	free(ctx);
}

struct context *init(unsigned int api)
{
	struct context *ctx;

	if (api > LIBMP_FOREIGN_API) {
		condlog(0, "%s: api version mismatch: %08x > %08x\n",
			__func__, api, LIBMP_FOREIGN_API);
		return NULL;
	}

	if ((ctx = calloc(1, sizeof(*ctx)))== NULL)
		return NULL;

	pthread_mutex_init(&ctx->mutex, NULL);

	ctx->mpvec = vector_alloc();
	if (ctx->mpvec == NULL)
		goto err;

	return ctx;
err:
	cleanup(ctx);
	return NULL;
}

int add(struct context *ctx, struct udev_device *ud)
{
	condlog(4, "%s called for \"%s\"", __func__, THIS);
	return FOREIGN_IGNORED;
}

int change(struct context *ctx, struct udev_device *ud)
{
	condlog(4, "%s called for \"%s\"", __func__, THIS);
	return FOREIGN_NODEV;
}

int remove(struct context *ctx, struct udev_device *ud)
{
	condlog(4, "%s called for \"%s\"", __func__, THIS);
	return FOREIGN_NODEV;
}

void check(struct context *ctx)
{
	condlog(4, "%s called for \"%s\"", __func__, THIS);
	return;
}

vector* get_multipaths(const struct context *ctx)
{
	condlog(4, "%s called for \"%s\"", __func__, THIS);
	return NULL;
}

vector* get_paths(const struct context *ctx)
{
	condlog(4, "%s called for \"%s\"", __func__, THIS);
	return NULL;
}
