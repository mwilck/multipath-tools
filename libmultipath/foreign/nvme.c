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

#include <sys/sysmacros.h>
#include <stdio.h>
#include <stdlib.h>
#include <libudev.h>
#include <pthread.h>
#include "vector.h"
#include "generic.h"
#include "foreign.h"
#include "lock.h"
#include "debug.h"

const char *THIS;

struct nvme_map {
	struct gen_multipath gen;
	const char *wwid;
	const char *model;
	const char *firmware_rev;
	const char *serial;
	const char *subsysnqn;
	dev_t devt;
};

#define const_gen_mp_to_nvme(g) ((const struct nvme_map*)(g))
#define gen_mp_to_nvme(g) ((struct nvme_map*)(g))
#define nvme_mp_to_gen(n) &((n)->gen)

struct context {
	pthread_mutex_t mutex;
	vector mpvec;
};

static const struct _vector*
nvme_mp_get_pgs(const struct gen_multipath *gmp) {
	return NULL;
}

static int snprint_nvme_map(const struct gen_multipath *gmp,
			    char *buff, int len, char wildcard)
{
	const struct nvme_map *nvm = const_gen_mp_to_nvme(gmp);

	switch (wildcard) {
	case 'n':
		return snprintf(buff, len, "(%d:%d)",
				major(nvm->devt), minor(nvm->devt));
	case 'R':
		return snprintf(buff, len, "[foreign: %s]", THIS);
	default:
		break;
	}
	return 0;
}

static const struct _vector*
nvme_pg_get_paths(const struct gen_pathgroup *gpg) {
	return NULL;
}

static int snprint_nvme_pg(const struct gen_pathgroup *gmp,
			   char *buff, int len, char wildcard)
{
	return 0;
}

static int snprint_nvme_path(const struct gen_path *gmp,
			     char *buff, int len, char wildcard)
{
	switch (wildcard) {
	case 'R':
		return snprintf(buff, len, "[foreign: %s]", THIS);
	default:
		break;
	}
	return 0;
}

static const struct gen_multipath_ops nvme_map_ops = {
	.get_pathgroups = nvme_mp_get_pgs,
	.style = generic_style,
	.snprint = snprint_nvme_map,
};

static const struct gen_pathgroup_ops nvme_pg_ops __attribute__((unused)) = {
	.get_paths = nvme_pg_get_paths,
	.snprint = snprint_nvme_pg,
};

static const struct gen_path_ops nvme_path_ops __attribute__((unused)) = {
	.snprint = snprint_nvme_path,
};

int delete_all(struct context *ctx)
{
	condlog(4, "%s called for \"%s\"", __func__, THIS);
	return FOREIGN_IGNORED;
}

void cleanup(struct context *ctx)
{
	if (ctx == NULL)
		return;

	(void)delete_all(ctx);
	if (ctx->mpvec != NULL)
		vector_free(ctx->mpvec);
	pthread_mutex_destroy(&ctx->mutex);
	free(ctx);
}

struct context *init(unsigned int api, const char *name)
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

	THIS = name;
	return ctx;
err:
	cleanup(ctx);
	return NULL;
}

static struct nvme_map *find_nvme_map_by_devt(const struct context *ctx,
					      dev_t devt)
{
	struct nvme_map *nm;
	int i;

	if (ctx->mpvec == NULL)
		return NULL;

	vector_foreach_slot(ctx->mpvec, nm, i) {
		if (nm->devt == devt)
			return nm;
	}

	return NULL;
}

int add(struct context *ctx, struct udev_device *ud)
{
	struct udev_device *subsys;
	struct nvme_map *map;
	dev_t devt;

	condlog(4, "%s called for \"%s\"", __func__, THIS);

	if (ud == NULL)
		return FOREIGN_ERR;

	subsys = udev_device_get_parent_with_subsystem_devtype(ud,
							       "nvme-subsystem",
							       NULL);
	if (subsys == NULL)
		return FOREIGN_IGNORED;

	devt = udev_device_get_devnum(ud);
	if (find_nvme_map_by_devt(ctx, devt) != NULL)
		return FOREIGN_OK;

	map = calloc(1, sizeof(*map));
	if (map == NULL)
		return FOREIGN_ERR;

	map->devt = devt;
	map->gen.ops = &nvme_map_ops;

	return FOREIGN_CLAIMED;
}

int change(struct context *ctx, struct udev_device *ud)
{
	condlog(4, "%s called for \"%s\"", __func__, THIS);
	return FOREIGN_IGNORED;
}

int delete(struct context *ctx, struct udev_device *ud)
{
	condlog(4, "%s called for \"%s\"", __func__, THIS);
	return FOREIGN_IGNORED;
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
