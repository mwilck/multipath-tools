/*
 * dm-deps: udev helper utility to obtain number of dependencies
 * Copyright (c) 2017 SUSE Linux GmbH, Nuernberg, Germany
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#include <stdio.h>
#include <libdevmapper.h>

static int dm_get_dep_count(int major, int minor)
{
	struct dm_task *dmt;
	struct dm_deps *dm_deps;
	int ret = -1;

	if ((dmt = dm_task_create(DM_DEVICE_DEPS)) == NULL)
		return -1;

	if (!dm_task_set_major(dmt, major) ||
	    !dm_task_set_minor(dmt, minor) ||
	    !dm_task_no_open_count(dmt) ||
	    !dm_task_run(dmt))
		goto out;

	dm_deps = dm_task_get_deps(dmt);
	if (dm_deps != NULL)
		ret = dm_deps->count;

out:
	dm_task_destroy(dmt);
	return ret;
}

static int usage(const char *exe)
{
	fprintf(stderr, "usage: %s <major> <minor>\n", exe);
	return 1;
}

int main(int argc, const char * const argv[])
{
	char *endp;
	int major, minor, count;

	if (argc != 3 || *argv[1] == '\0' || *argv[2] == '\0')
		return usage(argv[0]);

	major = strtoul(argv[1], &endp, 0);
	if (*endp != '\0')
		return usage(argv[0]);

	minor = strtoul(argv[2], &endp, 0);
	if (*endp != '\0')
		return usage(argv[0]);

	count = dm_get_dep_count(major, minor);
	if (count == -1) {
		fprintf(stderr, "%s: error in libdevmapper\n", argv[0]);
		return 2;
	}

	printf("DM_DEPS='%d'\n", count);
	return 0;
}
