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
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <glob.h>
#include <dlfcn.h>
#include <libudev.h>
#include "vector.h"
#include "debug.h"
#include "util.h"
#include "foreign.h"

static vector foreigns;

#define get_dlsym(foreign, sym, lbl)					\
	do {								\
		foreign->sym =	dlsym(foreign->handle, #sym);		\
		if (foreign->sym == NULL) {				\
			condlog(0, "%s: symbol \"%s\" not found in \"%s\"", \
				__func__, #sym, foreign->name);		\
			goto lbl;					\
		}							\
	} while(0)

static void free_foreign(struct foreign **fgn)
{
	if (fgn == NULL || *fgn == NULL)
		return;
	condlog(4, "%s: freeing \"%s\"", __func__, (*fgn)->name);
	if ((*fgn)->context != NULL)
		(*fgn)->cleanup((*fgn)->context);
	if ((*fgn)->handle != NULL)
		dlclose((*fgn)->handle);
	free(*fgn);
}

void cleanup_foreign(void)
{
	struct foreign *fgn;
	int i;

	vector_foreach_slot(foreigns, fgn, i)
		free_foreign(&fgn);
	vector_free(foreigns);
	foreigns = NULL;
}

int init_foreign(const char *multipath_dir)
{
	char pathbuf[PATH_MAX];
	static const char base[] = "libforeign-";
	static const char suffix[] = ".so";
	glob_t globbuf;
	int ret = -EINVAL, r, i;

	if (foreigns != NULL) {
		condlog(0, "%s: already initialized", __func__);
		return -EEXIST;
	}
	foreigns = vector_alloc();

	if (snprintf(pathbuf, sizeof(pathbuf), "%s/%s*%s",
		     multipath_dir, base, suffix) >= sizeof(pathbuf)) {
		condlog(1, "%s: path length overflow", __func__);
		goto err;
	}

	condlog(4, "%s: looking for %s\n", __func__, pathbuf);
	memset(&globbuf, 0, sizeof(globbuf));
	r = glob(pathbuf, 0, NULL, &globbuf);

	if (r == GLOB_NOMATCH) {
		condlog(2, "%s: no foreign multipath libraries found",
			__func__);
		globfree(&globbuf);
		return 0;
	} else if (r != 0) {
		char *msg;

		if (errno != 0) {
			ret = -errno;
			msg = strerror(errno);
		} else {
			ret = -1;
			msg = (r == GLOB_ABORTED ? "read error" :
			       "out of memory");
		}
		condlog(0, "%s: search for foreign libraries failed: %d (%s)",
			__func__, r, msg);
		globfree(&globbuf);
		goto err;
	}

	for (i = 0; i < globbuf.gl_pathc; i++) {
		char *msg, *fn;
		struct foreign *fgn;
		int len, namesz;

		fn = strrchr(globbuf.gl_pathv[i], '/');
		if (fn == NULL)
			fn = globbuf.gl_pathv[i];
		else
			fn++;

		len = strlen(fn);
		if (len <= sizeof(base) + sizeof(suffix) - 2) {
			condlog(0, "%s: internal error: filename too short: %s",
				__func__, globbuf.gl_pathv[i]);
			continue;
		}

		condlog(4, "%s: found %s", __func__, fn);

		namesz = len + 3 - sizeof(base) - sizeof(suffix);
		fgn = malloc(sizeof(*fgn) + namesz);
		if (fgn == NULL)
			continue;
		memset(fgn, 0, sizeof(*fgn));

		strlcpy((char*)fgn + sizeof(*fgn), fn + sizeof(base) - 1,
			namesz);
		fgn->name = (const char*)fgn + sizeof(*fgn);

		fgn->handle = dlopen(globbuf.gl_pathv[i], RTLD_NOW|RTLD_LOCAL);
		msg = dlerror();
		if (fgn->handle == NULL) {
			condlog(1, "%s: failed to open %s: %s", __func__,
				fn, msg);
			free_foreign(&fgn);
			continue;
		}

		get_dlsym(fgn, init, dl_err);
		get_dlsym(fgn, cleanup, dl_err);
		get_dlsym(fgn, add, dl_err);
		get_dlsym(fgn, change, dl_err);
		get_dlsym(fgn, remove, dl_err);
		get_dlsym(fgn, remove_all, dl_err);
		get_dlsym(fgn, check, dl_err);
		get_dlsym(fgn, get_multipaths, dl_err);
		get_dlsym(fgn, get_paths, dl_err);

		fgn->context = fgn->init(LIBMP_FOREIGN_API);
		if (fgn->context == NULL) {
			condlog(0, "%s: init() failed for %s", __func__, fn);
			free_foreign(&fgn);
			continue;
		}

		if (vector_alloc_slot(foreigns) == NULL) {
			free_foreign(&fgn);
			continue;
		}
		vector_set_slot(foreigns, fgn);
		condlog(2, "foreign library \"%s\" loaded successfully", fgn->name);

		continue;

	dl_err:
		free_foreign(&fgn);
	}
	globfree(&globbuf);

	return 0;
err:
	cleanup_foreign();
	return ret;
}

int add_foreign(struct udev_device *udev)
{
	struct foreign *fgn;
	dev_t dt;
	int j;

	if (udev == NULL) {
		condlog(1, "%s called with NULL udev", __func__);
		return FOREIGN_ERR;
	}
	dt = udev_device_get_devnum(udev);
	vector_foreach_slot(foreigns, fgn, j) {
		int r = fgn->add(fgn->context, udev);

		if (r == FOREIGN_CLAIMED) {
			condlog(2, "%s: foreign \"%s\" claims device %d:%d",
				__func__, fgn->name, major(dt), minor(dt));
			return r;
		} else if (r == FOREIGN_OK) {
			condlog(4, "%s: foreign \"%s\" owns device %d:%d",
				__func__, fgn->name, major(dt), minor(dt));
			return r;
		} else if (r != FOREIGN_IGNORED) {
			condlog(1, "%s: unexpected return value %d from \"%s\"",
				__func__, r, fgn->name);
		}
	}
	return FOREIGN_IGNORED;
}

int change_foreign(struct udev_device *udev)
{
	struct foreign *fgn;
	int j;
	dev_t dt;

	if (udev == NULL) {
		condlog(1, "%s called with NULL udev", __func__);
		return FOREIGN_ERR;
	}
	dt = udev_device_get_devnum(udev);
	vector_foreach_slot(foreigns, fgn, j) {
		int r = fgn->change(fgn->context, udev);

		if (r == FOREIGN_CLAIMED) {
			condlog(2, "%s: foreign \"%s\" claims device %d:%d",
				__func__, fgn->name, major(dt), minor(dt));
			return r;
		} else if (r == FOREIGN_UNCLAIMED) {
			condlog(2, "%s: foreign \"%s\" released device %d:%d",
				__func__, fgn->name, major(dt), minor(dt));
			return r;
		} else if (r == FOREIGN_OK) {
			condlog(4, "%s: foreign \"%s\" completed %d:%d",
				__func__, fgn->name, major(dt), minor(dt));
			return r;
		} else if (r != FOREIGN_IGNORED) {
			condlog(1, "%s: unexpected return value %d from \"%s\"",
				__func__, r, fgn->name);
		}
	}
	return FOREIGN_IGNORED;
}

int remove_foreign(struct udev_device *udev)
{
	struct foreign *fgn;
	int j;
	dev_t dt;

	if (udev == NULL) {
		condlog(1, "%s called with NULL udev", __func__);
		return FOREIGN_ERR;
	}
	dt = udev_device_get_devnum(udev);
	vector_foreach_slot(foreigns, fgn, j) {
		int r = fgn->remove(fgn->context, udev);

		if (r == FOREIGN_OK) {
			condlog(2, "%s: foreign \"%s\" removed device %d:%d",
				__func__, fgn->name, major(dt), minor(dt));
			return r;
		} else if (r != FOREIGN_IGNORED) {
			condlog(1, "%s: unexpected return value %d from \"%s\"",
				__func__, r, fgn->name);
		}
	}
	return FOREIGN_IGNORED;
}

int remove_all_foreign(void)
{
	struct foreign *fgn;
	int j;

	vector_foreach_slot(foreigns, fgn, j) {
		int r;

		r = fgn->remove_all(fgn->context);
		if (r != FOREIGN_IGNORED && r != FOREIGN_OK) {
			condlog(1, "%s: unexpected return value %d from \"%s\"",
				__func__, r, fgn->name);
		}
	}
	return FOREIGN_OK;
}

void check_foreign(void)
{
	struct foreign *fgn;
	int j;

	vector_foreach_slot(foreigns, fgn, j) {
		fgn->check(fgn->context);
	}
}

vector get_foreign_multipaths(void)
{
	vector all = NULL;
	struct foreign *fgn;
	int j;

	vector_foreach_slot(foreigns, fgn, j) {
		vector v = fgn->get_multipaths(fgn->context);

		if (v == NULL)
			continue;
		vector_convert(all, v, struct gen_multipath, identity);
		vector_free(v);
	}
	return all;
}

vector get_foreign_paths(void)
{
	vector all = NULL;
	struct foreign *fgn;
	int j;

	vector_foreach_slot(foreigns, fgn, j) {
		vector v = fgn->get_paths(fgn->context);

		if (v == NULL)
			continue;
		vector_convert(all, v, struct gen_multipath, identity);
		vector_free(v);
	}
	return all;
}
