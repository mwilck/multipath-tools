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
#ifndef _FOREIGN_H
#define _FOREIGN_H
#include <libudev.h>

#define LIBMP_FOREIGN_API ((1 << 8) | 0)

struct context;

/* return codes of functions below returning "int" */
enum foreign_retcode {
	FOREIGN_OK,
	FOREIGN_CLAIMED,
	FOREIGN_IGNORED,
	FOREIGN_UNCLAIMED,
	FOREIGN_NODEV,
	FOREIGN_ERR,
	__LAST_FOREIGN_RETCODE,
};

struct foreign {
	/*
	 * method: init
	 *
	 * Initialize foreign library, and check API compatibility
	 * return pointer to opaque internal data strucure if successful,
	 * NULL otherwise.
	 */
	struct context* (*init)(unsigned int api);

	/*
	 * method: cleanup
	 *
	 * Free data structures used by foreign library, including
	 * context itself.
	 */
	void (*cleanup)(struct context *);

	/*
	 * method: add
	 *
	 * This is called during path detection, and for udev ADD events.
	 *
	 * Return values:
	 * FOREIGN_CLAIMED: device newly claimed
	 * FOREIGN_OK: already registered
	 * FOREIGN_IGNORED: not registered, still wants to ignore
	 * FOREIGN_ERR: error processing device (will be treated like
	 * FOREIGN_IGNORED)
	 */
	int (*add)(struct context *, struct udev_device *);

	/*
	 * method: change
	 *
	 * This is called on udev CHANGE events.
	 *
	 * Return values:
	 *
	 * FOREIGN_OK: event processed
	 * FOREIGN_IGNORED: the device is ignored
	 * FOREIGN_CLAIMED: previously not registered or claimed device is now
	 * claimed. Unlike "add()", this should not change internal state
	 * immediately, because multipathd may need to try to release the device
	 * and may fail doing so. If it succeeds, it will call add() afterwards.
	 * FOREIGN_UNCLAIMED: previously claimed device is now ignored, and
	 * internally released.
	 * FOREIGN_ERR: error processing device (will be treated like
	 * FOREIGN_IGNORED).
	 */
	int (*change)(struct context *, struct udev_device *);

	/*
	 * method: remove
	 *
	 * This is called on udev REMOVE events.
	 *
	 * Return values:
	 * FOREIGN_OK: processed correctly
	 * FOREIGN_IGNORED: device wasn't registered internally
	 * FOREIGN_ERR: error occured (will be treated like
	 * FOREIGN_IGNORED).
	 */
	int (*remove)(struct context *, struct udev_device *);

	/*
	 * method: check
	 *
	 * This is called from multipathd's checker loop.
	 *
	 * Check status of managed devices, update internal status, and print
	 * log messages if appropriate.
	 */
	void (*check)(struct context *);

	/*
	 * method: get_multipaths
	 *
	 * return a vector of "struct gen_multipath*" with the map devices
	 * belonging to this library, or NULL if there are none or an error
	 * occurs.
	 */
	vector (*get_multipaths)(const struct context *);

	/*
	 * method: get_paths
	 *
	 * return a vector of "struct gen_path*" with the path devices
	 * belonging to this library, or NULL if there are none or an error
	 * occurs.
	 */
	vector (*get_paths)(const struct context *);
	const char *name;
	void *handle;
	struct context *context;
};

int init_foreign(const char *multipath_dir);
void cleanup_foreign(void);
int add_foreign(struct udev_device *);
int change_foreign(struct udev_device *);
int remove_foreign(struct udev_device *);
void check_foreign(void);
vector get_foreign_multipaths(void);
vector get_foreign_paths(void);

#endif /*  _FOREIGN_H */
