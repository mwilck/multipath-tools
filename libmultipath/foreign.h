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
#include <stdbool.h>
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
	 *
	 * arg "name" denotes the name by which the library is known.
	 */
	struct context* (*init)(unsigned int api, const char *name);

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
	 * FOREIGN_UNCLAIMED: previously claimed device is now ignored. The
	 * internal state is not updated yet, multipathd will call delete()
	 * after handling this return value successfully.
	 * FOREIGN_ERR: error processing device (will be treated like
	 * FOREIGN_IGNORED).
	 */
	int (*change)(struct context *, struct udev_device *);

	/*
	 * method: delete
	 *
	 * This is called on udev DELETE events.
	 *
	 * Return values:
	 * FOREIGN_OK: processed correctly (device deleted)
	 * FOREIGN_IGNORED: device wasn't registered internally
	 * FOREIGN_ERR: error occured (will be treated like
	 * FOREIGN_IGNORED).
	 */
	int (*delete)(struct context *, struct udev_device *);

	/*
	 * method: delete_all
	 *
	 * This is called if multipathd reconfigures itself.
	 * Delete all registered devices.
	 *
	 * Return values:
	 * FOREIGN_OK: processed correctly
	 * FOREIGN_IGNORED: foreign had nothing to delete
	 * FOREIGN_ERR: error occured
	 */
	int (*delete_all)(struct context*);

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
	const struct _vector* (*get_multipaths)(const struct context *);

	/*
	 * method: get_paths
	 *
	 * return a vector of "struct gen_path*" with the path devices
	 * belonging to this library, or NULL if there are none or an error
	 * occurs.
	void (*release_multipaths)(const struct context *ctx,
				   const struct _vector* mpvec);
	 */
	const struct _vector* (*get_paths)(const struct context *);
	void (*release_paths)(const struct context *ctx,
			      const struct _vector* ppvec);

	const char *name;
	void *handle;
	struct context *context;
};

int init_foreign(const char *multipath_dir);
void cleanup_foreign(void);
int add_foreign(struct udev_device *);
int change_foreign(struct udev_device *);
int delete_foreign(struct udev_device *);
int delete_all_foreign(void);
void check_foreign(void);

/**
 * foreign_path_layout()
 * call this before printing paths, after get_path_layout(), to determine
 * output field width.
 */
void foreign_path_layout(void);

/**
 * foreign_multipath_layout()
 * call this before printing maps, after get_multipath_layout(), to determine
 * output field width.
 */
void foreign_multipath_layout(void);

/**
 * snprint_foreign_topology(buf, len, verbosity);
 * prints topology information from foreign libraries into buffer,
 * '\0' - terminated.
 * @param buf: output buffer
 * @param len: size of output buffer
 * @param verbosity: verbosity level
 * @returns: number of printed characters excluding trailing '\0'.
 */
int snprint_foreign_topology(char *buf, int len, int verbosity);

/**
 * snprint_foreign_paths(buf, len, style, pad);
 * prints formatted path information from foreign libraries into buffer,
 * '\0' - terminated.
 * @param buf: output buffer
 * @param len: size of output buffer
 * @param style: format string
 * @param pad: whether to pad field width
 * @returns: number of printed characters excluding trailing '\0'.
 */
int snprint_foreign_paths(char *buf, int len, const char *style, int pad);

/**
 * snprint_foreign_multipaths(buf, len, style, pad);
 * prints formatted map information from foreign libraries into buffer,
 * '\0' - terminated.
 * @param buf: output buffer
 * @param len: size of output buffer
 * @param style: format string
 * @param pad: whether to pad field width
 * @returns: number of printed characters excluding trailing '\0'.
 */
int snprint_foreign_multipaths(char *buf, int len,
			       const char *style, int pretty);

/**
 * print_foreign_topology(v)
 * print foreign topology to stdout
 * @param verbosity: verbosity level
 */
void print_foreign_topology(int verbosity);

/**
 * is_claimed_by_foreign(ud)
 * @param udev: udev device
 * @returns: true iff device is (newly or already) claimed by a foreign lib
 */
static inline bool
is_claimed_by_foreign(struct udev_device *ud)
{
	int rc = add_foreign(ud);

	return (rc == FOREIGN_CLAIMED || rc == FOREIGN_OK);
}

#endif /*  _FOREIGN_H */
