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
#ifndef _GENERIC_H
#define _GENERIC_H
#include "vector.h"

struct gen_multipath;
struct gen_pathgroup;
struct gen_path;

struct gen_multipath_ops {
	/*
	 * return a newly allocated vector of const struct gen_pathgroup*
	 * caller is responsible to free it (don't try to free members!)
	 */
	vector (*get_pathgroups)(const struct gen_multipath*);
	/*
	 * print the property of the multipath map matching
	 * the passed-in wildcard character into "buf", 0-terminated,
	 * no more than "len" characters including trailing '\0',
	 * returning the number of characters printed (without trailing '\0').
	 * If this wildcard is unsupported, prints nothing and returns 0.
	 */
	int (*snprint)(const struct gen_multipath*,
		       char *buf, int len, char wildcard);
	/*
	 * print special format for multipath printout into buf.
	 */
	int (*style)(const struct gen_multipath*,
		     char *buf, int len, int verbosity);
};

struct gen_pathgroup_ops {
	/*
	 * return a vector of const struct gen_path*
	 * caller is responsible to free it (don't try to free members!)
	 */
	vector (*get_paths)(const struct gen_pathgroup*);
	/* see above */
	int (*snprint)(const struct gen_pathgroup*,
		       char *buf, int len, char wildcard);
};

struct gen_path_ops {
	/* see above */
	int (*snprint)(const struct gen_path*,
		       char *buf, int len, char wildcard);
};

struct gen_multipath {
	const struct gen_multipath_ops *ops;
};

struct gen_pathgroup {
	const struct gen_pathgroup_ops *ops;
};

struct gen_path {
	const struct gen_path_ops *ops;
};

#endif /* _GENERIC_H */
