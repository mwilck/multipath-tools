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

#include <stdint.h>
#include <sys/types.h>
#include "generic.h"
#include "dm-generic.h"
#include "structs.h"
#include "structs_vec.h"
#include "config.h"
#include "print.h"

static vector dm_mp_get_pgs(const struct gen_multipath *gmp)
{
	return vector_convert(gen_multipath_to_dm(gmp)->pg,
			      struct pathgroup, dm_pathgroup_to_gen);
}

static vector dm_pg_get_paths(const struct gen_pathgroup *gpg)
{
	return vector_convert(gen_pathgroup_to_dm(gpg)->paths,
			      struct path, dm_path_to_gen);
}

const struct gen_multipath_ops dm_gen_multipath_ops = {
	.get_pathgroups = dm_mp_get_pgs,
	.snprint = snprint_multipath_attr,
};

const struct gen_pathgroup_ops dm_gen_pathgroup_ops = {
	.get_paths = dm_pg_get_paths,
	.snprint = snprint_pathgroup_attr,
};

const struct gen_path_ops dm_gen_path_ops = {
	.snprint = snprint_path_attr,
};
