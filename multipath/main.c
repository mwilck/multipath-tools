/*
 * Soft:        multipath device mapper target autoconfig
 *
 * Version:     $Id: main.h,v 0.0.1 2003/09/18 15:13:38 cvaroqui Exp $
 *
 * Author:      Christophe Varoqui
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *              See the GNU General Public License for more details.
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Copyright (c) 2003, 2004, 2005 Christophe Varoqui
 * Copyright (c) 2005 Benjamin Marzinski, Redhat
 * Copyright (c) 2005 Kiyoshi Ueda, NEC
 * Copyright (c) 2005 Patrick Caulfield, Redhat
 * Copyright (c) 2005 Edward Goggin, EMC
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <libudev.h>
#include <syslog.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <stdlib.h>

#include <checkers.h>
#include <prio.h>
#include <vector.h>
#include <memory.h>
#include <libdevmapper.h>
#include <devmapper.h>
#include <util.h>
#include <defaults.h>
#include <structs.h>
#include <structs_vec.h>
#include <dmparser.h>
#include <sysfs.h>
#include <config.h>
#include <blacklist.h>
#include <discovery.h>
#include <debug.h>
#include <switchgroup.h>
#include <print.h>
#include <alias.h>
#include <configure.h>
#include <pgpolicies.h>
#include <version.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <wwids.h>
#include <uxsock.h>

int logsink;

static int
filter_pathvec (vector pathvec, char * refwwid)
{
	int i;
	struct path * pp;

	if (!refwwid || !strlen(refwwid))
		return 0;

	vector_foreach_slot (pathvec, pp, i) {
		if (strncmp(pp->wwid, refwwid, WWID_SIZE) != 0) {
			condlog(3, "skip path %s : out of scope", pp->dev);
			free_path(pp);
			vector_del_slot(pathvec, i);
			i--;
		}
	}
	return 0;
}

static void
usage (char * progname)
{
	fprintf (stderr, VERSION_STRING);
	fprintf (stderr, "Usage:\n");
	fprintf (stderr, "  %s [-a|-c|-w|-W] [-d] [-r] [-i] [-v lvl] [-p pol] [-b fil] [-q] [dev]\n", progname);
	fprintf (stderr, "  %s -l|-ll|-f [-v lvl] [-b fil] [dev]\n", progname);
	fprintf (stderr, "  %s -F [-v lvl]\n", progname);
	fprintf (stderr, "  %s -t\n", progname);
	fprintf (stderr, "  %s -h\n", progname);
	fprintf (stderr,
		"\n"
		"Where:\n"
		"  -h      print this usage text\n" \
		"  -l      show multipath topology (sysfs and DM info)\n" \
		"  -ll     show multipath topology (maximum info)\n" \
		"  -f      flush a multipath device map\n" \
		"  -F      flush all multipath device maps\n" \
		"  -a      add a device wwid to the wwids file\n" \
		"  -c      check if a device should be a path in a multipath device\n" \
		"  -q      allow queue_if_no_path when multipathd is not running\n"\
		"  -d      dry run, do not create or update devmaps\n" \
		"  -t      dump internal hardware table\n" \
		"  -r      force devmap reload\n" \
		"  -i      ignore wwids file\n" \
		"  -B      treat the bindings file as read only\n" \
		"  -p      policy failover|multibus|group_by_serial|group_by_prio\n" \
		"  -b fil  bindings file location\n" \
		"  -w      remove a device from the wwids file\n" \
		"  -W      reset the wwids file include only the current devices\n" \
		"  -p pol  force all maps to specified path grouping policy :\n" \
		"          . failover            one path per priority group\n" \
		"          . multibus            all paths in one priority group\n" \
		"          . group_by_serial     one priority group per serial\n" \
		"          . group_by_prio       one priority group per priority lvl\n" \
		"          . group_by_node_name  one priority group per target node\n" \
		"  -v lvl  verbosity level\n" \
		"          . 0 no output\n" \
		"          . 1 print created devmap names only\n" \
		"          . 2 default verbosity\n" \
		"          . 3 print debug information\n" \
		"  dev     action limited to:\n" \
		"          . multipath named 'dev' (ex: mpath0) or\n" \
		"          . multipath whose wwid is 'dev' (ex: 60051..)\n" \
		"          . multipath including the path named 'dev' (ex: /dev/sda)\n" \
		"          . multipath including the path with maj:min 'dev' (ex: 8:0)\n" \
		);

}

static int
update_paths (struct multipath * mpp)
{
	int i, j;
	struct pathgroup * pgp;
	struct path * pp;

	if (!mpp->pg)
		return 0;

	vector_foreach_slot (mpp->pg, pgp, i) {
		if (!pgp->paths)
			continue;

		vector_foreach_slot (pgp->paths, pp, j) {
			if (!strlen(pp->dev)) {
				if (devt2devname(pp->dev, FILE_NAME_SIZE,
						 pp->dev_t)) {
					/*
					 * path is not in sysfs anymore
					 */
					pp->chkrstate = pp->state = PATH_DOWN;
					continue;
				}
				pp->mpp = mpp;
				if (pathinfo(pp, conf->hwtable, DI_ALL))
					pp->state = PATH_UNCHECKED;
				continue;
			}
			pp->mpp = mpp;
			if (pp->state == PATH_UNCHECKED ||
			    pp->state == PATH_WILD) {
				if (pathinfo(pp, conf->hwtable, DI_CHECKER))
					pp->state = PATH_UNCHECKED;
			}

			if (pp->priority == PRIO_UNDEF) {
				if (pathinfo(pp, conf->hwtable, DI_PRIO))
					pp->priority = PRIO_UNDEF;
			}
		}
	}
	return 0;
}

static int
get_dm_mpvec (vector curmp, vector pathvec, char * refwwid)
{
	int i;
	struct multipath * mpp;
	char params[PARAMS_SIZE], status[PARAMS_SIZE];

	if (dm_get_maps(curmp))
		return 1;

	vector_foreach_slot (curmp, mpp, i) {
		/*
		 * discard out of scope maps
		 */
		if (mpp->wwid && refwwid &&
		    strncmp(mpp->wwid, refwwid, WWID_SIZE)) {
			condlog(3, "skip map %s: out of scope", mpp->alias);
			free_multipath(mpp, KEEP_PATHS);
			vector_del_slot(curmp, i);
			i--;
			continue;
		}

		if (conf->cmd == CMD_VALID_PATH)
			continue;

		dm_get_map(mpp->alias, &mpp->size, params);
		condlog(3, "params = %s", params);
		dm_get_status(mpp->alias, status);
		condlog(3, "status = %s", status);

		disassemble_map(pathvec, params, mpp);

		/*
		 * disassemble_map() can add new paths to pathvec.
		 * If not in "fast list mode", we need to fetch information
		 * about them
		 */
		if (conf->cmd != CMD_LIST_SHORT)
			update_paths(mpp);

		if (conf->cmd == CMD_LIST_LONG)
			mpp->bestpg = select_path_group(mpp);

		disassemble_status(status, mpp);

		if (conf->cmd == CMD_LIST_SHORT ||
		    conf->cmd == CMD_LIST_LONG)
			print_multipath_topology(mpp, conf->verbosity);

		if (conf->cmd == CMD_CREATE)
			reinstate_paths(mpp);
	}
	return 0;
}

static int
is_used_by_multipath(struct udev_device *ud)
{
	int ret = 0;
	const char *sp;
	char pathname[PATH_SIZE];
	char *holdername = NULL;
	int rv;
	DIR *hdir = NULL;
	struct dirent *holder;
	struct udev *udev;
	struct udev_device *dm_ud = NULL;
	const char *dm_name;

	udev = udev_device_get_udev(ud);
	if (udev == NULL) {
		condlog(1, "%s: error retrieving udev context", __func__);
		return 0;
	}
	sp = udev_device_get_syspath(ud);
	if (sp == NULL) {
		condlog(1, "%s: error retrieving syspath", __func__);
		return 0;
	}
	rv = snprintf(pathname, sizeof(pathname), "%s/holders", sp);
	if (rv < 0 || rv >= sizeof(pathname)) {
		condlog(1, "%s: error in snprintf", __func__);
		return 0;
	}
	hdir = opendir(pathname);
	if (hdir == NULL) {
		condlog(1, "%s: error in opendir: %m", __func__);
		return 0;
	}
	while ((holder = readdir(hdir)) != NULL) {
		if ((strcmp(holder->d_name,".") == 0) ||
		    (strcmp(holder->d_name,"..") == 0))
			continue;
		if (!strncmp(holder->d_name, "dm-", 3)) {
			rv = snprintf(pathname, sizeof(pathname),
				      "%s/holders/%s",
				      sp, holder->d_name);
			if (rv < 0 || rv >= sizeof(pathname)) {
				condlog(1, "%s: error in snprintf", __func__);
				goto out;
			}
			holdername = realpath(pathname, NULL);
			if (holdername == NULL) {
				condlog(1, "%s: error in realpath: %m",
					__func__);
				goto out;
			}
			dm_ud = udev_device_new_from_syspath(udev, holdername);
			if (dm_ud == NULL) {
				condlog(1, "%s: error getting udev from %s",
					__func__, holdername);
				goto out_hn;
			}
			dm_name = udev_device_get_sysattr_value(dm_ud, "dm/name");
			if (dm_name == NULL) {
				condlog(1, "%s: error getting dm/name from %s",
					__func__, holdername);
				goto out_ud;
			}
			condlog(4, "%s: checking %s", __func__, dm_name);
			rv = dm_type(dm_name, TGT_MPATH);
			if (rv == 1) {
				condlog(3, "%s: holder %s is multipath",
					 __func__, dm_name);
				ret = 1;
			} else
				condlog(3, "%s: holder %s is not multipath",
					 __func__, dm_name);
		} else
			condlog(3, "%s: holder %s is not dm",
				__func__, holder->d_name);
		/* Never more than 1 holder for multipath */
		break;
	}
out_ud:
	udev_device_unref(dm_ud);
out_hn:
	free(holdername);
out:
	closedir(hdir);
	return ret;
}

static int
check_path_in_use(struct path *pp)
{
	const char *devnode;
	int fd;
	struct stat stt;
	if (!pp || !pp->udev) {
		condlog(1, "%s: called with empty path", __func__);
		return 0;
	}
	devnode = udev_device_get_devnode(pp->udev);
	if (!devnode) {
		condlog(1, "%s: no devnode found for %s", __func__,
			pp->dev);
		return 0;
	}
	condlog(4, "%s: checking %s", __func__, devnode);
	if (stat(devnode, &stt) == -1) {
		condlog(1, "%s: stat error for %s: %m", __func__, devnode);
		return 0;
	}
	if (!S_ISBLK(stt.st_mode)) {
		condlog(1, "%s: %s is not a block device", __func__, devnode);
		return 0;
	}
	fd = open(devnode, O_RDONLY|O_EXCL);
	if (fd >= 0) {
		close(fd);
		condlog(3, "%s: %s is unused", __func__, devnode);
		return 0;
	}
	if (errno == EBUSY) {
		condlog(3, "%s: %s is in use", __func__, devnode);
		return !is_used_by_multipath(pp->udev);
	} else {
		condlog(1, "%s: open error for %s: %m", __func__, devnode);
		return 1;
	}
}

/*
 * Return value:
 *  -1: Retry
 *   0: Success
 *   1: Failure
 */
static int
configure (void)
{
	vector curmp = NULL;
	vector pathvec = NULL;
	struct vectors vecs;
	int r = 1;
	int di_flag = 0;
	char * refwwid = NULL;
	char * dev = NULL;
	struct path *pp = NULL;

	/*
	 * allocate core vectors to store paths and multipaths
	 */
	curmp = vector_alloc();
	pathvec = vector_alloc();

	if (!curmp || !pathvec) {
		condlog(0, "can not allocate memory");
		goto out;
	}
	vecs.pathvec = pathvec;
	vecs.mpvec = curmp;

	dev = convert_dev(conf->dev, (conf->dev_type == DEV_DEVNODE));

	/*
	 * if we have a blacklisted device parameter, exit early
	 */
	if (dev && conf->dev_type == DEV_DEVNODE &&
	    conf->cmd != CMD_REMOVE_WWID &&
	    (filter_devnode(conf->blist_devnode,
			    conf->elist_devnode, dev) > 0)) {
		if (conf->cmd == CMD_VALID_PATH)
			printf("%s is not a valid multipath device path\n",
			       conf->dev);
		goto out;
	}
	/*
	 * scope limiting must be translated into a wwid
	 * failing the translation is fatal (by policy)
	 */
	if (conf->dev) {
		int failed = get_refwwid(conf->dev, conf->dev_type, pathvec,
					 &refwwid, &pp);
		if (!refwwid) {
			if (failed == 2 && conf->cmd == CMD_VALID_PATH)
				printf("%s is not a valid multipath device path\n", conf->dev);
			else
				condlog(3, "scope is nul");
			goto out;
		}
		if (conf->cmd == CMD_REMOVE_WWID) {
			r = remove_wwid(refwwid);
			if (r == 0)
				printf("wwid '%s' removed\n", refwwid);
			else if (r == 1) {
				printf("wwid '%s' not in wwids file\n",
					refwwid);
				r = 0;
			}
			goto out;
		}
		if (conf->cmd == CMD_ADD_WWID) {
			r = remember_wwid(refwwid);
			if (r == 0)
				printf("wwid '%s' added\n", refwwid);
			else
				printf("failed adding '%s' to wwids file\n",
				       refwwid);
			goto out;
		}
		condlog(3, "scope limited to %s", refwwid);
		if (conf->cmd == CMD_VALID_PATH && pp != NULL &&
		    check_path_in_use(pp)) {
			condlog(2, "possible configuration problem: "
				"path %s is in use by a non-multipath holder",
				conf->dev);
			printf("%s is not a valid multipath device path\n",
				conf->dev);
			goto out;
		}
		/* If you are ignoring the wwids file and find_multipaths is
		 * set, you need to actually check if there are two available
		 * paths to determine if this path should be multipathed. To
		 * do this, we put off the check until after discovering all
		 * the paths */
		if (conf->cmd == CMD_VALID_PATH &&
		    (!conf->find_multipaths || !conf->ignore_wwids)) {
			if (conf->ignore_wwids ||
			    check_wwids_file(refwwid, 0) == 0)
				r = 0;

			printf("%s %s a valid multipath device path\n",
			       conf->dev, r == 0 ? "is" : "is not");
			goto out;
		}
	}

	/*
	 * get a path list
	 */
	if (conf->dev)
		di_flag = DI_WWID;

	if (conf->cmd == CMD_LIST_LONG)
		/* extended path info '-ll' */
		di_flag |= DI_SYSFS | DI_CHECKER | DI_SERIAL;
	else if (conf->cmd == CMD_LIST_SHORT)
		/* minimum path info '-l' */
		di_flag |= DI_SYSFS;
	else
		/* maximum info */
		di_flag = DI_ALL;

	if (path_discovery(pathvec, conf, di_flag) == 0)
		goto out;

	if (conf->verbosity > 2)
		print_all_paths(pathvec, 1);

	get_path_layout(pathvec, 0);

	if (get_dm_mpvec(curmp, pathvec, refwwid))
		goto out;

	filter_pathvec(pathvec, refwwid);


	if (conf->cmd == CMD_VALID_PATH) {
		/* This only happens if find_multipaths is and
		 * ignore_wwids is set.
		 * If there is currently a multipath device matching
		 * the refwwid, or there is more than one path matching
		 * the refwwid, then the path is valid */
		if (VECTOR_SIZE(curmp) != 0 || VECTOR_SIZE(pathvec) > 1)
			r = 0;
		printf("%s %s a valid multipath device path\n",
		       conf->dev, r == 0 ? "is" : "is not");
		goto out;
	}

	if (conf->cmd != CMD_CREATE && conf->cmd != CMD_DRY_RUN) {
		r = 0;
		goto out;
	}

	/*
	 * core logic entry point
	 */
	r = coalesce_paths(&vecs, NULL, refwwid, conf->force_reload);

out:
	if (refwwid)
		FREE(refwwid);

	free_multipathvec(curmp, KEEP_PATHS);
	free_pathvec(pathvec, FREE_PATHS);

	return r;
}

static int
dump_config (void)
{
	char * c;
	char * reply;
	unsigned int maxlen = 256;
	int again = 1;

	reply = MALLOC(maxlen);

	while (again) {
		if (!reply)
			return 1;
		c = reply;
		c += snprint_defaults(c, reply + maxlen - c);
		again = ((c - reply) == maxlen);
		if (again) {
			reply = REALLOC(reply, maxlen *= 2);
			continue;
		}
		c += snprint_blacklist(c, reply + maxlen - c);
		again = ((c - reply) == maxlen);
		if (again) {
			reply = REALLOC(reply, maxlen *= 2);
			continue;
		}
		c += snprint_blacklist_except(c, reply + maxlen - c);
		again = ((c - reply) == maxlen);
		if (again) {
			reply = REALLOC(reply, maxlen *= 2);
			continue;
		}
		c += snprint_hwtable(c, reply + maxlen - c, conf->hwtable);
		again = ((c - reply) == maxlen);
		if (again) {
			reply = REALLOC(reply, maxlen *= 2);
			continue;
		}
		if (VECTOR_SIZE(conf->mptable) > 0) {
			c += snprint_mptable(c, reply + maxlen - c,
					     conf->mptable);
			again = ((c - reply) == maxlen);
			if (again)
				reply = REALLOC(reply, maxlen *= 2);
		}
	}

	printf("%s", reply);
	FREE(reply);
	return 0;
}

static int
get_dev_type(char *dev) {
	struct stat buf;
	int i;

	if (stat(dev, &buf) == 0 && S_ISBLK(buf.st_mode)) {
		if (dm_is_dm_major(major(buf.st_rdev)))
			return DEV_DEVMAP;
		return DEV_DEVNODE;
	}
	else if (sscanf(dev, "%d:%d", &i, &i) == 2)
		return DEV_DEVT;
	else
		return DEV_DEVMAP;
}

int
main (int argc, char *argv[])
{
	struct udev *udev;
	int arg;
	extern char *optarg;
	extern int optind;
	int r = 1;

	udev = udev_new();
	logsink = 0;
	if (load_config(DEFAULT_CONFIGFILE, udev))
		exit(1);

	while ((arg = getopt(argc, argv, ":adchl::FfM:v:p:b:BritquwW")) != EOF ) {
		switch(arg) {
		case 1: printf("optarg : %s\n",optarg);
			break;
		case 'v':
			if (sizeof(optarg) > sizeof(char *) ||
			    !isdigit(optarg[0])) {
				usage (argv[0]);
				exit(1);
			}

			conf->verbosity = atoi(optarg);
			break;
		case 'b':
			conf->bindings_file = strdup(optarg);
			break;
		case 'B':
			conf->bindings_read_only = 1;
			break;
		case 'q':
			conf->allow_queueing = 1;
			break;
		case 'c':
			conf->cmd = CMD_VALID_PATH;
			break;
		case 'd':
			if (conf->cmd == CMD_CREATE)
				conf->cmd = CMD_DRY_RUN;
			break;
		case 'f':
			conf->remove = FLUSH_ONE;
			break;
		case 'F':
			conf->remove = FLUSH_ALL;
			break;
		case 'l':
			if (optarg && !strncmp(optarg, "l", 1))
				conf->cmd = CMD_LIST_LONG;
			else
				conf->cmd = CMD_LIST_SHORT;

			break;
		case 'M':
#if _DEBUG_
			debug = atoi(optarg);
#endif
			break;
		case 'p':
			conf->pgpolicy_flag = get_pgpolicy_id(optarg);
			if (conf->pgpolicy_flag == -1) {
				printf("'%s' is not a valid policy\n", optarg);
				usage(argv[0]);
				exit(1);
			}
			break;
		case 'r':
			conf->force_reload = 1;
			break;
		case 'i':
			conf->ignore_wwids = 1;
			break;
		case 't':
			r = dump_config();
			goto out_free_config;
		case 'h':
			usage(argv[0]);
			exit(0);
		case 'u':
			conf->cmd = CMD_VALID_PATH;
			conf->dev_type = DEV_UEVENT;
			break;
		case 'w':
			conf->cmd = CMD_REMOVE_WWID;
			break;
		case 'W':
			conf->cmd = CMD_RESET_WWIDS;
			break;
		case 'a':
			conf->cmd = CMD_ADD_WWID;
			break;
		case ':':
			fprintf(stderr, "Missing option argument\n");
			usage(argv[0]);
			exit(1);
		case '?':
			fprintf(stderr, "Unknown switch: %s\n", optarg);
			usage(argv[0]);
			exit(1);
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (getuid() != 0) {
		fprintf(stderr, "need to be root\n");
		exit(1);
	}

	if (dm_prereq())
		exit(1);
	dm_drv_version(conf->version, TGT_MPATH);
	dm_udev_set_sync_support(1);

	if (optind < argc) {
		conf->dev = MALLOC(FILE_NAME_SIZE);

		if (!conf->dev)
			goto out;

		strncpy(conf->dev, argv[optind], FILE_NAME_SIZE);
		if (conf->dev_type != DEV_UEVENT)
			conf->dev_type = get_dev_type(conf->dev);
	}
	conf->daemon = 0;
	if (conf->dev_type == DEV_UEVENT) {
		openlog("multipath", 0, LOG_DAEMON);
		setlogmask(LOG_UPTO(conf->verbosity + 3));
		logsink = 1;
	}

	if (conf->max_fds) {
		struct rlimit fd_limit;

		fd_limit.rlim_cur = conf->max_fds;
		fd_limit.rlim_max = conf->max_fds;
		if (setrlimit(RLIMIT_NOFILE, &fd_limit) < 0)
			condlog(0, "can't set open fds limit to %d : %s",
				conf->max_fds, strerror(errno));
	}

	if (init_checkers()) {
		condlog(0, "failed to initialize checkers");
		goto out;
	}
	if (init_prio()) {
		condlog(0, "failed to initialize prioritizers");
		goto out;
	}
	dm_init();

	if (conf->cmd == CMD_VALID_PATH &&
	    (!conf->dev || conf->dev_type == DEV_DEVMAP)) {
		condlog(0, "the -c option requires a path to check");
		goto out;
	}
	if (conf->cmd == CMD_VALID_PATH &&
	    conf->dev_type == DEV_UEVENT) {
		int fd;

		fd = ux_socket_connect(DEFAULT_SOCKET);
		if (fd == -1) {
			condlog(3, "%s: daemon is not running", conf->dev);
			if (!systemd_service_enabled(conf->dev)) {
				printf("%s is not a valid "
				       "multipath device path\n", conf->dev);
				goto out;
			}
		} else
			close(fd);
	}
	if (conf->cmd == CMD_REMOVE_WWID && !conf->dev) {
		condlog(0, "the -w option requires a device");
		goto out;
	}
	if (conf->cmd == CMD_RESET_WWIDS) {
		struct multipath * mpp;
		int i;
		vector curmp;

		curmp = vector_alloc();
		if (!curmp) {
			condlog(0, "can't allocate memory for mp list");
			goto out;
		}
		if (dm_get_maps(curmp) == 0)
			r = replace_wwids(curmp);
		if (r == 0)
			printf("successfully reset wwids\n");
		vector_foreach_slot_backwards(curmp, mpp, i) {
			vector_del_slot(curmp, i);
			free_multipath(mpp, KEEP_PATHS);
		}
		vector_free(curmp);
		goto out;
	}
	if (conf->remove == FLUSH_ONE) {
		if (conf->dev_type == DEV_DEVMAP) {
			r = dm_suspend_and_flush_map(conf->dev);
		} else
			condlog(0, "must provide a map name to remove");

		goto out;
	}
	else if (conf->remove == FLUSH_ALL) {
		r = dm_flush_maps();
		goto out;
	}
	while ((r = configure()) < 0)
		condlog(3, "restart multipath configuration process");

out:
	dm_lib_release();
	dm_lib_exit();

	cleanup_prio();
	cleanup_checkers();

	if (conf->dev_type == DEV_UEVENT)
		closelog();

out_free_config:
	/*
	 * Freeing config must be done after dm_lib_exit(), because
	 * the logging function (dm_write_log()), which is called there,
	 * references the config.
	 */
	free_config(conf);
	conf = NULL;
	udev_unref(udev);
#ifdef _DEBUG_
	dbg_free_final(NULL);
#endif
	return r;
}
