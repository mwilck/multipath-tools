/* Set BROKEN to 1 to treat broken behavior as success */
#define BROKEN 1
#define VERBOSITY 2

#include <stdbool.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdlib.h>
#include <cmocka.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <sys/sysmacros.h>
#include "structs.h"
#include "structs_vec.h"
#include "config.h"
#include "debug.h"
#include "discovery.h"
#include "util.h"
#include "propsel.h"
#include "defaults.h"
#include "pgpolicies.h"

#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define N_CONF_FILES 2

static const char tmplate[] = "/tmp/hwtable-XXXXXX";
static const char default_devnode[] = "sdTEST";
static const char default_wwid[] = "TEST-WWID";
static const char default_wwid_1[] = "TEST-WWID-1";
/* pretend new dm, use minio_rq */
static const unsigned int dm_tgt_version[3] = { 1, 1, 1 };
static const char _mocked_filename[] = "mocked_path";

struct key_value {
	const char *key;
	const char *value;
};

struct hwt_state {
	char *tmpname;
	char *dirname;
	FILE *config_file;
	FILE *conf_dir_file[N_CONF_FILES];
	struct vectors *vecs;
};

static struct config *_conf;
struct udev *udev;
int logsink;

struct config *get_multipath_config(void)
{
	return _conf;
}

void put_multipath_config(void *arg)
{}

void make_config_file_path(char *buf, int buflen,
			  const struct hwt_state *hwt, int i)
{
	static const char fn_template[] = "%s/test-%02d.conf";

	if (i == -1)
		/* main config file */
		snprintf(buf, buflen, fn_template, hwt->tmpname, 0);
	else
		snprintf(buf, buflen, fn_template, hwt->dirname, i);
}

static void reset_vecs(struct vectors *vecs)
{
	remove_maps(vecs);
	free_pathvec(vecs->pathvec, FREE_PATHS);

	vecs->pathvec = vector_alloc();
	assert_ptr_not_equal(vecs->pathvec, NULL);
	vecs->mpvec = vector_alloc();
	assert_ptr_not_equal(vecs->mpvec, NULL);
}

static void free_hwt(struct hwt_state *hwt)
{
	char buf[PATH_MAX];
	int i;

	if (hwt->config_file != NULL)
		fclose(hwt->config_file);
	for (i = 0; i < N_CONF_FILES; i++) {
		if (hwt->conf_dir_file[i] != NULL)
			fclose(hwt->conf_dir_file[i]);
	}

	if (hwt->tmpname != NULL) {
		make_config_file_path(buf, sizeof(buf), hwt, -1);
		unlink(buf);
		rmdir(hwt->tmpname);
		free(hwt->tmpname);
	}

	if (hwt->dirname != NULL) {
		for (i = 0; i < N_CONF_FILES; i++) {
			make_config_file_path(buf, sizeof(buf), hwt, i);
			unlink(buf);
		}
		rmdir(hwt->dirname);
		free(hwt->dirname);
	}

	if (hwt->vecs != NULL) {
		if (hwt->vecs->mpvec != NULL)
			remove_maps(hwt->vecs);
		if (hwt->vecs->pathvec != NULL)
			free_pathvec(hwt->vecs->pathvec, FREE_PATHS);
		pthread_mutex_destroy(&hwt->vecs->lock.mutex);
		free(hwt->vecs);
	}
	free(hwt);
}

static int setup(void **state)
{
	struct hwt_state *hwt;
	char buf[PATH_MAX];
	int i;

	*state = NULL;
	hwt = calloc(1, sizeof(*hwt));
	if (hwt == NULL)
		return -1;

	snprintf(buf, sizeof(buf), "%s", tmplate);
	if (mkdtemp(buf) == NULL) {
		condlog(0, "mkdtemp: %s", strerror(errno));
		goto err;
	}
	hwt->tmpname = strdup(buf);

	snprintf(buf, sizeof(buf), "%s", tmplate);
	if (mkdtemp(buf) == NULL) {
		condlog(0, "mkdtemp (2): %s", strerror(errno));
		goto err;
	}
	hwt->dirname = strdup(buf);

	make_config_file_path(buf, sizeof(buf), hwt, -1);
	hwt->config_file = fopen(buf, "w+");
	if (hwt->config_file == NULL)
		goto err;

	for (i = 0; i < N_CONF_FILES; i++) {
		make_config_file_path(buf, sizeof(buf), hwt, i);
		hwt->conf_dir_file[i] = fopen(buf, "w+");
		if (hwt->conf_dir_file[i] == NULL)
			goto err;
	}

	hwt->vecs = calloc(1, sizeof(*hwt->vecs));
	if (hwt->vecs == NULL)
		goto err;
	pthread_mutex_init(&hwt->vecs->lock.mutex, NULL);
	hwt->vecs->pathvec = vector_alloc();
	hwt->vecs->mpvec = vector_alloc();
	if (hwt->vecs->pathvec == NULL || hwt->vecs->mpvec == NULL)
		goto err;

	*state = hwt;
	return 0;

err:
	free_hwt(hwt);
	return -1;
}

static int teardown(void **state)
{
	if (state == NULL || *state == NULL)
		return -1;

	free_hwt(*state);
	*state = NULL;

	return 0;
}

/*
 * Helpers for creating the config file(s)
 */

static void reset_config(FILE *ff)
{
	if (ff == NULL)
		return;
	rewind(ff);
	if (ftruncate(fileno(ff), 0) == -1)
		condlog(1, "ftruncate: %s", strerror(errno));
}

static void reset_configs(const struct hwt_state *hwt)
{
	int i;

	reset_config(hwt->config_file);
	for (i = 0; i < N_CONF_FILES; i++)
		reset_config(hwt->conf_dir_file[i]);
}

static void write_key_values(FILE *ff, int nkv, const struct key_value *kv)
{
	int i;

	for (i = 0; i < nkv; i++) {
		if (strchr(kv[i].value, ' ') == NULL &&
		    strchr(kv[i].value, '\"') == NULL)
			fprintf(ff, "\t%s %s\n", kv[i].key, kv[i].value);
		else
			fprintf(ff, "\t%s \"%s\"\n", kv[i].key, kv[i].value);
	}
}

static void begin_section(FILE *ff, const char *section)
{
	fprintf(ff, "%s {\n", section);
}

static void end_section(FILE *ff)
{
	fprintf(ff, "}\n");
}

static void write_section(FILE *ff, const char *section,
			  int nkv, const struct key_value *kv)
{
	begin_section(ff, section);
	write_key_values(ff, nkv, kv);
	end_section(ff);
}

static void write_defaults(const struct hwt_state *hwt)
{
	static const char bindings_name[] = "bindings";
	static struct key_value defaults[] = {
		{ "config_dir", NULL },
		{ "bindings_file", NULL },
		{ "detect_prio", "no" },
		{ "detect_checker", "no" },
	};
	char buf[sizeof(tmplate) + sizeof(bindings_name)];

	snprintf(buf, sizeof(buf), "%s/%s", hwt->tmpname, bindings_name);
	defaults[0].value = hwt->dirname;
	defaults[1].value = buf;
	write_section(hwt->config_file, "defaults",
		      ARRAY_SIZE(defaults), defaults);
}

static void begin_config(const struct hwt_state *hwt)
{
	reset_configs(hwt);
	write_defaults(hwt);
}

static void begin_section_all(const struct hwt_state *hwt, const char *section)
{
	int i;

	begin_section(hwt->config_file, section);
	for (i = 0; i < N_CONF_FILES; i++)
		begin_section(hwt->conf_dir_file[i], section);
}

static void end_section_all(const struct hwt_state *hwt)
{
	int i;

	end_section(hwt->config_file);
	for (i = 0; i < N_CONF_FILES; i++)
		end_section(hwt->conf_dir_file[i]);
}

static void finish_config(const struct hwt_state *hwt)
{
	int i;

	fflush(hwt->config_file);
	for (i = 0; i < N_CONF_FILES; i++) {
		fflush(hwt->conf_dir_file[i]);
	}
}

static void write_device(FILE *ff, int nkv, const struct key_value *kv)
{
	write_section(ff, "device", nkv, kv);
}

/*
 * Some macros to avoid boilerplace code
 */

#define CHECK_STATE(state) ({ \
	assert_ptr_not_equal(state, NULL); \
	assert_ptr_not_equal(*(state), NULL);	\
	*state; })

#define WRITE_EMPTY_CONF(hwt) do {				\
		begin_config(hwt);				\
		finish_config(hwt);				\
	} while (0)

#define WRITE_ONE_DEVICE(hwt, kv) do {					\
		begin_config(hwt);					\
		begin_section_all(hwt, "devices");			\
		write_device(hwt->config_file, ARRAY_SIZE(kv), kv);	\
		end_section_all(hwt);					\
		finish_config(hwt);					\
	} while (0)

#define WRITE_TWO_DEVICES(hwt, kv1, kv2) do {				\
		begin_config(hwt);					\
		begin_section_all(hwt, "devices");			\
		write_device(hwt->config_file, ARRAY_SIZE(kv1), kv1);	\
		write_device(hwt->config_file, ARRAY_SIZE(kv2), kv2);	\
		end_section_all(hwt);					\
		finish_config(hwt);					\
	} while (0)

#define WRITE_TWO_DEVICES_W_DIR(hwt, kv1, kv2) do {			\
		begin_config(hwt);					\
		begin_section_all(hwt, "devices");			\
		write_device(hwt->config_file, ARRAY_SIZE(kv1), kv1);	\
		write_device(hwt->conf_dir_file[0],			\
			     ARRAY_SIZE(kv2), kv2);			\
		end_section_all(hwt);					\
		finish_config(hwt);					\
	} while (0)

#define LOAD_CONFIG(hwt) ({ \
	char buf[PATH_MAX];	   \
	struct config *__cf;						\
									\
	make_config_file_path(buf, sizeof(buf), hwt, -1);		\
	__cf = load_config(buf);					\
	assert_ptr_not_equal(__cf, NULL);				\
	assert_ptr_not_equal(__cf->hwtable, NULL);			\
	__cf->verbosity = VERBOSITY;					\
	memcpy(&__cf->version, dm_tgt_version, sizeof(__cf->version));	\
	__cf; })

#define FREE_CONFIG(conf) do {			\
		free_config(conf);		\
		conf = NULL;			\
	} while (0)

#define TEST_PROP(prop, val) do {				\
		if (val == NULL)				\
			assert_ptr_equal(prop, NULL);		\
		else {						\
			assert_ptr_not_equal(prop, NULL);	\
			assert_string_equal(prop, val);		\
		}						\
	} while (0)

#if BROKEN
#define TEST_PROP_BROKEN(name, prop, bad, good) do {			\
		condlog(1, "%s: WARNING: Broken test for %s == \"%s\" on line %d, should be \"%s\"", \
			__func__, name, bad ? bad : "NULL",		\
			__LINE__, good ? good : "NULL");			\
		TEST_PROP(prop, bad);					\
	} while (0)
#else
#define TEST_PROP_BROKEN(name, prop, bad, good) TEST_PROP(prop, good)
#endif

/*
 * Some predefined key/value pairs
 */

static const char _wwid[] = "wwid";
static const char _vendor[] = "vendor";
static const char _product[] = "product";
static const char _prio[] = "prio";
static const char _checker[] = "path_checker";
static const char _getuid[] = "getuid_callout";
static const char _uid_attr[] = "uid_attribute";
static const char _bl_product[] = "product_blacklist";
static const char _minio[] = "rr_min_io_rq";
static const char _no_path_retry[] = "no_path_retry";

/* Device identifiers */
static const struct key_value vnd_foo = { _vendor, "foo" };
static const struct key_value prd_bar = { _product, "bar" };
static const struct key_value prd_bam = { _product, "bam" };
static const struct key_value prd_barz = { _product, "barz" };
static const struct key_value vnd_boo = { _vendor, "boo" };
static const struct key_value prd_baz = { _product, "baz" };
static const struct key_value wwid_test = { _wwid, default_wwid };

/* Regular expresssions */
static const struct key_value vnd__oo = { _vendor, ".oo" };
static const struct key_value vnd_t_oo = { _vendor, "^.oo" };
static const struct key_value prd_ba_ = { _product, "ba." };
static const struct key_value prd_ba_s = { _product, "(bar|baz|ba\\.)$" };
/* Pathological cases, see below */
static const struct key_value prd_barx = { _product, "ba[[rxy]" };
static const struct key_value prd_bazy = { _product, "ba[zy]" };
static const struct key_value prd_bazy1 = { _product, "ba(z|y)" };

/* Properties */
static const struct key_value prio_emc = { _prio, "emc" };
static const struct key_value prio_hds = { _prio, "hds" };
static const struct key_value prio_rdac = { _prio, "rdac" };
static const struct key_value chk_hp = { _checker, "hp_sw" };
static const struct key_value gui_foo = { _getuid, "/tmp/foo" };
static const struct key_value uid_baz = { _uid_attr, "BAZ_ATTR" };
static const struct key_value bl_bar = { _bl_product, "bar" };
static const struct key_value bl_baz = { _bl_product, "baz" };
static const struct key_value bl_barx = { _bl_product, "ba[[rxy]" };
static const struct key_value bl_bazy = { _bl_product, "ba[zy]" };
static const struct key_value minio_99 = { _minio, "99" };
static const struct key_value npr_37 = { _no_path_retry, "37" };
static const struct key_value npr_queue = { _no_path_retry, "queue" };

/*
 * Helper wrappers for mock_path().
 *
 * We need to make pathinfo() think it has detected a device with
 * certain vendor/product/rev. This requires faking lots of udev
 * and sysfs function responses.
 *
 * This requires hwtable-test_OBJDEPS = ../libmultipath/discovery.o
 * in the Makefile in order to wrap calls from discovery.o.
 *
 * Note that functions that are called and defined in discovery.o can't
 * be wrapped this way (e.g. sysfs_get_vendor), because symbols are
 * resolved by the assembler before the linking stage.
 */

int __real_open(const char *path, int flags, int mode);
int __wrap_open(const char *path, int flags, int mode)
{
	condlog(4, "%s: %s", __func__, path);

	if (!strcmp(path, _mocked_filename))
		return 111;
	return __real_open(path, flags, mode);
}

int __wrap_execute_program(char *path, char *value, int len)
{
	char *val = mock_ptr_type(char *);

	condlog(5, "%s: %s", __func__, val);
	strlcpy(value, val, len);
	return 0;
}

bool __wrap_is_claimed_by_foreign(struct udev_device *ud)
{
	condlog(5, "%s: %p", __func__, ud);
	return false;
}

struct udev_list_entry
*__wrap_udev_device_get_properties_list_entry(struct udev_device *ud)
{
	void *p = (void*)0x12345678;
	condlog(5, "%s: %p", __func__, p);

	return p;
}

struct udev_list_entry
*__wrap_udev_list_entry_get_next(struct udev_list_entry *udle)
{
	void *p  = NULL;
	condlog(5, "%s: %p", __func__, p);

	return p;
}

const char *__wrap_udev_list_entry_get_name(struct udev_list_entry *udle)
{
	char *val = mock_ptr_type(char *);

	condlog(5, "%s: %s", __func__, val);
	return val;
}

struct udev_device *__wrap_udev_device_ref(struct udev_device *ud)
{
	return ud;
}

struct udev_device *__wrap_udev_device_unref(struct udev_device *ud)
{
	return ud;
}

char *__wrap_udev_device_get_subsystem(struct udev_device *ud)
{
	char *val = mock_ptr_type(char *);

	condlog(5, "%s: %s", __func__, val);
	return val;
}

char *__wrap_udev_device_get_sysname(struct udev_device *ud)
{
	char *val  = mock_ptr_type(char *);

	condlog(5, "%s: %s", __func__, val);
	return val;
}

char *__wrap_udev_device_get_devnode(struct udev_device *ud)
{
	char *val  = mock_ptr_type(char *);

	condlog(5, "%s: %s", __func__, val);
	return val;
}

dev_t __wrap_udev_device_get_devnum(struct udev_device *ud)
{
	condlog(5, "%s: %p", __func__, ud);
	return makedev(17, 17);
}

char *__wrap_udev_device_get_sysattr_value(struct udev_device *ud,
					     const char *attr)
{
	char *val  = mock_ptr_type(char *);

	condlog(5, "%s: %s->%s", __func__, attr, val);
	return val;
}

char *__wrap_udev_device_get_property_value(struct udev_device *ud,
					    const char *attr)
{
	char *val  = mock_ptr_type(char *);

	condlog(5, "%s: %s->%s", __func__, attr, val);
	return val;
}

int __wrap_sysfs_get_size(struct path *pp, unsigned long long *sz)
{
	*sz = 12345678UL;
	return 0;
}

void *__wrap_udev_device_get_parent_with_subsystem_devtype(
	struct udev_device *ud, const char *subsys, char *type)
{
	/* return non-NULL for sysfs_get_tgt_nodename */
	return type;
}

void *__wrap_udev_device_get_parent(struct udev_device *ud)
{
	char *val  = mock_ptr_type(void *);

	condlog(5, "%s: %p", __func__, val);
	return val;
}

ssize_t __wrap_sysfs_attr_get_value(struct udev_device *dev,
				    const char *attr_name,
				    char *value, size_t sz)
{
	char *val  = mock_ptr_type(char *);

	condlog(5, "%s: %s", __func__, val);
	strlcpy(value, val, sz);
	return strlen(value);
}

int __wrap_checker_check(struct checker *c, int st)
{
	condlog(5, "%s: %d", __func__, st);
	return st;
}

int __wrap_prio_getprio(struct prio *p, struct path *pp, unsigned int tmo)
{
	int pr = 5;

	condlog(5, "%s: %d", __func__, pr);
	return pr;
}

enum {
	BL_BY_DEVNODE	= (1 << 0),
	BL_BY_DEVICE	= (1 << 1),
	BL_BY_WWID	= (1 << 2),
	BL_BY_PROPERTY	= (1 << 3),
	BL_MASK = BL_BY_DEVNODE|BL_BY_DEVICE|BL_BY_WWID|BL_BY_PROPERTY,
	NEED_SELECT_PRIO = (1 << 8),
	NEED_FD		= (1 << 9),
	USE_GETUID	= (1 << 10)
};

struct mocked_path {
	const char *vendor;
	const char *product;
	const char *rev;
	const char *wwid;
	const char *devnode;
	unsigned int flags;
};

static struct mocked_path *fill_mocked_path(struct mocked_path *mp,
					    const char *vendor,
					    const char *product,
					    const char *rev,
					    const char *wwid,
					    const char *devnode,
					    unsigned int flags)
{
	mp->vendor = (vendor ? vendor : "noname");
	mp->product = (product ? product : "noprod");
	mp->rev = (rev ? rev : "0");
	mp->wwid = (wwid ? wwid : default_wwid);
	mp->devnode = (devnode ? devnode : default_devnode);
	mp->flags = flags|NEED_SELECT_PRIO|NEED_FD;
	return mp;
}

static struct mocked_path *mocked_path_from_path(struct mocked_path *mp,
						 struct path *pp)
{
	mp->vendor = pp->vendor_id;
	mp->product = pp->product_id;
	mp->rev = pp->rev;
	mp->wwid = pp->wwid;
	mp->devnode = pp->dev;
	mp->flags = (prio_selected(&pp->prio) ? 0 : NEED_SELECT_PRIO) |
		(pp->fd < 0 ? NEED_FD : 0) |
		(pp->getuid ? USE_GETUID : 0);
	return mp;
}

static void mock_sysfs_pathinfo(const struct mocked_path *mp)
{
	static const char hbtl[] = "4:0:3:1";

	will_return(__wrap_udev_device_get_subsystem, "scsi");
	will_return(__wrap_udev_device_get_sysname, hbtl);
	will_return(__wrap_udev_device_get_sysname, hbtl);
	will_return(__wrap_udev_device_get_sysattr_value, mp->vendor);
	will_return(__wrap_udev_device_get_sysname, hbtl);
	will_return(__wrap_udev_device_get_sysattr_value, mp->product);
	will_return(__wrap_udev_device_get_sysname, hbtl);
	will_return(__wrap_udev_device_get_sysattr_value, mp->rev);

	/* sysfs_get_tgt_nodename */
	will_return(__wrap_udev_device_get_sysattr_value, NULL);
	will_return(__wrap_udev_device_get_parent, NULL);
	will_return(__wrap_udev_device_get_parent, NULL);
	will_return(__wrap_udev_device_get_sysname, "nofibre");
	will_return(__wrap_udev_device_get_sysname, "noiscsi");
	will_return(__wrap_udev_device_get_parent, NULL);
	will_return(__wrap_udev_device_get_sysname, "ata25");
}

/*
 * Pretend we detected a SCSI device with given vendor/prod/rev
 */
static void mock_pathinfo(int mask, const struct mocked_path *mp)
{
	/* filter_property */
	will_return(__wrap_udev_device_get_sysname, mp->devnode);
	if (mp->flags & BL_BY_PROPERTY) {
		will_return(__wrap_udev_list_entry_get_name, "BAZ");
		return;
	} else
		will_return(__wrap_udev_list_entry_get_name,
			    "SCSI_IDENT_LUN_NAA_EXT");

	if (mask & DI_SYSFS)
		mock_sysfs_pathinfo(mp);

	if (mp->flags & BL_BY_DEVICE &&
	    (mask & DI_BLACKLIST && mask & DI_SYSFS))
		return;

	/* path_offline */
	will_return(__wrap_udev_device_get_subsystem, "scsi");
	will_return(__wrap_sysfs_attr_get_value, "running");

	if (mask & DI_NOIO)
		return;

	/* fake open() in pathinfo() */
	if (mp->flags & NEED_FD)
		will_return(__wrap_udev_device_get_devnode, _mocked_filename);
	/* DI_SERIAL is unsupported */
	assert_false(mask & DI_SERIAL);

	if (mask & DI_WWID) {
		if (mp->flags & USE_GETUID)
			will_return(__wrap_execute_program, mp->wwid);
		else
			/* get_udev_uid() */
			will_return(__wrap_udev_device_get_property_value,
				    mp->wwid);
	}

	if (mask & DI_CHECKER) {
		/* get_state -> sysfs_get_timeout  */
		will_return(__wrap_udev_device_get_subsystem, "scsi");
		will_return(__wrap_udev_device_get_sysattr_value, "180");
	}

	if (mask & DI_PRIO && mp->flags & NEED_SELECT_PRIO) {

		/* sysfs_get_timeout, again (!?) */
		will_return(__wrap_udev_device_get_subsystem, "scsi");
		will_return(__wrap_udev_device_get_sysattr_value, "180");

	}
}

static void mock_store_pathinfo(int mask,  const struct mocked_path *mp)
{
	will_return(__wrap_udev_device_get_sysname, mp->devnode);
	mock_pathinfo(mask, mp);
}

static struct path *__mock_path(vector pathvec,
				const char *vnd, const char *prd,
				const char *rev, const char *wwid,
				const char *dev,
				unsigned int flags, int mask)
{
	struct mocked_path mop;
	struct path *pp;
	struct config *conf;
	int r;

	fill_mocked_path(&mop, vnd, prd, rev, wwid, dev, flags);
	mock_store_pathinfo(mask, &mop);

	conf = get_multipath_config();
	r = store_pathinfo(pathvec, conf, (void *)&mop, mask, &pp);
	put_multipath_config(conf);

	if (flags & BL_MASK) {
		assert_int_equal(r, PATHINFO_SKIPPED);
		return NULL;
	}
	assert_int_equal(r, PATHINFO_OK);
	assert_non_null(pp);
	return pp;
}

int default_mask = (DI_SYSFS|DI_BLACKLIST|DI_WWID|DI_CHECKER|DI_PRIO);

#define mock_path(v, p) __mock_path(hwt->vecs->pathvec, \
				       (v), (p), "0", NULL, NULL, \
				       0, default_mask)
#define mock_path_flags(v, p, f) __mock_path(hwt->vecs->pathvec, \
						(v), (p), "0", NULL, NULL, \
						(f), default_mask)
#define mock_path_blacklisted(v, p) __mock_path(hwt->vecs->pathvec, \
						   (v), (p), "0", NULL, NULL, \
						   BL_BY_DEVICE, default_mask)
#define mock_path_wwid(v, p, w) __mock_path(hwt->vecs->pathvec,		\
					       (v), (p), "0", (w), NULL, \
					       0, default_mask)

static struct multipath *__mock_multipath(struct vectors *vecs, struct path *pp)
{
	struct multipath *mp;
	struct config *conf;
	struct mocked_path mop;

	mocked_path_from_path(&mop, pp);
	/* pathinfo() call in adopt_paths */
	mock_pathinfo(DI_CHECKER|DI_PRIO, &mop);

	mp = add_map_with_path(vecs, pp, 1);
	assert_ptr_not_equal(mp, NULL);

	/* TBD: mock setup_map() ... */
	conf = get_multipath_config();
	select_pgpolicy(conf, mp);
	select_no_path_retry(conf, mp);
	select_retain_hwhandler(conf, mp);
	select_minio(conf, mp);
	put_multipath_config(conf);

	return mp;
}

#define mock_multipath(pp) __mock_multipath(hwt->vecs, (pp))

/***** BEGIN TESTS SECTION *****/

/*
 * Sanity check for the test itself, because defaults may be changed
 * in libmultipath.
 *
 * Our checking for match or non-match relies on the defaults being
 * different from what our device sections contain.
 */
static void test_sanity_globals(void **state)
{
	assert_string_not_equal(prio_emc.value, DEFAULT_PRIO);
	assert_string_not_equal(prio_hds.value, DEFAULT_PRIO);
	assert_string_not_equal(chk_hp.value, DEFAULT_CHECKER);
	assert_int_not_equal(MULTIBUS, DEFAULT_PGPOLICY);
	assert_int_not_equal(NO_PATH_RETRY_QUEUE, DEFAULT_NO_PATH_RETRY);
	assert_int_not_equal(atoi(minio_99.value), DEFAULT_MINIO_RQ);
	assert_int_not_equal(atoi(npr_37.value), DEFAULT_NO_PATH_RETRY);
}

/*
 * Regression test for internal hwtable. NVME is an example of two entries
 * in the built-in hwtable, one if which matches a subset of the other.
 */
static void test_internal_nvme(void **state)
{
	const struct hwt_state *hwt;
	struct path *pp;
	struct multipath *mp;

	hwt = CHECK_STATE(state);
	reset_vecs(hwt->vecs);
	WRITE_EMPTY_CONF(hwt);
	_conf = LOAD_CONFIG(hwt);

	/*
	 * Generic NVMe: expect defaults for pgpolicy and no_path_retry
	 */
	pp = mock_path("NVME", "NoName");
	mp = mock_multipath(pp);
	assert_ptr_not_equal(mp, NULL);
	TEST_PROP(pp->checker.name, NONE);
	TEST_PROP(pp->uid_attribute, "ID_WWN");
	assert_int_equal(mp->pgpolicy, DEFAULT_PGPOLICY);
	assert_int_equal(mp->no_path_retry, DEFAULT_NO_PATH_RETRY);
	assert_int_equal(mp->retain_hwhandler, RETAIN_HWHANDLER_OFF);

	/*
	 * NetApp NVMe: expect special values for pgpolicy and no_path_retry
	 */
	pp = mock_path_wwid("NVME", "NetApp ONTAP Controller",
			    default_wwid_1);
	mp = mock_multipath(pp);
	assert_ptr_not_equal(mp, NULL);
	TEST_PROP(pp->checker.name, NONE);
	TEST_PROP(pp->uid_attribute, "ID_WWN");
	assert_int_equal(mp->pgpolicy, MULTIBUS);
	assert_int_equal(mp->no_path_retry, NO_PATH_RETRY_QUEUE);
	assert_int_equal(mp->retain_hwhandler, RETAIN_HWHANDLER_OFF);

	FREE_CONFIG(_conf);
}

/*
 * Device section with a single simple entry ("foo:bar")
 */
static void test_string_hwe(void **state)
{
	const struct hwt_state *hwt;
	struct path *pp;
	const struct key_value kv[] = { vnd_foo, prd_bar, prio_emc };

	hwt = CHECK_STATE(state);
	WRITE_ONE_DEVICE(hwt, kv);
	_conf = LOAD_CONFIG(hwt);

	/* foo:bar matches */
	pp = mock_path(vnd_foo.value, prd_bar.value);
	TEST_PROP(prio_name(&pp->prio), prio_emc.value);

	/* foo:baz doesn't match */
	pp = mock_path(vnd_foo.value, prd_baz.value);
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);

	/* boo:bar doesn't match */
	pp = mock_path(vnd_boo.value, prd_bar.value);
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);

	FREE_CONFIG(_conf);
}

/*
 * Device section with a single regex entry ("^.foo:(bar|baz|ba\.)$")
 */
static void test_regex_hwe(void **state)
{
	const struct hwt_state *hwt;
	struct path *pp;
	const struct key_value kv[] = { vnd_t_oo, prd_ba_s, prio_emc };

	hwt = CHECK_STATE(state);
	reset_vecs(hwt->vecs);
	WRITE_ONE_DEVICE(hwt, kv);
	_conf = LOAD_CONFIG(hwt);

	/* foo:bar matches */
	pp = mock_path(vnd_foo.value, prd_bar.value);
	TEST_PROP(prio_name(&pp->prio), prio_emc.value);

	/* foo:baz matches */
	pp = mock_path(vnd_foo.value, prd_baz.value);
	TEST_PROP(prio_name(&pp->prio), prio_emc.value);

	/* boo:baz matches */
	pp = mock_path(vnd_boo.value, prd_bar.value);
	TEST_PROP(prio_name(&pp->prio), prio_emc.value);

	/* foo:BAR doesn't match */
	pp = mock_path(vnd_foo.value, "BAR");
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);

	/* bboo:bar doesn't match */
	pp = mock_path("bboo", prd_bar.value);
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);

	FREE_CONFIG(_conf);
}

/*
 * Two device entries, kv1 is a regex match ("^.foo:(bar|baz|ba\.)$"),
 * kv2 a string match (foo:bar) which matches a subset of the regex.
 * Both are added to the main config file.
 *
 * Expected: Devices matching both get properties from both, kv2 taking
 * precedence. Devices matching kv1 only just get props from kv1.
 *
 * Current: These entries are currently _NOT_ merged, therefore getuid is
 * default for kv1 matches, and checker is default on kv2 matches.
 */
static void test_regex_string_hwe(void **state)
{
	const struct hwt_state *hwt;
	struct path *pp;
	const struct key_value kv1[] = { vnd_t_oo, prd_ba_s, prio_emc, chk_hp };
	const struct key_value kv2[] = { vnd_foo, prd_bar, prio_hds, gui_foo };

	hwt = CHECK_STATE(state);
	reset_vecs(hwt->vecs);
	WRITE_TWO_DEVICES(hwt, kv1, kv2);
	_conf = LOAD_CONFIG(hwt);

	/* foo:baz matches kv1 */
	pp = mock_path(vnd_foo.value, prd_baz.value);
	TEST_PROP(prio_name(&pp->prio), prio_emc.value);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, chk_hp.value);

	/* boo:baz matches kv1 */
	pp = mock_path(vnd_boo.value, prd_baz.value);
	TEST_PROP(prio_name(&pp->prio), prio_emc.value);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, chk_hp.value);

	/* .oo:ba. matches kv1 */
	pp = mock_path(vnd__oo.value, prd_ba_.value);
	TEST_PROP(prio_name(&pp->prio), prio_emc.value);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, chk_hp.value);

	/* .foo:(bar|baz|ba\.) doesn't match */
	pp = mock_path(vnd__oo.value, prd_ba_s.value);
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, DEFAULT_CHECKER);

	/* foo:bar matches kv2 and kv1 */
	pp = mock_path_flags(vnd_foo.value, prd_bar.value, USE_GETUID);
	TEST_PROP(prio_name(&pp->prio), prio_hds.value);
	TEST_PROP(pp->getuid, gui_foo.value);
	/*
	 * You'd expect that the two entries above be merged,
	 * but that isn't the case if they're in the same input file.
	 */
	TEST_PROP_BROKEN(_checker, pp->checker.name,
			 DEFAULT_CHECKER, chk_hp.value);

	FREE_CONFIG(_conf);
}

/*
 * Two device entries, kv1 is a regex match ("^.foo:(bar|baz|ba\.)$"),
 * kv2 a string match (foo:bar) which matches a subset of the regex.
 * kv1 is added to the main config file, kv2 to a config_dir file.
 * This case is more important as you may think, because it's equivalent
 * to kv1 being in the built-in hwtable and kv2 in multipath.conf.
 *
 * Expected: Devices matching kv2 (and thus, both) get properties
 * from both, kv2 taking precedence.
 * Devices matching kv1 only just get props from kv1.
 *
 * Current: behaves as expected.
 */
static void test_regex_string_hwe_dir(void **state)
{
	const struct hwt_state *hwt;
	struct path *pp;
	const struct key_value kv1[] = { vnd_t_oo, prd_ba_s, prio_emc, chk_hp };
	const struct key_value kv2[] = { vnd_foo, prd_bar, prio_hds, gui_foo };

	hwt = CHECK_STATE(state);
	reset_vecs(hwt->vecs);
	WRITE_TWO_DEVICES_W_DIR(hwt, kv1, kv2);
	_conf = LOAD_CONFIG(hwt);

	/* foo:baz matches kv1 */
	pp = mock_path(vnd_foo.value, prd_baz.value);
	TEST_PROP(prio_name(&pp->prio), prio_emc.value);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, chk_hp.value);

	/* boo:baz matches kv1 */
	pp = mock_path(vnd_boo.value, prd_baz.value);
	TEST_PROP(prio_name(&pp->prio), prio_emc.value);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, chk_hp.value);

	/* .oo:ba. matches kv1 */
	pp = mock_path(vnd__oo.value, prd_ba_.value);
	TEST_PROP(prio_name(&pp->prio), prio_emc.value);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, chk_hp.value);

	/* .oo:(bar|baz|ba\.)$ doesn't match */
	pp = mock_path(vnd__oo.value, prd_ba_s.value);
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, DEFAULT_CHECKER);

	/* foo:bar matches kv2 */
	pp = mock_path_flags(vnd_foo.value, prd_bar.value, USE_GETUID);
	/* Later match takes prio */
	TEST_PROP(prio_name(&pp->prio), prio_hds.value);
	TEST_PROP(pp->getuid, gui_foo.value);
	/* This time it's merged */
	TEST_PROP(pp->checker.name, chk_hp.value);

	FREE_CONFIG(_conf);
}

/*
 * Three device entries, kv1 is a regex match and kv2 and kv3 string
 * matches, where kv3 is a substring of kv2. All in different config
 * files.
 *
 * Expected: Devices matching kv3 get props from all, devices matching
 * kv2 from kv2 and kv1, and devices matching kv1 only just from kv1.
 */
static void test_regex_2_strings_hwe_dir(void **state)
{
	const struct hwt_state *hwt;
	struct path *pp;
	const struct key_value kv1[] = { vnd_foo, prd_ba_, prio_emc, chk_hp };
	const struct key_value kv2[] = { vnd_foo, prd_bar, prio_hds, uid_baz };
	const struct key_value kv3[] = { vnd_foo, prd_barz,
					 prio_rdac, gui_foo };

	hwt = CHECK_STATE(state);
	reset_vecs(hwt->vecs);
	begin_config(hwt);
	begin_section_all(hwt, "devices");
	write_device(hwt->config_file, ARRAY_SIZE(kv1), kv1);
	write_device(hwt->conf_dir_file[0], ARRAY_SIZE(kv2), kv2);
	write_device(hwt->conf_dir_file[1], ARRAY_SIZE(kv3), kv3);
	end_section_all(hwt);
	finish_config(hwt);
	_conf = LOAD_CONFIG(hwt);

	/* foo:baz matches kv1 */
	pp = mock_path(vnd_foo.value, prd_baz.value);
	TEST_PROP(prio_name(&pp->prio), prio_emc.value);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->uid_attribute, DEFAULT_UID_ATTRIBUTE);
	TEST_PROP(pp->checker.name, chk_hp.value);

	/* boo:baz doesn't match */
	pp = mock_path(vnd_boo.value, prd_baz.value);
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->uid_attribute, DEFAULT_UID_ATTRIBUTE);
	TEST_PROP(pp->checker.name, DEFAULT_CHECKER);

	/* foo:bar matches kv2 and kv1 */
	pp = mock_path(vnd_foo.value, prd_bar.value);
	TEST_PROP(prio_name(&pp->prio), prio_hds.value);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->uid_attribute, uid_baz.value);
	TEST_PROP(pp->checker.name, chk_hp.value);

	/* foo:barz matches kv3 and kv2 and kv1 */
	pp = mock_path_flags(vnd_foo.value, prd_barz.value, USE_GETUID);
	TEST_PROP(prio_name(&pp->prio), prio_rdac.value);
	TEST_PROP(pp->getuid, gui_foo.value);
	TEST_PROP(pp->uid_attribute, NULL);
	TEST_PROP(pp->checker.name, chk_hp.value);

	FREE_CONFIG(_conf);
}

/*
 * Like test_regex_string_hwe_dir, but the order of kv1 and kv2 is exchanged.
 *
 * Expected: Devices matching kv1 (and thus, both) get properties
 * from both, kv1 taking precedence.
 * Devices matching kv1 only just get props from kv1.
 *
 * Current: kv2 never matches, because kv1 is more generic and encountered
 * first; thus properties from kv2 aren't used.
 */
static void test_string_regex_hwe_dir(void **state)
{
	const struct hwt_state *hwt;
	struct path *pp;
	const struct key_value kv1[] = { vnd_t_oo, prd_ba_s, prio_emc, chk_hp };
	const struct key_value kv2[] = { vnd_foo, prd_bar, prio_hds, gui_foo };

	hwt = CHECK_STATE(state);
	reset_vecs(hwt->vecs);
	WRITE_TWO_DEVICES_W_DIR(hwt, kv2, kv1);
	_conf = LOAD_CONFIG(hwt);

	/* foo:bar matches kv2 and kv1 */
	pp = mock_path_flags(vnd_foo.value, prd_bar.value,
			     BROKEN == 1 ? 0 : USE_GETUID);
	TEST_PROP(prio_name(&pp->prio), prio_emc.value);
	TEST_PROP_BROKEN(_getuid, pp->getuid, (char *)NULL, gui_foo.value);
	TEST_PROP(pp->checker.name, chk_hp.value);

	/* foo:baz matches kv1 */
	pp = mock_path(vnd_foo.value, prd_baz.value);
	TEST_PROP(prio_name(&pp->prio), prio_emc.value);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, chk_hp.value);

	/* boo:baz matches kv1 */
	pp = mock_path(vnd_boo.value, prd_baz.value);
	TEST_PROP(prio_name(&pp->prio), prio_emc.value);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, chk_hp.value);

	/* .oo:ba. matches kv1 */
	pp = mock_path(vnd__oo.value, prd_ba_.value);
	TEST_PROP(prio_name(&pp->prio), prio_emc.value);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, chk_hp.value);

	/* .oo:(bar|baz|ba\.)$ doesn't match */
	pp = mock_path(vnd__oo.value, prd_ba_s.value);
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, DEFAULT_CHECKER);

	FREE_CONFIG(_conf);
}

/*
 * Two identical device entries kv1 and kv2, trival regex ("string").
 * Both are added to the main config file.
 * These entries are NOT merged.
 * This could happen in a large multipath.conf file.
 *
 * Expected: matching devices get props from both, kv2 taking precedence.
 *
 * Current: devices get props from kv2 only.
 */
static void test_2_ident_strings_hwe(void **state)
{
	const struct hwt_state *hwt;
	struct path *pp;
	const struct key_value kv1[] = { vnd_foo, prd_bar, prio_emc, chk_hp };
	const struct key_value kv2[] = { vnd_foo, prd_bar, prio_hds, gui_foo };

	hwt = CHECK_STATE(state);
	reset_vecs(hwt->vecs);
	WRITE_TWO_DEVICES(hwt, kv1, kv2);
	_conf = LOAD_CONFIG(hwt);

	/* foo:baz doesn't match */
	pp = mock_path(vnd_foo.value, prd_baz.value);
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, DEFAULT_CHECKER);

	/* foo:bar matches both, but only kv2 is seen */
	pp = mock_path_flags(vnd_foo.value, prd_bar.value, USE_GETUID);
	TEST_PROP(prio_name(&pp->prio), prio_hds.value);
	TEST_PROP(pp->getuid, gui_foo.value);
	TEST_PROP_BROKEN(_checker, pp->checker.name, DEFAULT_CHECKER,
			 chk_hp.value);

	FREE_CONFIG(_conf);
}

/*
 * Two identical device entries kv1 and kv2, trival regex ("string").
 * Both are added to an extra config file.
 * This could happen in a large multipath.conf file.
 *
 * Expected: matching devices get props from both, kv2 taking precedence.
 */
static void test_2_ident_strings_both_dir(void **state)
{
	const struct hwt_state *hwt;
	struct path *pp;
	const struct key_value kv1[] = { vnd_foo, prd_bar, prio_emc, chk_hp };
	const struct key_value kv2[] = { vnd_foo, prd_bar, prio_hds, gui_foo };

	hwt = CHECK_STATE(state);
	reset_vecs(hwt->vecs);
	begin_config(hwt);
	begin_section_all(hwt, "devices");
	write_device(hwt->conf_dir_file[1], ARRAY_SIZE(kv1), kv1);
	write_device(hwt->conf_dir_file[1], ARRAY_SIZE(kv2), kv2);
	end_section_all(hwt);
	finish_config(hwt);
	_conf = LOAD_CONFIG(hwt);

	/* foo:baz doesn't match */
	pp = mock_path(vnd_foo.value, prd_baz.value);
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, DEFAULT_CHECKER);

	/* foo:bar matches both */
	pp = mock_path_flags(vnd_foo.value, prd_bar.value, USE_GETUID);
	TEST_PROP(prio_name(&pp->prio), prio_hds.value);
	TEST_PROP(pp->getuid, gui_foo.value);
	TEST_PROP_BROKEN(_checker, pp->checker.name, DEFAULT_CHECKER,
			 chk_hp.value);

	FREE_CONFIG(_conf);
}

/*
 * Two identical device entries kv1 and kv2, trival regex ("string").
 * Both are added to an extra config file.
 * An empty entry with the same string exists in the main config file.
 *
 * Expected: matching devices get props from both, kv2 taking precedence.
 */
static void test_2_ident_strings_both_dir_w_prev(void **state)
{
	const struct hwt_state *hwt;
	struct path *pp;
	const struct key_value kv0[] = { vnd_foo, prd_bar };
	const struct key_value kv1[] = { vnd_foo, prd_bar, prio_emc, chk_hp };
	const struct key_value kv2[] = { vnd_foo, prd_bar, prio_hds, gui_foo };

	hwt = CHECK_STATE(state);
	reset_vecs(hwt->vecs);
	begin_config(hwt);
	begin_section_all(hwt, "devices");
	write_device(hwt->config_file, ARRAY_SIZE(kv0), kv0);
	write_device(hwt->conf_dir_file[1], ARRAY_SIZE(kv1), kv1);
	write_device(hwt->conf_dir_file[1], ARRAY_SIZE(kv2), kv2);
	end_section_all(hwt);
	finish_config(hwt);
	_conf = LOAD_CONFIG(hwt);

	/* foo:baz doesn't match */
	pp = mock_path(vnd_foo.value, prd_baz.value);
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, DEFAULT_CHECKER);

	/* foo:bar matches both */
	pp = mock_path_flags(vnd_foo.value, prd_bar.value, USE_GETUID);
	TEST_PROP(prio_name(&pp->prio), prio_hds.value);
	TEST_PROP(pp->getuid, gui_foo.value);
	TEST_PROP_BROKEN(_checker, pp->checker.name, DEFAULT_CHECKER,
			 chk_hp.value);

	FREE_CONFIG(_conf);
}

/*
 * Two identical device entries kv1 and kv2, trival regex ("string").
 * kv1 is added to the main config file, kv2 to a config_dir file.
 * These entries are merged.
 * This case is more important as you may think, because it's equivalent
 * to kv1 being in the built-in hwtable and kv2 in multipath.conf.
 *
 * Expected: matching devices get props from both, kv2 taking precedence.
 *
 * Current: behaves as expected.
 */
static void test_2_ident_strings_hwe_dir(void **state)
{
	const struct hwt_state *hwt;
	struct path *pp;
	const struct key_value kv1[] = { vnd_foo, prd_bar, prio_emc, chk_hp };
	const struct key_value kv2[] = { vnd_foo, prd_bar, prio_hds, gui_foo };

	hwt = CHECK_STATE(state);
	reset_vecs(hwt->vecs);
	WRITE_TWO_DEVICES_W_DIR(hwt, kv1, kv2);
	_conf = LOAD_CONFIG(hwt);

	/* foo:baz doesn't match */
	pp = mock_path(vnd_foo.value, prd_baz.value);
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, DEFAULT_CHECKER);

	/* foo:bar matches both */
	pp = mock_path_flags(vnd_foo.value, prd_bar.value, USE_GETUID);
	TEST_PROP(prio_name(&pp->prio), prio_hds.value);
	TEST_PROP(pp->getuid, gui_foo.value);
	TEST_PROP(pp->checker.name, chk_hp.value);

	FREE_CONFIG(_conf);
}

/*
 * Like test_2_ident_strings_hwe_dir, but this time the config_dir file
 * contains an additional, empty entry (kv0).
 *
 * Expected: matching devices get props from kv1 and kv2, kv2 taking precedence.
 *
 * Current: kv0 and kv1 are merged into kv0, and then ignored because kv2 takes
 * precedence. Thus the presence of the empty kv0 changes how kv1 is treated.
 */
static void test_3_ident_strings_hwe_dir(void **state)
{
	const struct hwt_state *hwt;
	struct path *pp;
	const struct key_value kv0[] = { vnd_foo, prd_bar };
	const struct key_value kv1[] = { vnd_foo, prd_bar, prio_emc, chk_hp };
	const struct key_value kv2[] = { vnd_foo, prd_bar, prio_hds, gui_foo };

	hwt = CHECK_STATE(state);
	reset_vecs(hwt->vecs);
	begin_config(hwt);
	begin_section_all(hwt, "devices");
	write_device(hwt->config_file, ARRAY_SIZE(kv1), kv1);
	write_device(hwt->conf_dir_file[1], ARRAY_SIZE(kv0), kv0);
	write_device(hwt->conf_dir_file[1], ARRAY_SIZE(kv2), kv2);
	end_section_all(hwt);
	finish_config(hwt);
	_conf = LOAD_CONFIG(hwt);

	/* foo:baz doesn't match */
	pp = mock_path(vnd_foo.value, prd_baz.value);
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, DEFAULT_CHECKER);

	/* foo:bar matches both */
	pp = mock_path_flags(vnd_foo.value, prd_bar.value, USE_GETUID);
	TEST_PROP(prio_name(&pp->prio), prio_hds.value);
	TEST_PROP(pp->getuid, gui_foo.value);
	TEST_PROP_BROKEN(_checker, pp->checker.name, DEFAULT_CHECKER,
			 chk_hp.value);

	FREE_CONFIG(_conf);
}

/*
 * Two identical device entries kv1 and kv2, non-trival regex that matches
 * itself (string ".oo" matches regex ".oo").
 * kv1 is added to the main config file, kv2 to a config_dir file.
 * This case is more important as you may think, because it's equivalent
 * to kv1 being in the built-in hwtable and kv2 in multipath.conf.
 *
 * Expected: matching devices get props from both, kv2 taking precedence.
 *
 * Current: behaves as expected.
 */
static void test_2_ident_self_matching_re_hwe_dir(void **state)
{
	const struct hwt_state *hwt;
	struct path *pp;
	const struct key_value kv1[] = { vnd__oo, prd_bar, prio_emc, chk_hp };
	const struct key_value kv2[] = { vnd__oo, prd_bar, prio_hds, gui_foo };

	hwt = CHECK_STATE(state);
	reset_vecs(hwt->vecs);
	WRITE_TWO_DEVICES_W_DIR(hwt, kv1, kv2);
	_conf = LOAD_CONFIG(hwt);

	/* foo:baz doesn't match */
	pp = mock_path(vnd_foo.value, prd_baz.value);
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, DEFAULT_CHECKER);

	/* foo:bar matches both */
	pp = mock_path_flags(vnd_foo.value, prd_bar.value, USE_GETUID);
	TEST_PROP(prio_name(&pp->prio), prio_hds.value);
	TEST_PROP(pp->getuid, gui_foo.value);
	TEST_PROP(pp->checker.name, chk_hp.value);

	FREE_CONFIG(_conf);
}

/*
 * Two identical device entries kv1 and kv2, non-trival regex that matches
 * itself (string ".oo" matches regex ".oo").
 * kv1 and kv2 are added to the main config file.
 *
 * Expected: matching devices get props from both, kv2 taking precedence.
 *
 * Current: Devices get properties from kv2 only (kv1 and kv2 are not merged).
 */
static void test_2_ident_self_matching_re_hwe(void **state)
{
	const struct hwt_state *hwt;
	struct path *pp;
	const struct key_value kv1[] = { vnd__oo, prd_bar, prio_emc, chk_hp };
	const struct key_value kv2[] = { vnd__oo, prd_bar, prio_hds, gui_foo };

	hwt = CHECK_STATE(state);
	reset_vecs(hwt->vecs);
	WRITE_TWO_DEVICES(hwt, kv1, kv2);
	_conf = LOAD_CONFIG(hwt);

	/* foo:baz doesn't match */
	pp = mock_path(vnd_foo.value, prd_baz.value);
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, DEFAULT_CHECKER);

	/* foo:bar matches */
	pp = mock_path_flags(vnd_foo.value, prd_bar.value, USE_GETUID);
	TEST_PROP(prio_name(&pp->prio), prio_hds.value);
	TEST_PROP(pp->getuid, gui_foo.value);
	TEST_PROP_BROKEN(_checker, pp->checker.name,
			 DEFAULT_CHECKER, chk_hp.value);

	FREE_CONFIG(_conf);
}

/*
 * Two identical device entries kv1 and kv2, non-trival regex that doesn't
 * match itself (string "^.oo" doesn't match regex "^.oo").
 * kv1 is added to the main config file, kv2 to a config_dir file.
 * This case is more important as you may think, see above.
 *
 * Expected: matching devices get props from both, kv2 taking precedence.
 *
 * Current: devices get props from kv2 only.
 */
static void test_2_ident_not_self_matching_re_hwe_dir(void **state)
{
	const struct hwt_state *hwt;
	struct path *pp;
	const struct key_value kv1[] = { vnd_t_oo, prd_bar, prio_emc, chk_hp };
	const struct key_value kv2[] = { vnd_t_oo, prd_bar, prio_hds, gui_foo };

	hwt = CHECK_STATE(state);
	reset_vecs(hwt->vecs);
	WRITE_TWO_DEVICES_W_DIR(hwt, kv1, kv2);
	_conf = LOAD_CONFIG(hwt);

	/* foo:baz doesn't match */
	pp = mock_path(vnd_foo.value, prd_baz.value);
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, DEFAULT_CHECKER);

	/* foo:bar matches both, but only kv2 is seen */
	pp = mock_path_flags(vnd_foo.value, prd_bar.value, USE_GETUID);
	TEST_PROP(prio_name(&pp->prio), prio_hds.value);
	TEST_PROP(pp->getuid, gui_foo.value);
	TEST_PROP_BROKEN(_checker, pp->checker.name,
			 DEFAULT_CHECKER, chk_hp.value);

	FREE_CONFIG(_conf);
}

/*
 * Two different non-trivial regexes kv1, kv2. The 1st one matches the 2nd, but
 * it doesn't match all possible strings matching the second.
 * ("ba[zy]" matches regex "ba[[rxy]", but "baz" does not).
 * This causes the first entry to be merged into the second, but both entries
 * to be kept.
 *
 * Expected: Devices matching both regexes get properties from both, kv2
 * taking precedence. Devices matching just one regex get properties from
 * that one regex only.
 *
 * Current: behaves as expected, except for devices that match only kv2.
 * Those get properties from kv1, too.
 */
static void test_2_matching_res_hwe_dir(void **state)
{
	const struct hwt_state *hwt;
	struct path *pp;
	const struct key_value kv1[] = { vnd_foo, prd_barx,
					 prio_emc, chk_hp };
	const struct key_value kv2[] = { vnd_foo, prd_bazy,
					 prio_hds, gui_foo };

	hwt = CHECK_STATE(state);
	reset_vecs(hwt->vecs);
	WRITE_TWO_DEVICES_W_DIR(hwt, kv1, kv2);
	_conf = LOAD_CONFIG(hwt);

	/* foo:bar matches k1 only */
	pp = mock_path(vnd_foo.value, prd_bar.value);
	TEST_PROP(prio_name(&pp->prio), prio_emc.value);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, chk_hp.value);

	/* foo:bay matches k1 and k2 */
	pp = mock_path_flags(vnd_foo.value, "bay", USE_GETUID);
	TEST_PROP(prio_name(&pp->prio), prio_hds.value);
	TEST_PROP(pp->getuid, gui_foo.value);
	TEST_PROP(pp->checker.name, chk_hp.value);

	/*
	 * foo:baz matches k2 only. Yet it sees the value from k1,
	 * because k1 has beem merged into k2.
	 */
	pp = mock_path_flags(vnd_foo.value, prd_baz.value, USE_GETUID);
	TEST_PROP(prio_name(&pp->prio), prio_hds.value);
	TEST_PROP(pp->getuid, gui_foo.value);
	TEST_PROP_BROKEN(_checker, pp->checker.name,
			 chk_hp.value, DEFAULT_CHECKER);

	FREE_CONFIG(_conf);
}

/*
 * Two different non-trivial regexes which match the same set of strings.
 * But they don't match each other.
 * "baz" matches both regex "ba[zy]" and "ba(z|y)"
 *
 * Expected: matching devices get properties from both, kv2 taking precedence.
 *
 * Current: matching devices get properties from kv2 only.
 */
static void test_2_nonmatching_res_hwe_dir(void **state)
{
	const struct hwt_state *hwt;
	struct path *pp;
	const struct key_value kv1[] = { vnd_foo, prd_bazy,
					 prio_emc, chk_hp };
	const struct key_value kv2[] = { vnd_foo, prd_bazy1,
					 prio_hds, gui_foo };

	hwt = CHECK_STATE(state);
	reset_vecs(hwt->vecs);
	WRITE_TWO_DEVICES_W_DIR(hwt, kv1, kv2);
	_conf = LOAD_CONFIG(hwt);

	/* foo:bar doesn't match */
	pp = mock_path(vnd_foo.value, prd_bar.value);
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, DEFAULT_CHECKER);

	/*
	 * foo:baz matches k2 and k1. Yet it sees the value from k2 only.
	 */
	pp = mock_path_flags(vnd_foo.value, prd_baz.value, USE_GETUID);
	TEST_PROP(prio_name(&pp->prio), prio_hds.value);
	TEST_PROP(pp->getuid, gui_foo.value);
	TEST_PROP_BROKEN(_checker, pp->checker.name,
			 DEFAULT_CHECKER, chk_hp.value);

	FREE_CONFIG(_conf);
}

/*
 * Simple blacklist test.
 */
static void test_blacklist(void **state)
{
	const struct hwt_state *hwt;
	const struct key_value kv1[] = { vnd_foo, prd_bar };

	hwt = CHECK_STATE(state);
	reset_vecs(hwt->vecs);
	begin_config(hwt);
	begin_section_all(hwt, "blacklist");
	write_device(hwt->config_file, ARRAY_SIZE(kv1), kv1);
	end_section_all(hwt);
	finish_config(hwt);
	_conf = LOAD_CONFIG(hwt);

	mock_path_blacklisted(vnd_foo.value, prd_bar.value);
	mock_path(vnd_foo.value, prd_baz.value);

	FREE_CONFIG(_conf);
}

/*
 * Simple blacklist test with regex and exception
- */
static void test_blacklist_regex(void **state)
{
	const struct hwt_state *hwt;
	const struct key_value kv1[] = { vnd_foo, prd_ba_s };
	const struct key_value kv2[] = { vnd_foo, prd_bar };

	hwt = CHECK_STATE(state);
	reset_vecs(hwt->vecs);
	begin_config(hwt);
	begin_section_all(hwt, "blacklist");
	write_device(hwt->config_file, ARRAY_SIZE(kv1), kv1);
	end_section_all(hwt);
	begin_section_all(hwt, "blacklist_exceptions");
	write_device(hwt->conf_dir_file[0], ARRAY_SIZE(kv2), kv2);
	end_section_all(hwt);
	finish_config(hwt);
	_conf = LOAD_CONFIG(hwt);

	mock_path(vnd_foo.value, prd_bar.value);
	mock_path_blacklisted(vnd_foo.value, prd_baz.value);
	mock_path(vnd_foo.value, prd_bam.value);

	FREE_CONFIG(_conf);
}

/*
 * Simple blacklist test with regex and exception
 * config file order inverted wrt test_blacklist_regex
 */
static void test_blacklist_regex_inv(void **state)
{
	const struct hwt_state *hwt;
	const struct key_value kv1[] = { vnd_foo, prd_ba_s };
	const struct key_value kv2[] = { vnd_foo, prd_bar };

	hwt = CHECK_STATE(state);
	reset_vecs(hwt->vecs);
	begin_config(hwt);
	begin_section_all(hwt, "blacklist");
	write_device(hwt->conf_dir_file[0], ARRAY_SIZE(kv1), kv1);
	end_section_all(hwt);
	begin_section_all(hwt, "blacklist_exceptions");
	write_device(hwt->config_file, ARRAY_SIZE(kv2), kv2);
	end_section_all(hwt);
	finish_config(hwt);
	_conf = LOAD_CONFIG(hwt);

	mock_path(vnd_foo.value, prd_bar.value);
	mock_path_blacklisted(vnd_foo.value, prd_baz.value);
	mock_path(vnd_foo.value, prd_bam.value);

	FREE_CONFIG(_conf);
}

/*
 * Simple blacklist test with regex and exception
 * config file order inverted wrt test_blacklist_regex
 */
static void test_blacklist_regex_matching(void **state)
{
	const struct hwt_state *hwt;
	const struct key_value kv1[] = { vnd_foo, prd_barx };
	const struct key_value kv2[] = { vnd_foo, prd_bazy };

	hwt = CHECK_STATE(state);
	reset_vecs(hwt->vecs);
	begin_config(hwt);
	begin_section_all(hwt, "blacklist");
	write_device(hwt->config_file, ARRAY_SIZE(kv1), kv1);
	write_device(hwt->conf_dir_file[0], ARRAY_SIZE(kv2), kv2);
	end_section_all(hwt);
	finish_config(hwt);
	_conf = LOAD_CONFIG(hwt);

	mock_path_blacklisted(vnd_foo.value, prd_bar.value);
	mock_path_blacklisted(vnd_foo.value, prd_baz.value);
	mock_path(vnd_foo.value, prd_bam.value);

	FREE_CONFIG(_conf);
}

/*
 * Test for product_blacklist. Two entries blacklisting each other.
 *
 * Expected: Both are blacklisted.
 */
static void test_product_blacklist(void **state)
{
	const struct hwt_state *hwt;
	const struct key_value kv1[] = { vnd_foo, prd_bar, bl_baz };
	const struct key_value kv2[] = { vnd_foo, prd_baz, bl_bar };

	hwt = CHECK_STATE(state);
	reset_vecs(hwt->vecs);
	WRITE_TWO_DEVICES(hwt, kv1, kv2);
	_conf = LOAD_CONFIG(hwt);

	mock_path_blacklisted(vnd_foo.value, prd_baz.value);
	mock_path_blacklisted(vnd_foo.value, prd_bar.value);
	mock_path(vnd_foo.value, prd_bam.value);

	FREE_CONFIG(_conf);
}

/*
 * Test for product_blacklist. The second regex "matches" the first.
 * This is a pathological example.
 *
 * Expected: "foo:bar", "foo:baz" are blacklisted.
 *
 * Current: "foo:baz" is not blacklisted, because the two regexes are
 * merged into one.
 */
static void test_product_blacklist_matching(void **state)
{
	const struct hwt_state *hwt;
	const struct key_value kv1[] = { vnd_foo, prd_bar, bl_barx };
	const struct key_value kv2[] = { vnd_foo, prd_baz, bl_bazy };

	hwt = CHECK_STATE(state);
	reset_vecs(hwt->vecs);
	WRITE_TWO_DEVICES(hwt, kv1, kv2);
	_conf = LOAD_CONFIG(hwt);

	mock_path_blacklisted(vnd_foo.value, prd_bar.value);
#if BROKEN == 1
	condlog(1, "%s: WARNING: broken blacklist test on line %d",
		__func__, __LINE__+1);
	mock_path(vnd_foo.value, prd_baz.value);
#else
	mock_path_blacklisted(vnd_foo.value, prd_baz.value);
#endif
	mock_path(vnd_foo.value, prd_bam.value);

	FREE_CONFIG(_conf);
}

/*
 * Basic test for multipath-based configuration.
 *
 * Expected: properties, including pp->prio, are taken from multipath
 * section.
 */
static void test_multipath_config(void **state)
{
	const struct hwt_state *hwt;
	struct path *pp;
	struct multipath *mp;
	const struct key_value kvm[] = { wwid_test, prio_rdac, minio_99 };
	const struct key_value kvp[] = { vnd_foo, prd_bar, prio_emc, uid_baz };

	hwt = CHECK_STATE(state);
	reset_vecs(hwt->vecs);
	begin_config(hwt);
	begin_section_all(hwt, "devices");
	write_section(hwt->conf_dir_file[0], "device", ARRAY_SIZE(kvp), kvp);
	end_section_all(hwt);
	begin_section_all(hwt, "multipaths");
	write_section(hwt->config_file, "multipath", ARRAY_SIZE(kvm), kvm);
	end_section_all(hwt);
	finish_config(hwt);
	_conf = LOAD_CONFIG(hwt);

	pp = mock_path(vnd_foo.value, prd_bar.value);
	mp = mock_multipath(pp);
	assert_ptr_not_equal(mp, NULL);
	assert_ptr_not_equal(mp->mpe, NULL);
	TEST_PROP(prio_name(&pp->prio), prio_rdac.value);
	assert_int_equal(mp->minio, atoi(minio_99.value));
	TEST_PROP(pp->uid_attribute, uid_baz.value);

	/* test different wwid */
	pp = mock_path_wwid(vnd_foo.value, prd_bar.value, default_wwid_1);
	mp = mock_multipath(pp);
	assert_ptr_not_equal(mp, NULL);
	assert_ptr_equal(mp->mpe, NULL);
	TEST_PROP(prio_name(&pp->prio), prio_emc.value);
	assert_int_equal(mp->minio, DEFAULT_MINIO_RQ);
	TEST_PROP(pp->uid_attribute, uid_baz.value);

	FREE_CONFIG(_conf);
}

/*
 * Basic test for multipath-based configuration. Two sections for the same wwid.
 *
 * Expected: properties are taken from both multipath sections.
 */
static void test_multipath_config_2(void **state)
{
	const struct hwt_state *hwt;
	struct path *pp;
	struct multipath *mp;
	const struct key_value kv1[] = { wwid_test, prio_rdac, npr_queue };
	const struct key_value kv2[] = { wwid_test, minio_99, npr_37 };

	hwt = CHECK_STATE(state);
	reset_vecs(hwt->vecs);
	begin_config(hwt);
	begin_section_all(hwt, "multipaths");
	write_section(hwt->config_file, "multipath", ARRAY_SIZE(kv1), kv1);
	write_section(hwt->conf_dir_file[1], "multipath", ARRAY_SIZE(kv2), kv2);
	end_section_all(hwt);
	finish_config(hwt);
	_conf = LOAD_CONFIG(hwt);

	pp = mock_path(vnd_foo.value, prd_bar.value);
	mp = mock_multipath(pp);
	assert_ptr_not_equal(mp, NULL);
	assert_ptr_not_equal(mp->mpe, NULL);
	TEST_PROP(prio_name(&pp->prio), prio_rdac.value);
#if BROKEN
	condlog(1, "%s: WARNING: broken test on %d", __func__, __LINE__ + 1);
	assert_int_equal(mp->minio, DEFAULT_MINIO_RQ);
	condlog(1, "%s: WARNING: broken test on %d", __func__, __LINE__ + 1);
	assert_int_equal(mp->no_path_retry, NO_PATH_RETRY_QUEUE);
#else
	assert_int_equal(mp->minio, atoi(minio_99.value));
	assert_int_equal(mp->no_path_retry, atoi(npr_37.value));
#endif

	FREE_CONFIG(_conf);
}

/*
 * Same as test_multipath_config_2, both entries in the same config file.
 *
 * Expected: properties, are taken from both multipath sections.
 */
static void test_multipath_config_3(void **state)
{
	const struct hwt_state *hwt;
	struct path *pp;
	struct multipath *mp;
	const struct key_value kv1[] = { wwid_test, prio_rdac, npr_queue };
	const struct key_value kv2[] = { wwid_test, minio_99, npr_37 };

	hwt = CHECK_STATE(state);
	reset_vecs(hwt->vecs);
	begin_config(hwt);
	begin_section_all(hwt, "multipaths");
	write_section(hwt->config_file, "multipath", ARRAY_SIZE(kv1), kv1);
	write_section(hwt->config_file, "multipath", ARRAY_SIZE(kv2), kv2);
	end_section_all(hwt);
	finish_config(hwt);
	_conf = LOAD_CONFIG(hwt);

	pp = mock_path(vnd_foo.value, prd_bar.value);
	mp = mock_multipath(pp);
	assert_ptr_not_equal(mp, NULL);
	assert_ptr_not_equal(mp->mpe, NULL);
	TEST_PROP(prio_name(&pp->prio), prio_rdac.value);
#if BROKEN
	condlog(1, "%s: WARNING: broken test on %d", __func__, __LINE__ + 1);
	assert_int_equal(mp->minio, DEFAULT_MINIO_RQ);
	condlog(1, "%s: WARNING: broken test on %d", __func__, __LINE__ + 1);
	assert_int_equal(mp->no_path_retry, NO_PATH_RETRY_QUEUE);
#else
	assert_int_equal(mp->minio, atoi(minio_99.value));
	assert_int_equal(mp->no_path_retry, atoi(npr_37.value));
#endif

	FREE_CONFIG(_conf);
}

static int test_hwtable(void)
{
	const struct CMUnitTest tests[] = {
	cmocka_unit_test(test_sanity_globals),
		cmocka_unit_test(test_internal_nvme),
		cmocka_unit_test(test_string_hwe),
		cmocka_unit_test(test_regex_hwe),
		cmocka_unit_test(test_regex_string_hwe), 
		cmocka_unit_test(test_regex_string_hwe_dir),
		cmocka_unit_test(test_regex_2_strings_hwe_dir),
		cmocka_unit_test(test_string_regex_hwe_dir),
		cmocka_unit_test(test_2_ident_strings_hwe),
		cmocka_unit_test(test_2_ident_strings_both_dir),
		cmocka_unit_test(test_2_ident_strings_both_dir_w_prev),
		cmocka_unit_test(test_2_ident_strings_hwe_dir),
		cmocka_unit_test(test_3_ident_strings_hwe_dir),
		cmocka_unit_test(test_2_ident_self_matching_re_hwe),
		cmocka_unit_test(test_2_ident_self_matching_re_hwe_dir),
		cmocka_unit_test(test_2_ident_not_self_matching_re_hwe_dir),
		cmocka_unit_test(test_2_matching_res_hwe_dir),
		cmocka_unit_test(test_2_nonmatching_res_hwe_dir),
		cmocka_unit_test(test_blacklist),
		cmocka_unit_test(test_blacklist_regex),
		cmocka_unit_test(test_blacklist_regex_inv),
		cmocka_unit_test(test_blacklist_regex_matching),
		cmocka_unit_test(test_product_blacklist),
		cmocka_unit_test(test_product_blacklist_matching),
		cmocka_unit_test(test_multipath_config),
		cmocka_unit_test(test_multipath_config_2),
		cmocka_unit_test(test_multipath_config_3),
	};

	return cmocka_run_group_tests(tests, setup, teardown);
}

int main(void)
{
	int ret = 0;

	ret += test_hwtable();
	return ret;
}
