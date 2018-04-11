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

struct key_value {
	const char *key;
	char *value;
};

struct hwt_state {
	char *tmpname;
	char *dirname;
	FILE *config_file;
	FILE *conf_dir_file[N_CONF_FILES];
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

	for (i = 0; i < nkv; i++)
		fprintf(ff, "\t%s \"%s\"\n", kv[i].key, kv[i].value);
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
	static struct key_value defaults[] = {
		{ "config_dir", NULL },
		{ "detect_prio", "no" },
		{ "detect_checker", "no" },
	};

	defaults[0].value = hwt->dirname;
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

static const char _vendor[] = "vendor";
static const char _product[] = "product";
static const char _prio[] = "prio";
static const char _checker[] = "path_checker";
static const char _getuid[] = "getuid_callout";
static const char _uid_attr[] = "uid_attribute";

/* Device identifiers */
static const struct key_value vnd_foo = { _vendor, "foo" };
static const struct key_value prd_bar = { _product, "bar" };
static const struct key_value prd_barz = { _product, "barz" };
static const struct key_value vnd_boo = { _vendor, "boo" };
static const struct key_value prd_baz = { _product, "baz" };

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

bool __wrap_is_claimed_by_foreign(struct udev_device *ud)
{
	condlog(5, "%s: %p", __func__, ud);
	return false;
}

int __wrap_filter_property(struct config *conf, struct udev_device *ud)
{
	condlog(5, "%s: %p", __func__, ud);
	return 0;
}

int __wrap_filter_devnode(vector blist, vector elist, char *dev)
{
	condlog(5, "%s: %p", __func__, dev);
	return 0;
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

/*
 * Pretent we detected a SCSI device with given vendor/prod/rev
 */
static struct path *mock_path(const char *vendor, const char *prod,
			      const char *rev)
{
	const char hbtl[] = "4:0:3:1";
	struct path *pp;
	struct config *conf;

	pp = alloc_path();
	assert_ptr_not_equal(pp, NULL);

	pp->udev = (void *)pp; /* fake non-NULL udev */
	pp->detect_prio = DETECT_PRIO_OFF;
	pp->detect_checker = DETECT_CHECKER_OFF;
	strlcpy(pp->dev, "sdTEST", sizeof(pp->dev));
	strlcpy(pp->wwid, "TEST-WWID", sizeof(pp->wwid));

	/* scsi_sysfs_pathinfo */
	will_return(__wrap_udev_device_get_subsystem, "scsi");
	will_return(__wrap_udev_device_get_sysname, hbtl);
	will_return(__wrap_udev_device_get_sysname, hbtl);
	will_return(__wrap_udev_device_get_sysattr_value, vendor);
	will_return(__wrap_udev_device_get_sysname, hbtl);
	will_return(__wrap_udev_device_get_sysattr_value, prod);
	will_return(__wrap_udev_device_get_sysname, hbtl);
	will_return(__wrap_udev_device_get_sysattr_value, rev);

	/* sysfs_get_tgt_nodename */
	will_return(__wrap_udev_device_get_sysattr_value, NULL);
	will_return(__wrap_udev_device_get_parent, NULL);
	will_return(__wrap_udev_device_get_parent, NULL);
	will_return(__wrap_udev_device_get_sysname, "nofibre");
	will_return(__wrap_udev_device_get_sysname, "noiscsi");
	will_return(__wrap_udev_device_get_parent, NULL);
	will_return(__wrap_udev_device_get_sysname, "ata25");

	/* path_offline */
	will_return(__wrap_udev_device_get_subsystem, "scsi");
	will_return(__wrap_sysfs_attr_get_value, "running");

	conf = get_multipath_config();
	assert_int_equal(pathinfo(pp, conf, DI_SYSFS|DI_NOIO), PATHINFO_OK);
	select_prio(conf, pp);
	select_getuid(conf, pp);

	/* sysfs_get_timeout */
	will_return(__wrap_udev_device_get_subsystem, "scsi");
	will_return(__wrap_udev_device_get_sysattr_value, "180");
	select_checker(conf, pp);
	put_multipath_config(conf);

	return pp;
}

static struct multipath *mock_multipath(struct path *pp)
{
	struct multipath *mp = alloc_multipath();
	struct config *conf;

	if (!mp)
		return NULL;
	mp->alias = strdup("mppTEST");
	mp->paths = vector_alloc();
	if (mp->paths == NULL || mp->alias == NULL)
		goto out_free;
	if (vector_alloc_slot(mp->paths) == NULL)
		goto out_free;

	vector_set_slot(mp->paths, pp);
	extract_hwe_from_path(mp);
	if (mp->hwe == NULL)
		goto out_free;

	conf = get_multipath_config();
	select_pgpolicy(conf, mp);
	select_no_path_retry(conf, mp);
	select_retain_hwhandler(conf, mp);
	put_multipath_config(conf);
	return mp;

out_free:
	free_multipath(mp, KEEP_PATHS);
	return NULL;
}

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
	WRITE_EMPTY_CONF(hwt);
	_conf = LOAD_CONFIG(hwt);

	/*
	 * Generic NVMe: expect defaults for pgpolicy and no_path_retry
	 */
	pp = mock_path("NVME", "NoName", "0");
	mp = mock_multipath(pp);
	assert_ptr_not_equal(mp, NULL);
	TEST_PROP(pp->checker.name, NONE);
	TEST_PROP(pp->uid_attribute, "ID_WWN");
	assert_int_equal(mp->pgpolicy, DEFAULT_PGPOLICY);
	assert_int_equal(mp->no_path_retry, DEFAULT_NO_PATH_RETRY);
	assert_int_equal(mp->retain_hwhandler, RETAIN_HWHANDLER_OFF);
	free_multipath(mp, FREE_PATHS);

	/*
	 * NetApp NVMe: expect special values for pgpolicy and no_path_retry
	 */
	pp = mock_path("NVME", "NetApp ONTAP Controller", "0");
	mp = mock_multipath(pp);
	assert_ptr_not_equal(mp, NULL);
	TEST_PROP(pp->checker.name, NONE);
	TEST_PROP(pp->uid_attribute, "ID_WWN");
	assert_int_equal(mp->pgpolicy, MULTIBUS);
	assert_int_equal(mp->no_path_retry, NO_PATH_RETRY_QUEUE);
	assert_int_equal(mp->retain_hwhandler, RETAIN_HWHANDLER_OFF);
	free_multipath(mp, FREE_PATHS);

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
	pp = mock_path(vnd_foo.value, prd_bar.value, "0");
	TEST_PROP(prio_name(&pp->prio), kv[2].value);
	free_path(pp);

	/* foo:baz doesn't match */
	pp = mock_path(vnd_foo.value, prd_baz.value, "0");
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);
	free_path(pp);

	/* boo:bar doesn't match */
	pp = mock_path(vnd_boo.value, prd_bar.value, "0");
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);
	free_path(pp);

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
	WRITE_ONE_DEVICE(hwt, kv);
	_conf = LOAD_CONFIG(hwt);

	/* foo:bar matches */
	pp = mock_path(vnd_foo.value, prd_bar.value, "0");
	TEST_PROP(prio_name(&pp->prio), kv[2].value);
	free_path(pp);

	/* foo:baz matches */
	pp = mock_path(vnd_foo.value, prd_baz.value, "0");
	TEST_PROP(prio_name(&pp->prio), kv[2].value);
	free_path(pp);

	/* boo:baz matches */
	pp = mock_path(vnd_boo.value, prd_bar.value, "0");
	TEST_PROP(prio_name(&pp->prio), kv[2].value);
	free_path(pp);

	/* foo:BAR doesn't match */
	pp = mock_path(vnd_foo.value, "BAR", "0");
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);
	free_path(pp);

	/* bboo:bar doesn't match */
	pp = mock_path("bboo", prd_bar.value, "0");
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);
	free_path(pp);

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
	WRITE_TWO_DEVICES(hwt, kv1, kv2);
	_conf = LOAD_CONFIG(hwt);

	/* foo:baz matches kv1 */
	pp = mock_path(vnd_foo.value, prd_baz.value, "0");
	TEST_PROP(prio_name(&pp->prio), kv1[2].value);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, kv1[3].value);
	free_path(pp);

	/* boo:baz matches kv1 */
	pp = mock_path(vnd_boo.value, prd_baz.value, "0");
	TEST_PROP(prio_name(&pp->prio), kv1[2].value);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, kv1[3].value);
	free_path(pp);

	/* .oo:ba. matches kv1 */
	pp = mock_path(vnd__oo.value, prd_ba_.value, "0");
	TEST_PROP(prio_name(&pp->prio), kv1[2].value);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, kv1[3].value);
	free_path(pp);

	/* .foo:(bar|baz|ba\.) doesn't match */
	pp = mock_path(vnd__oo.value, prd_ba_s.value, "0");
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, DEFAULT_CHECKER);
	free_path(pp);

	/* foo:bar matches kv2 and kv1 */
	pp = mock_path(vnd_foo.value, prd_bar.value, "0");
	TEST_PROP(prio_name(&pp->prio), kv2[2].value);
	TEST_PROP(pp->getuid, kv2[3].value);
	/*
	 * You'd expect that the two entries above be merged,
	 * but that isn't the case if they're in the same input file.
	 */
	TEST_PROP_BROKEN(_checker, pp->checker.name,
			 DEFAULT_CHECKER, kv1[3].value);
	free_path(pp);

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
	WRITE_TWO_DEVICES_W_DIR(hwt, kv1, kv2);
	_conf = LOAD_CONFIG(hwt);

	/* foo:baz matches kv1 */
	pp = mock_path(vnd_foo.value, prd_baz.value, "0");
	TEST_PROP(prio_name(&pp->prio), kv1[2].value);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, kv1[3].value);
	free_path(pp);

	/* boo:baz matches kv1 */
	pp = mock_path(vnd_boo.value, prd_baz.value, "0");
	TEST_PROP(prio_name(&pp->prio), kv1[2].value);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, kv1[3].value);
	free_path(pp);

	/* .oo:ba. matches kv1 */
	pp = mock_path(vnd__oo.value, prd_ba_.value, "0");
	TEST_PROP(prio_name(&pp->prio), kv1[2].value);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, kv1[3].value);
	free_path(pp);

	/* .oo:(bar|baz|ba\.)$ doesn't match */
	pp = mock_path(vnd__oo.value, prd_ba_s.value, "0");
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, DEFAULT_CHECKER);
	free_path(pp);

	/* foo:bar matches kv2 */
	pp = mock_path(vnd_foo.value, prd_bar.value, "0");
	/* Later match takes prio */
	TEST_PROP(prio_name(&pp->prio), kv2[2].value);
	TEST_PROP(pp->getuid, kv2[3].value);
	/* This time it's merged */
	TEST_PROP(pp->checker.name, kv1[3].value);
	free_path(pp);

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
	const struct key_value kv3[] =
		{ vnd_foo, prd_barz, prio_rdac, gui_foo };

	hwt = CHECK_STATE(state);
	begin_config(hwt);
	begin_section_all(hwt, "devices");
	write_device(hwt->config_file, ARRAY_SIZE(kv1), kv1);
	write_device(hwt->conf_dir_file[0], ARRAY_SIZE(kv2), kv2);
	write_device(hwt->conf_dir_file[1], ARRAY_SIZE(kv3), kv3);
	end_section_all(hwt);
	finish_config(hwt);
	_conf = LOAD_CONFIG(hwt);

	/* foo:baz matches kv1 */
	pp = mock_path(vnd_foo.value, prd_baz.value, "0");
	TEST_PROP(prio_name(&pp->prio), kv1[2].value);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->uid_attribute, DEFAULT_UID_ATTRIBUTE);
	TEST_PROP(pp->checker.name, kv1[3].value);
	free_path(pp);

	/* boo:baz doesn't match */
	pp = mock_path(vnd_boo.value, prd_baz.value, "0");
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->uid_attribute, DEFAULT_UID_ATTRIBUTE);
	TEST_PROP(pp->checker.name, DEFAULT_CHECKER);
	free_path(pp);

	/* foo:bar matches kv2 and kv1 */
	pp = mock_path(vnd_foo.value, prd_bar.value, "0");
	TEST_PROP(prio_name(&pp->prio), kv2[2].value);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->uid_attribute, kv2[3].value);
	TEST_PROP(pp->checker.name, kv1[3].value);
	free_path(pp);

	/* foo:barz matches kv3 and kv2 and kv1 */
	pp = mock_path(vnd_foo.value, prd_barz.value, "0");
	TEST_PROP(prio_name(&pp->prio), kv3[2].value);
	TEST_PROP(pp->getuid, kv3[3].value);
	TEST_PROP(pp->uid_attribute, NULL);
	TEST_PROP(pp->checker.name, kv1[3].value);
	free_path(pp);

	FREE_CONFIG(_conf);
}

/*
 * Like test_regex_string_hwe_dir, but kv1 and kv2 are exchanged.
 *
 * Expected: Devices matching kv1 (and thus, both) get properties
 * from both, kv2 taking precedence.
 * Devices matching kv2 only just get props from kv2.
 *
 * Current: kv1 never matches, because kv2 is more generic and encountered
 * first; thus properties from kv1 aren't used.
 */
static void test_string_regex_hwe_dir(void **state)
{
	const struct hwt_state *hwt;
	struct path *pp;
	const struct key_value kv1[] = { vnd_foo, prd_bar, prio_hds, gui_foo };
	const struct key_value kv2[] = { vnd_t_oo, prd_ba_s, prio_emc, chk_hp };

	hwt = CHECK_STATE(state);
	WRITE_TWO_DEVICES_W_DIR(hwt, kv1, kv2);
	_conf = LOAD_CONFIG(hwt);

	/* foo:bar matches kv2 and kv1 */
	pp = mock_path(vnd_foo.value, prd_bar.value, "0");
	TEST_PROP(prio_name(&pp->prio), kv2[2].value);
	TEST_PROP_BROKEN(_getuid, pp->getuid, (char*)NULL, kv1[3].value);
	TEST_PROP(pp->checker.name, kv2[3].value);
	free_path(pp);

	/* foo:baz matches kv2 */
	pp = mock_path(vnd_foo.value, prd_baz.value, "0");
	TEST_PROP(prio_name(&pp->prio), kv2[2].value);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, kv2[3].value);
	free_path(pp);

	/* boo:baz matches kv2 */
	pp = mock_path(vnd_boo.value, prd_baz.value, "0");
	TEST_PROP(prio_name(&pp->prio), kv2[2].value);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, kv2[3].value);
	free_path(pp);

	/* .oo:ba. matches kv2 */
	pp = mock_path(vnd__oo.value, prd_ba_.value, "0");
	TEST_PROP(prio_name(&pp->prio), kv2[2].value);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, kv2[3].value);
	free_path(pp);

	/* .oo:(bar|baz|ba\.)$ doesn't match */
	pp = mock_path(vnd__oo.value, prd_ba_s.value, "0");
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, DEFAULT_CHECKER);
	free_path(pp);

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
	WRITE_TWO_DEVICES(hwt, kv1, kv2);
	_conf = LOAD_CONFIG(hwt);

	/* foo:baz doesn't match */
	pp = mock_path(vnd_foo.value, prd_baz.value, "0");
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, DEFAULT_CHECKER);
	free_path(pp);

	/* foo:bar matches both, but only kv2 is seen */
	pp = mock_path(vnd_foo.value, prd_bar.value, "0");
	TEST_PROP(prio_name(&pp->prio), kv2[2].value);
	TEST_PROP(pp->getuid, kv2[3].value);
	TEST_PROP_BROKEN(_checker, pp->checker.name,
			 DEFAULT_CHECKER, kv1[3].value);
	free_path(pp);

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
	begin_config(hwt);
	begin_section_all(hwt, "devices");
	write_device(hwt->conf_dir_file[1], ARRAY_SIZE(kv1), kv1);
	write_device(hwt->conf_dir_file[1], ARRAY_SIZE(kv2), kv2);
	end_section_all(hwt);
	finish_config(hwt);
	_conf = LOAD_CONFIG(hwt);

	/* foo:baz doesn't match */
	pp = mock_path(vnd_foo.value, prd_baz.value, "0");
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, DEFAULT_CHECKER);
	free_path(pp);

	/* foo:bar matches both */
	pp = mock_path(vnd_foo.value, prd_bar.value, "0");
	TEST_PROP(prio_name(&pp->prio), kv2[2].value);
	TEST_PROP(pp->getuid, kv2[3].value);
	TEST_PROP_BROKEN(_checker, pp->checker.name,
			 DEFAULT_CHECKER, kv1[3].value);
	free_path(pp);

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
	begin_config(hwt);
	begin_section_all(hwt, "devices");
	write_device(hwt->config_file, ARRAY_SIZE(kv0), kv0);
	write_device(hwt->conf_dir_file[1], ARRAY_SIZE(kv1), kv1);
	write_device(hwt->conf_dir_file[1], ARRAY_SIZE(kv2), kv2);
	end_section_all(hwt);
	finish_config(hwt);
	_conf = LOAD_CONFIG(hwt);

	/* foo:baz doesn't match */
	pp = mock_path(vnd_foo.value, prd_baz.value, "0");
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, DEFAULT_CHECKER);
	free_path(pp);

	/* foo:bar matches both */
	pp = mock_path(vnd_foo.value, prd_bar.value, "0");
	TEST_PROP(prio_name(&pp->prio), kv2[2].value);
	TEST_PROP(pp->getuid, kv2[3].value);
	TEST_PROP_BROKEN(_checker, pp->checker.name,
			 DEFAULT_CHECKER, kv1[3].value);
	free_path(pp);

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
	WRITE_TWO_DEVICES_W_DIR(hwt, kv1, kv2);
	_conf = LOAD_CONFIG(hwt);

	/* foo:baz doesn't match */
	pp = mock_path(vnd_foo.value, prd_baz.value, "0");
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, DEFAULT_CHECKER);
	free_path(pp);

	/* foo:bar matches both */
	pp = mock_path(vnd_foo.value, prd_bar.value, "0");
	TEST_PROP(prio_name(&pp->prio), kv2[2].value);
	TEST_PROP(pp->getuid, kv2[3].value);
	TEST_PROP(pp->checker.name, kv1[3].value);
	free_path(pp);

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
	begin_config(hwt);
	begin_section_all(hwt, "devices");
	write_device(hwt->config_file, ARRAY_SIZE(kv1), kv1);
	write_device(hwt->conf_dir_file[1], ARRAY_SIZE(kv0), kv0);
	write_device(hwt->conf_dir_file[1], ARRAY_SIZE(kv2), kv2);
	end_section_all(hwt);
	finish_config(hwt);
	_conf = LOAD_CONFIG(hwt);

	/* foo:baz doesn't match */
	pp = mock_path(vnd_foo.value, prd_baz.value, "0");
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, DEFAULT_CHECKER);
	free_path(pp);

	/* foo:bar matches both */
	pp = mock_path(vnd_foo.value, prd_bar.value, "0");
	TEST_PROP(prio_name(&pp->prio), kv2[2].value);
	TEST_PROP(pp->getuid, kv2[3].value);
	TEST_PROP_BROKEN(_checker, pp->checker.name,
			 DEFAULT_CHECKER, kv1[3].value);
	free_path(pp);

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
	WRITE_TWO_DEVICES_W_DIR(hwt, kv1, kv2);
	_conf = LOAD_CONFIG(hwt);

	/* foo:baz doesn't match */
	pp = mock_path(vnd_foo.value, prd_baz.value, "0");
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, DEFAULT_CHECKER);
	free_path(pp);

	/* foo:bar matches both */
	pp = mock_path(vnd_foo.value, prd_bar.value, "0");
	TEST_PROP(prio_name(&pp->prio), kv2[2].value);
	TEST_PROP(pp->getuid, kv2[3].value);
	TEST_PROP(pp->checker.name, kv1[3].value);
	free_path(pp);

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
	WRITE_TWO_DEVICES(hwt, kv1, kv2);
	_conf = LOAD_CONFIG(hwt);

	/* foo:baz doesn't match */
	pp = mock_path(vnd_foo.value, prd_baz.value, "0");
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, DEFAULT_CHECKER);
	free_path(pp);

	/* foo:bar matches */
	pp = mock_path(vnd_foo.value, prd_bar.value, "0");
	TEST_PROP(prio_name(&pp->prio), kv2[2].value);
	TEST_PROP(pp->getuid, kv2[3].value);
	TEST_PROP_BROKEN(_checker, pp->checker.name,
			 DEFAULT_CHECKER, kv1[3].value);
	free_path(pp);

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
	WRITE_TWO_DEVICES_W_DIR(hwt, kv1, kv2);
	_conf = LOAD_CONFIG(hwt);

	/* foo:baz doesn't match */
	pp = mock_path(vnd_foo.value, prd_baz.value, "0");
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, DEFAULT_CHECKER);
	free_path(pp);

	/* foo:bar matches both, but only kv2 is seen */
	pp = mock_path(vnd_foo.value, prd_bar.value, "0");
	TEST_PROP(prio_name(&pp->prio), kv2[2].value);
	TEST_PROP(pp->getuid, kv2[3].value);
	TEST_PROP_BROKEN(_checker, pp->checker.name,
			 DEFAULT_CHECKER, kv1[3].value);
	free_path(pp);

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
	WRITE_TWO_DEVICES_W_DIR(hwt, kv1, kv2);
	_conf = LOAD_CONFIG(hwt);

	/* foo:bar matches k1 only */
	pp = mock_path(vnd_foo.value, prd_bar.value, "0");
	TEST_PROP(prio_name(&pp->prio), kv1[2].value);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, kv1[3].value);
	free_path(pp);

	/* foo:bay matches k1 and k2 */
	pp = mock_path(vnd_foo.value, "bay", "0");
	TEST_PROP(prio_name(&pp->prio), kv2[2].value);
	TEST_PROP(pp->getuid, kv2[3].value);
	TEST_PROP(pp->checker.name, kv1[3].value);
	free_path(pp);

	/*
	 * foo:baz matches k2 only. Yet it sees the value from k1,
	 * because k1 has beem merged into k2.
	 */
	pp = mock_path(vnd_foo.value, prd_baz.value, "0");
	TEST_PROP(prio_name(&pp->prio), kv2[2].value);
	TEST_PROP(pp->getuid, kv2[3].value);
	TEST_PROP_BROKEN(_checker, pp->checker.name,
			 kv1[3].value, DEFAULT_CHECKER);
	free_path(pp);

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
	WRITE_TWO_DEVICES_W_DIR(hwt, kv1, kv2);
	_conf = LOAD_CONFIG(hwt);

	/* foo:bar doesn't match */
	pp = mock_path(vnd_foo.value, prd_bar.value, "0");
	TEST_PROP(prio_name(&pp->prio), DEFAULT_PRIO);
	TEST_PROP(pp->getuid, NULL);
	TEST_PROP(pp->checker.name, DEFAULT_CHECKER);
	free_path(pp);

	/*
	 * foo:baz matches k2 and k1. Yet it sees the value from k2 only.
	 */
	pp = mock_path(vnd_foo.value, prd_baz.value, "0");
	TEST_PROP(prio_name(&pp->prio), kv2[2].value);
	TEST_PROP(pp->getuid, kv2[3].value);
	TEST_PROP_BROKEN(_checker, pp->checker.name,
			 DEFAULT_CHECKER, kv1[3].value);
	free_path(pp);

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
	};

	return cmocka_run_group_tests(tests, setup, teardown);
}

int main(void)
{
	int ret = 0;

	ret += test_hwtable();
	return ret;
}
