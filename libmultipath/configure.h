/*
 * configurator actions
 */
#define ACT_NOTHING_STR         "unchanged"
#define ACT_REJECT_STR          "reject"
#define ACT_RELOAD_STR          "reload"
#define ACT_SWITCHPG_STR        "switchpg"
#define ACT_RENAME_STR          "rename"
#define ACT_CREATE_STR          "create"
#define ACT_RESIZE_STR          "resize"

enum actions {
	ACT_UNDEF,
	ACT_NOTHING,
	ACT_REJECT,
	ACT_RELOAD,
	ACT_SWITCHPG,
	ACT_RENAME,
	ACT_CREATE,
	ACT_RESIZE,
	ACT_FORCERENAME,
	ACT_DRY_RUN,
	ACT_IMPOSSIBLE,
};

#define FLUSH_ONE 1
#define FLUSH_ALL 2

struct vectors;

int setup_map (struct multipath * mpp, char * params, int params_size,
	       struct vectors *vecs );
int domap (struct multipath * mpp, char * params, int is_daemon);
int reinstate_paths (struct multipath *mpp);
int coalesce_paths (struct vectors *vecs, vector curmp, char * refwwid, int force_reload, enum mpath_cmds cmd);
int get_refwwid (enum mpath_cmds cmd, char * dev, enum devtypes dev_type,
		 vector pathvec, char **wwid);
int reload_map(struct vectors *vecs, struct multipath *mpp, int refresh, int is_daemon);
struct udev_device *get_udev_device(const char *dev, enum devtypes dev_type);
void trigger_paths_udev_change(struct multipath *mpp, bool is_mpath);
