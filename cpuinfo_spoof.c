// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/utsname.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/cpufreq.h>
#include <linux/rwsem.h>
#include <linux/build_bug.h>
#include "kirin9020.h"

#define REVISION "qilin-r3-20261027"
#define TARGET_RELEASE "5.15.167-android13-8-o-01144-gb3f32e037fab"
#define MAX_PATCHES 12

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("cpuinfo_spoof staged diagnostic " REVISION);
MODULE_VERSION(REVISION);
/* Removed by fix_vermagic.py after fitting the new .modinfo entries. */
MODULE_INFO(qilin_modinfo_reserve, "................................................................................................");

extern struct uts_namespace init_uts_ns;

/* Target-device BTF contract. Refuse a DDK layout that changes these fields. */
static_assert(sizeof(void *) == 8);
static_assert(sizeof(struct device_attribute) == 32);
static_assert(sizeof(struct freq_attr) == 32);
static_assert(offsetof(struct device_attribute, show) == 16);
static_assert(offsetof(struct freq_attr, show) == 16);
static_assert(offsetof(struct device, id) == 772);
static_assert(offsetof(struct uts_namespace, name) == 0);

static char *stage = "inspect";
module_param(stage, charp, 0444);
static bool pointer_tests;
module_param(pointer_tests, bool, 0444);
/* Recognize old invocations but reject them rather than enable several paths. */
static int spoof_enable, spoof_uts, spoof_cpuinfo, spoof_online;
static int spoof_topology, spoof_cpufreq, spoof_related, spoof_affinity;
module_param(spoof_enable, int, 0444);
module_param(spoof_uts, int, 0444);
module_param(spoof_cpuinfo, int, 0444);
module_param(spoof_online, int, 0444);
module_param(spoof_topology, int, 0444);
module_param(spoof_cpufreq, int, 0444);
module_param(spoof_related, int, 0444);
module_param(spoof_affinity, int, 0444);

static unsigned long (*lookup_fn)(const char *);
static unsigned long data_start, data_end, ro_start, ro_end;
static struct rw_semaphore *target_uts_sem;
static struct proc_dir_entry *control;
static unsigned int planned, applied;
static int last_error;
static int check_cpus = -EAGAIN, check_topology = -EAGAIN, check_cpufreq = -EAGAIN;
static bool pinned;
static char outcome[32] = "inspect_only";
static char original_release[__NEW_UTS_LEN + 1];

struct patch {
	void **slot;
	void *before;
	void *after;
	const char *name;
};
static struct patch patches[MAX_PATCHES];

/* register_kprobe yields a raw function entry, not a canonical CFI jump-table
 * pointer. Limit nocfi to this one precisely typed resolver call. Callback
 * type checks remain enabled; no kernel instructions or CFI tables are edited.
 */
static noinline unsigned long __nocfi resolve(const char *name)
{
	return lookup_fn(name);
}

static int resolver_init(void)
{
	struct kprobe probe = { .symbol_name = "kallsyms_lookup_name" };
	int ret = register_kprobe(&probe);

	if (ret)
		return ret;
	lookup_fn = (void *)probe.addr;
	unregister_kprobe(&probe);
	if (!lookup_fn)
		return -ENOENT;
	if (resolve("init_uts_ns") != (unsigned long)&init_uts_ns)
		return -ESTALE;
	data_start = resolve("_sdata");
	data_end = resolve("_edata");
	ro_start = resolve("__start_rodata");
	ro_end = resolve("__end_rodata");
	if (!data_start || data_end <= data_start || !ro_start || ro_end <= ro_start)
		return -EINVAL;
	pr_info("cpuinfo_spoof: data=[%px,%px) rodata=[%px,%px)\n",
		(void *)data_start, (void *)data_end, (void *)ro_start, (void *)ro_end);
	return 0;
}

static bool writable_profile(unsigned long address, size_t length)
{
	/* Conservative target-image range check, not a page-table permission test.
	 * No fallback to set_memory_rw, update_mapping_prot, or bind mounts.
	 */
	return length && address >= data_start && address < data_end &&
		length <= data_end - address &&
		!(address < ro_end && address + length > ro_start);
}

static int read_name(const char *source, char *dest, size_t capacity)
{
	size_t i;

	if (!source)
		return -EINVAL;
	for (i = 0; i < capacity; i++) {
		if (copy_from_kernel_nofault(dest + i, source + i, 1))
			return -EFAULT;
		if (!dest[i])
			return 0;
	}
	return -ENAMETOOLONG;
}

static bool callback_named(void *address, const char *expected)
{
	char symbol[160];
	snprintf(symbol, sizeof(symbol), "%ps", address);
	if (!strcmp(symbol, expected))
		return true;
	return !strncmp(symbol, expected, strlen(expected)) &&
		!strcmp(symbol + strlen(expected), ".cfi_jt");
}

static int plan_patch(void **slot, void *old, void *replacement,
		      const char *name, const char *callback)
{
	if (planned >= MAX_PATCHES || !old || !replacement)
		return -EINVAL;
	if (!writable_profile((unsigned long)slot, sizeof(*slot)) ||
	    !IS_ALIGNED((unsigned long)slot, sizeof(*slot)))
		return -EACCES;
	if (!callback_named(old, callback)) {
		pr_err("cpuinfo_spoof: REJECT %s callback=%ps expected=%s\n",
			name, old, callback);
		return -EPROTOTYPE;
	}
	patches[planned++] = (struct patch) {
		.slot = slot, .before = old, .after = replacement, .name = name,
	};
	pr_info("cpuinfo_spoof: PREPARED %s original=%ps slot=%px\n", name, old, slot);
	return 0;
}

static ssize_t fake_cpu_mask(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	(void)dev; (void)attr;
	return sysfs_emit(buf, "0-%d\n", FAKE_N_CPUS - 1);
}

static ssize_t fake_topology(struct device *dev, struct device_attribute *attr,
			    char *buf)
{
	int cpu = dev->id;

	if (cpu < 0 || cpu >= FAKE_N_CPUS)
		return -EINVAL;
	if (!strcmp(attr->attr.name, "core_id"))
		return sysfs_emit(buf, "%d\n", fake_core_id[cpu]);
	if (!strcmp(attr->attr.name, "physical_package_id"))
		return sysfs_emit(buf, "%d\n", fake_pkg_id[cpu]);
	if (!strcmp(attr->attr.name, "die_id"))
		return sysfs_emit(buf, "%d\n", FAKE_DIE_ID);
	return -EINVAL;
}

/* These are freq_attr callbacks, not device_attribute callbacks. */
static ssize_t fake_available(struct cpufreq_policy *policy, char *buf)
{
	(void)policy;
	return sysfs_emit(buf, "%s\n", FAKE_AVAIL_FREQS);
}

static ssize_t fake_boost(struct cpufreq_policy *policy, char *buf)
{
	(void)policy;
	return sysfs_emit(buf, "%s\n", FAKE_BOOST_FREQS);
}

static_assert(__same_type(((struct freq_attr *)0)->show, &fake_available));
static_assert(__same_type(((struct freq_attr *)0)->show, &fake_boost));
static_assert(__same_type(((struct device_attribute *)0)->show, &fake_cpu_mask));
static_assert(__same_type(((struct device_attribute *)0)->show, &fake_topology));

static int plan_device(struct device_attribute *object, const char *name,
		       const char *expected,
		       ssize_t (*replacement)(struct device *, struct device_attribute *, char *))
{
	struct device_attribute snapshot;
	char actual[64];
	int ret;

	if (!writable_profile((unsigned long)object, sizeof(snapshot)))
		return -EACCES;
	ret = copy_from_kernel_nofault(&snapshot, object, sizeof(snapshot));
	if (ret)
		return ret;
	ret = read_name(snapshot.attr.name, actual, sizeof(actual));
	if (ret || strcmp(actual, name))
		return ret ? ret : -EINVAL;
	return plan_patch((void **)&object->show, (void *)snapshot.show,
		(void *)replacement, name, expected);
}

static int plan_frequency(const char *symbol, const char *name,
			  const char *expected,
			  ssize_t (*replacement)(struct cpufreq_policy *, char *))
{
	struct freq_attr *object = (void *)resolve(symbol);
	struct freq_attr snapshot;
	char actual[64];
	int ret;

	if (!writable_profile((unsigned long)object, sizeof(snapshot)))
		return -EACCES;
	ret = copy_from_kernel_nofault(&snapshot, object, sizeof(snapshot));
	if (ret)
		return ret;
	ret = read_name(snapshot.attr.name, actual, sizeof(actual));
	if (ret || strcmp(actual, name))
		return ret ? ret : -EINVAL;
	return plan_patch((void **)&object->show, (void *)snapshot.show,
		(void *)replacement, name, expected);
}

static int plan_cpu_roots(void)
{
	/* Enumerate the CPU root group's real attribute objects. In this target,
	 * online/possible/present are entries of cpu_attrs (dev_ext_attribute),
	 * not the unrelated per-device dev_attr_online symbol.
	 */
	unsigned long array = resolve("cpu_root_attrs");
	unsigned int i, found = 0;

	if (!array)
		return -ENOENT;
	for (i = 0; i < 16; i++) {
		struct attribute *entry;
		struct attribute snapshot;
		char name[64];
		int ret;

		if (!writable_profile(array + i * sizeof(entry), sizeof(entry)))
			return -EACCES;
		ret = copy_from_kernel_nofault(&entry, (void *)(array + i * sizeof(entry)), sizeof(entry));
		if (ret)
			return ret;
		if (!entry)
			break;
		ret = copy_from_kernel_nofault(&snapshot, entry, sizeof(snapshot));
		if (ret)
			return ret;
		ret = read_name(snapshot.name, name, sizeof(name));
		if (ret)
			return ret;
		if (strcmp(name, "online") && strcmp(name, "possible") && strcmp(name, "present"))
			continue;
		/* Store a constant label, not a pointer to the stack-local name. */
		ret = plan_device((void *)entry,
			!strcmp(name, "online") ? "online" :
			!strcmp(name, "possible") ? "possible" : "present",
			"show_cpus_attr", fake_cpu_mask);
		if (ret)
			return ret;
		found++;
	}
	return found == 3 ? 0 : -ENOENT;
}

static int plan_topology(void)
{
	int ret;

	ret = plan_device((void *)resolve("dev_attr_core_id"), "core_id", "core_id_show", fake_topology);
	if (ret)
		return ret;
	ret = plan_device((void *)resolve("dev_attr_physical_package_id"),
		"physical_package_id", "physical_package_id_show", fake_topology);
	if (ret)
		return ret;
	return plan_device((void *)resolve("dev_attr_die_id"), "die_id", "die_id_show", fake_topology);
}

static int plan_cpufreq(void)
{
	int ret = plan_frequency("cpufreq_freq_attr_scaling_available_freqs",
		"scaling_available_frequencies", "scaling_available_frequencies_show", fake_available);
	if (ret)
		return ret;
	return plan_frequency("cpufreq_freq_attr_scaling_boost_freqs",
		"scaling_boost_frequencies", "scaling_boost_frequencies_show", fake_boost);
}

static void pin_before_publish(void)
{
	if (!pinned) {
		__module_get(THIS_MODULE);
		pinned = true;
	}
}

static int apply_uts(void)
{
	target_uts_sem = (void *)resolve("uts_sem");
	if (!writable_profile((unsigned long)target_uts_sem, sizeof(*target_uts_sem)) ||
	    !writable_profile((unsigned long)&init_uts_ns.name, sizeof(init_uts_ns.name)))
		return -EACCES;
	down_write(target_uts_sem);
	if (strcmp(init_uts_ns.name.release, TARGET_RELEASE)) {
		up_write(target_uts_sem);
		return -ESTALE;
	}
	pin_before_publish();
	/* Only change release; leave unrelated UTS fields and kernel flags alone. */
	strscpy(init_uts_ns.name.release, FAKE_UTS_RELEASE, sizeof(init_uts_ns.name.release));
	up_write(target_uts_sem);
	applied = 1;
	strscpy(outcome, "active", sizeof(outcome));
	return 0;
}

static void publish_pointers(void)
{
	unsigned int i;

	pin_before_publish();
	for (i = 0; i < planned; i++) {
		struct patch *p = &patches[i];
		pr_info("cpuinfo_spoof: BEFORE_WRITE %s\n", p->name);
		if (cmpxchg(p->slot, p->before, p->after) != p->before) {
			last_error = -EBUSY;
			strscpy(outcome, "partial_conflict", sizeof(outcome));
			return; /* Keep code resident for any already published callback. */
		}
		applied++;
		pr_info("cpuinfo_spoof: AFTER_WRITE %s\n", p->name);
	}
	strscpy(outcome, "active", sizeof(outcome));
}

static void inspect_symbols(void)
{
	unsigned long cpuinfo = resolve("cpuinfo_op");

	pr_info("cpuinfo_spoof: cpuinfo_op=%px in_rodata=%d; writes held\n",
		(void *)cpuinfo, cpuinfo >= ro_start && cpuinfo < ro_end);
	pr_info("cpuinfo_spoof: cpu_root_attrs=%px cpu_attrs=%px\n",
		(void *)resolve("cpu_root_attrs"), (void *)resolve("cpu_attrs"));
	pr_info("cpuinfo_spoof: callbacks retain CFI; affinity/related/getdents are held\n");
	if (!strcmp(stage, "inspect")) {
		check_cpus = plan_cpu_roots();
		planned = 0;
		check_topology = plan_topology();
		planned = 0;
		check_cpufreq = plan_cpufreq();
		planned = 0;
		pr_info("cpuinfo_spoof: READ_ONLY_PREFLIGHT cpus=%d topology=%d cpufreq=%d\n",
			check_cpus, check_topology, check_cpufreq);
	}
}

static int status_show(struct seq_file *m, void *unused)
{
	(void)unused;
	seq_printf(m, "revision=%s\nstage=%s\nstate=%s\nplanned=%u\napplied=%u\nlast_error=%d\npinned=%d\noriginal_release=%s\n",
		REVISION, stage, outcome, planned, applied, last_error, pinned, original_release);
	seq_printf(m, "preflight_cpus=%d\npreflight_topology=%d\npreflight_cpufreq=%d\n",
		check_cpus, check_topology, check_cpufreq);
	seq_puts(m, "cpuinfo=held\naffinity=held\nrelated=held\nmounts=none\n");
	return 0;
}

static int status_open(struct inode *inode, struct file *file)
{
	(void)inode;
	return single_open(file, status_show, NULL);
}

static const struct proc_ops status_ops = {
	.proc_open = status_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static int __init spoof_init(void)
{
	int ret;
	bool pointer_stage;

	pr_info("cpuinfo_spoof: BEGIN revision=%s stage=%s\n", REVISION, stage);
	if (spoof_enable || spoof_uts || spoof_cpuinfo || spoof_online ||
	    spoof_topology || spoof_cpufreq || spoof_related || spoof_affinity) {
		pr_err("cpuinfo_spoof: legacy multi-switch invocation rejected; use stage=inspect or stage=uts\n");
		return -EINVAL;
	}
	pointer_stage = !strcmp(stage, "cpus") || !strcmp(stage, "topology") || !strcmp(stage, "cpufreq");
	if (strcmp(stage, "inspect") && strcmp(stage, "uts") && !pointer_stage)
		return -EOPNOTSUPP;
	if (pointer_stage && !pointer_tests)
		return -EPERM;
	strscpy(original_release, init_uts_ns.name.release, sizeof(original_release));
	if (strcmp(original_release, TARGET_RELEASE))
		return -ESTALE;
	ret = resolver_init();
	if (ret)
		return ret;
	inspect_symbols();
	if (!strcmp(stage, "cpus"))
		ret = plan_cpu_roots();
	else if (!strcmp(stage, "topology"))
		ret = plan_topology();
	else if (!strcmp(stage, "cpufreq"))
		ret = plan_cpufreq();
	else
		ret = 0;
	if (ret) {
		pr_err("cpuinfo_spoof: PREFLIGHT_FAILED stage=%s rc=%d; no writes published\n", stage, ret);
		return ret;
	}
	control = proc_create("cpuinfo_spoof", 0444, NULL, &status_ops);
	if (!control)
		return -ENOMEM;
	if (!strcmp(stage, "uts")) {
		ret = apply_uts();
		if (ret) {
			proc_remove(control);
			return ret;
		}
	} else if (pointer_stage) {
		publish_pointers();
	}
	pr_info("cpuinfo_spoof: END state=%s planned=%u applied=%u error=%d\n",
		outcome, planned, applied, last_error);
	return 0;
}

static void __exit spoof_exit(void)
{
	/* A modified instance is pinned. No live callback code can be unloaded.
	 * This is a lifetime guard, not a claim about the historical crash cause.
	 * An inspect-only instance has never published callback pointers.
	 */
	proc_remove(control);
}
module_init(spoof_init);
module_exit(spoof_exit);
