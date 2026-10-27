#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/utsname.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/cpumask.h>
#include <linux/mm.h>
#include <asm/pgtable.h>

#include "kirin9020.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("cpuinfo_spoof");

extern struct uts_namespace init_uts_ns;

/*
 * Every surface has its own switch.  All default to 0 so that a plain
 * insmod only creates the control node and touches nothing.  Enable one
 * surface at a time to isolate a crash.
 */
static int spoof_enable = 1;
module_param(spoof_enable, int, 0644);

static int spoof_uts = 0;
module_param(spoof_uts, int, 0644);

static int spoof_cpuinfo = 0;
module_param(spoof_cpuinfo, int, 0644);

static int spoof_online = 0;
module_param(spoof_online, int, 0644);

static int spoof_topology = 0;
module_param(spoof_topology, int, 0644);

static int spoof_cpufreq = 0;
module_param(spoof_cpufreq, int, 0644);

static int spoof_related = 0;
module_param(spoof_related, int, 0644);

static int spoof_affinity = 0;
module_param(spoof_affinity, int, 0644);

static unsigned long (*fn_kallsyms_lookup_name)(const char *name) = NULL;

static void init_kallsyms(void)
{
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };

	if (register_kprobe(&kp) == 0) {
		fn_kallsyms_lookup_name = (void *)kp.addr;
		unregister_kprobe(&kp);
	}
	if (!fn_kallsyms_lookup_name)
		pr_warn("cpuinfo_spoof: kallsyms_lookup_name not found\n");
}

static unsigned long ksym_lookup(const char *name)
{
	if (fn_kallsyms_lookup_name)
		return fn_kallsyms_lookup_name(name);
	return 0;
}

/*
 * Most spoof targets (dev_attr_online/offline/kernel_max/isolated, topology
 * attrs, cpufreq freq attrs, init_uts_ns) are non-const objects in writable
 * .data - a plain store works with no page-permission dance.
 */
static int patch_ptr(unsigned long addr, void *new_ptr, void **saved)
{
	if (!addr)
		return -EINVAL;
	if (saved)
		*saved = *(void **)addr;
	*(void **)addr = new_ptr;
	return 0;
}

static void unpatch_ptr(unsigned long addr, void *old_ptr)
{
	if (!addr || !old_ptr)
		return;
	*(void **)addr = old_ptr;
}

/* ---- /proc/cpuinfo ---- */

static unsigned long cpuinfo_op_addr = 0;
static int (*saved_cpuinfo_show)(struct seq_file *, void *) = NULL;

static int fake_c_show(struct seq_file *m, void *v)
{
	int cpu;

	(void)v;
	if (m->index != 0)
		return 0;

	for (cpu = 0; cpu < FAKE_N_CPUS; cpu++) {
		seq_printf(m, "processor\t: %d\n", cpu);
		seq_printf(m, "BogoMIPS\t: %s\n", FAKE_BOGOMIPS);
		seq_printf(m, "Features\t: %s\n", FAKE_FEATURES);
		seq_printf(m, "CPU implementer\t: 0x%x\n", FAKE_IMPLEMENTER);
		seq_printf(m, "CPU architecture: %d\n", FAKE_ARCH);
		seq_printf(m, "CPU variant\t: 0x%x\n", FAKE_VARIANT);
		seq_printf(m, "CPU part\t: 0x%03x\n", fake_cpu_part[cpu]);
		seq_printf(m, "CPU revision\t: %d\n", FAKE_REVISION);
		seq_printf(m, "\n");
	}
	seq_printf(m, "Hardware\t: %s\n", FAKE_HARDWARE);
	return 0;
}

/* ---- /sys/devices/system/cpu/online + offline + kernel_max + isolated ---- */

static unsigned long dev_attr_online_addr = 0;
static unsigned long dev_attr_offline_addr = 0;
static unsigned long dev_attr_kernel_max_addr = 0;
static unsigned long dev_attr_isolated_addr = 0;
static ssize_t (*saved_online_show)(struct device *,
				    struct device_attribute *, char *) = NULL;
static ssize_t (*saved_offline_show)(struct device *,
				     struct device_attribute *, char *) = NULL;
static ssize_t (*saved_kernel_max_show)(struct device *,
					struct device_attribute *, char *) = NULL;
static ssize_t (*saved_isolated_show)(struct device *,
				      struct device_attribute *, char *) = NULL;

static ssize_t fake_online_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	(void)dev; (void)attr;
	return snprintf(buf, PAGE_SIZE, "0-%d\n", FAKE_N_CPUS - 1);
}

static ssize_t fake_offline_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	(void)dev; (void)attr;
	return snprintf(buf, PAGE_SIZE, "\n");
}

static ssize_t fake_kernel_max_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	(void)dev; (void)attr;
	return snprintf(buf, PAGE_SIZE, "%d\n", FAKE_KERNEL_MAX);
}

static ssize_t fake_isolated_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	(void)dev; (void)attr;
	return snprintf(buf, PAGE_SIZE, "\n");
}

/* ---- topology ---- */

static unsigned long dev_attr_core_id_addr = 0;
static unsigned long dev_attr_pkg_id_addr = 0;
static unsigned long dev_attr_die_id_addr = 0;
static ssize_t (*saved_core_id_show)(struct device *,
				     struct device_attribute *, char *) = NULL;
static ssize_t (*saved_pkg_id_show)(struct device *,
				    struct device_attribute *, char *) = NULL;
static ssize_t (*saved_die_id_show)(struct device *,
				    struct device_attribute *, char *) = NULL;

static int cpu_of_dev(struct device *dev)
{
	int cpu = dev ? dev->id : -1;

	if (cpu < 0 || cpu >= FAKE_N_CPUS)
		return -1;
	return cpu;
}

static ssize_t fake_core_id_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	int cpu = cpu_of_dev(dev);

	(void)attr;
	if (cpu < 0)
		return snprintf(buf, PAGE_SIZE, "%d\n", 0);
	return snprintf(buf, PAGE_SIZE, "%d\n", fake_core_id[cpu]);
}

static ssize_t fake_pkg_id_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	int cpu = cpu_of_dev(dev);

	(void)attr;
	if (cpu < 0)
		return snprintf(buf, PAGE_SIZE, "%d\n", 0);
	return snprintf(buf, PAGE_SIZE, "%d\n", fake_pkg_id[cpu]);
}

static ssize_t fake_die_id_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	(void)dev; (void)attr;
	return snprintf(buf, PAGE_SIZE, "%d\n", FAKE_DIE_ID);
}

/* ---- cpufreq ---- */

static unsigned long cpufreq_avail_addr = 0;
static unsigned long cpufreq_boost_addr = 0;
static ssize_t (*saved_avail_show)(struct device *,
				   struct device_attribute *, char *) = NULL;
static ssize_t (*saved_boost_show)(struct device *,
				   struct device_attribute *, char *) = NULL;

static ssize_t fake_avail_freqs_show(struct device *dev,
				     struct device_attribute *attr, char *buf)
{
	(void)dev; (void)attr;
	return snprintf(buf, PAGE_SIZE, "%s\n", FAKE_AVAIL_FREQS);
}

static ssize_t fake_boost_freqs_show(struct device *dev,
				     struct device_attribute *attr, char *buf)
{
	(void)dev; (void)attr;
	return snprintf(buf, PAGE_SIZE, "%s\n", FAKE_BOOST_FREQS);
}

/* ---- cpufreq related_cpus (type not confirmed, isolated switch) ---- */

static unsigned long related_cpus_addr = 0;
static ssize_t (*saved_related_show)(struct device *,
				     struct device_attribute *, char *) = NULL;

static ssize_t fake_related_show(struct device *dev,
				 struct device_attribute *attr, char *buf)
{
	int cpu = dev ? dev->id : 0;
	int base;

	(void)attr;
	if (cpu < 0 || cpu >= FAKE_N_CPUS)
		cpu = 0;
	base = (cpu / FAKE_CLUSTER_SIZE) * FAKE_CLUSTER_SIZE;
	return snprintf(buf, PAGE_SIZE, "%d %d %d %d\n",
			base, base + 1, base + 2, base + 3);
}

/* ---- uts ---- */

static struct new_utsname saved_uts;

static void uts_spoof_install(void)
{
	memcpy(&saved_uts, &init_uts_ns.name, sizeof(saved_uts));
	strncpy(init_uts_ns.name.release, FAKE_UTS_RELEASE,
		sizeof(init_uts_ns.name.release) - 1);
	strncpy(init_uts_ns.name.version, FAKE_UTS_VERSION,
		sizeof(init_uts_ns.name.version) - 1);
	strncpy(init_uts_ns.name.machine, FAKE_UTS_MACHINE,
		sizeof(init_uts_ns.name.machine) - 1);
}

static void uts_spoof_remove(void)
{
	memcpy(&init_uts_ns.name, &saved_uts, sizeof(saved_uts));
}

/* ---- sched_getaffinity (nproc) ---- */

static struct kprobe kp_sched_getaffinity;
static int affinity_registered = 0;

static void sched_ga_post(struct kprobe *p, struct pt_regs *regs,
			  unsigned long flags)
{
	unsigned long mask_ptr = regs->regs[2];
	unsigned long len = regs->regs[1];
	unsigned long fake_mask;

	(void)p; (void)flags;
	if (len < sizeof(fake_mask))
		return;

	fake_mask = (1UL << FAKE_N_CPUS) - 1;
	if (copy_to_user((void __user *)mask_ptr, &fake_mask,
			 sizeof(fake_mask)) == 0)
		regs->regs[0] = sizeof(fake_mask);
}

/* ---- install / remove ---- */

static int installed = 0;
static struct proc_dir_entry *ctl_entry;

static void install_cpuinfo(void)
{
	int r;

	cpuinfo_op_addr = ksym_lookup("cpuinfo_op");
	if (!cpuinfo_op_addr) {
		pr_warn("cpuinfo_spoof: cpuinfo_op not found\n");
		return;
	}
	r = patch_ptr(cpuinfo_op_addr + offsetof(struct seq_operations, show),
		      fake_c_show, (void **)&saved_cpuinfo_show);
	if (r)
		pr_warn("cpuinfo_spoof: cpuinfo patch failed %d\n", r);
}

static void install_online(void)
{
	dev_attr_online_addr = ksym_lookup("dev_attr_online");
	if (dev_attr_online_addr) {
		patch_ptr(dev_attr_online_addr +
			  offsetof(struct device_attribute, show),
			  fake_online_show, (void **)&saved_online_show);
	} else {
		pr_warn("cpuinfo_spoof: dev_attr_online not found\n");
	}

	dev_attr_offline_addr = ksym_lookup("dev_attr_offline");
	if (dev_attr_offline_addr) {
		patch_ptr(dev_attr_offline_addr +
			  offsetof(struct device_attribute, show),
			  fake_offline_show, (void **)&saved_offline_show);
	} else {
		pr_warn("cpuinfo_spoof: dev_attr_offline not found\n");
	}

	dev_attr_kernel_max_addr = ksym_lookup("dev_attr_kernel_max");
	if (dev_attr_kernel_max_addr) {
		patch_ptr(dev_attr_kernel_max_addr +
			  offsetof(struct device_attribute, show),
			  fake_kernel_max_show, (void **)&saved_kernel_max_show);
	} else {
		pr_warn("cpuinfo_spoof: dev_attr_kernel_max not found\n");
	}

	dev_attr_isolated_addr = ksym_lookup("dev_attr_isolated");
	if (dev_attr_isolated_addr) {
		patch_ptr(dev_attr_isolated_addr +
			  offsetof(struct device_attribute, show),
			  fake_isolated_show, (void **)&saved_isolated_show);
	} else {
		pr_warn("cpuinfo_spoof: dev_attr_isolated not found\n");
	}
}

static void install_topology(void)
{
	dev_attr_core_id_addr = ksym_lookup("dev_attr_core_id");
	if (dev_attr_core_id_addr) {
		patch_ptr(dev_attr_core_id_addr +
			  offsetof(struct device_attribute, show),
			  fake_core_id_show, (void **)&saved_core_id_show);
	} else {
		pr_warn("cpuinfo_spoof: dev_attr_core_id not found\n");
	}

	dev_attr_pkg_id_addr = ksym_lookup("dev_attr_physical_package_id");
	if (dev_attr_pkg_id_addr) {
		patch_ptr(dev_attr_pkg_id_addr +
			  offsetof(struct device_attribute, show),
			  fake_pkg_id_show, (void **)&saved_pkg_id_show);
	} else {
		pr_warn("cpuinfo_spoof: dev_attr_physical_package_id not found\n");
	}

	dev_attr_die_id_addr = ksym_lookup("dev_attr_die_id");
	if (dev_attr_die_id_addr) {
		patch_ptr(dev_attr_die_id_addr +
			  offsetof(struct device_attribute, show),
			  fake_die_id_show, (void **)&saved_die_id_show);
	} else {
		pr_warn("cpuinfo_spoof: dev_attr_die_id not found\n");
	}
}

/*
 * cpufreq_freq_attr_{scaling_available,scaling_boost}_freqs embed a
 * struct device_attribute as their first member, so the pointer to the base
 * is also a pointer to the attribute and the show offset is unchanged.
 */
static void install_cpufreq(void)
{
	cpufreq_avail_addr = ksym_lookup("cpufreq_freq_attr_scaling_available_freqs");
	if (cpufreq_avail_addr) {
		patch_ptr(cpufreq_avail_addr +
			  offsetof(struct device_attribute, show),
			  fake_avail_freqs_show, (void **)&saved_avail_show);
	} else {
		pr_warn("cpuinfo_spoof: cpufreq available_freqs not found\n");
	}

	cpufreq_boost_addr = ksym_lookup("cpufreq_freq_attr_scaling_boost_freqs");
	if (cpufreq_boost_addr) {
		patch_ptr(cpufreq_boost_addr +
			  offsetof(struct device_attribute, show),
			  fake_boost_freqs_show, (void **)&saved_boost_show);
	} else {
		pr_warn("cpuinfo_spoof: cpufreq boost_freqs not found\n");
	}
}

static void install_related(void)
{
	related_cpus_addr = ksym_lookup("related_cpus");
	if (related_cpus_addr) {
		patch_ptr(related_cpus_addr +
			  offsetof(struct device_attribute, show),
			  fake_related_show, (void **)&saved_related_show);
	} else {
		pr_warn("cpuinfo_spoof: related_cpus not found\n");
	}
}

static int do_install(void)
{
	int r;

	if (installed)
		return 0;

	if (spoof_uts)
		uts_spoof_install();
	if (spoof_cpuinfo)
		install_cpuinfo();
	if (spoof_online)
		install_online();
	if (spoof_topology)
		install_topology();
	if (spoof_cpufreq)
		install_cpufreq();
	if (spoof_related)
		install_related();

	if (spoof_affinity) {
		kp_sched_getaffinity.symbol_name = "__arm64_sys_sched_getaffinity";
		kp_sched_getaffinity.post_handler = sched_ga_post;
		r = register_kprobe(&kp_sched_getaffinity);
		if (r)
			pr_warn("cpuinfo_spoof: sched_getaffinity kprobe failed %d\n", r);
		else
			affinity_registered = 1;
	}

	installed = 1;
	return 0;
}

static void do_remove(void)
{
	if (!installed)
		return;

	if (affinity_registered) {
		unregister_kprobe(&kp_sched_getaffinity);
		affinity_registered = 0;
	}

	unpatch_ptr(cpuinfo_op_addr + offsetof(struct seq_operations, show),
		    (void *)saved_cpuinfo_show);
	unpatch_ptr(dev_attr_online_addr + offsetof(struct device_attribute, show),
		    (void *)saved_online_show);
	unpatch_ptr(dev_attr_offline_addr + offsetof(struct device_attribute, show),
		    (void *)saved_offline_show);
	unpatch_ptr(dev_attr_kernel_max_addr + offsetof(struct device_attribute, show),
		    (void *)saved_kernel_max_show);
	unpatch_ptr(dev_attr_isolated_addr + offsetof(struct device_attribute, show),
		    (void *)saved_isolated_show);
	unpatch_ptr(dev_attr_core_id_addr + offsetof(struct device_attribute, show),
		    (void *)saved_core_id_show);
	unpatch_ptr(dev_attr_pkg_id_addr + offsetof(struct device_attribute, show),
		    (void *)saved_pkg_id_show);
	unpatch_ptr(dev_attr_die_id_addr + offsetof(struct device_attribute, show),
		    (void *)saved_die_id_show);
	unpatch_ptr(cpufreq_avail_addr + offsetof(struct device_attribute, show),
		    (void *)saved_avail_show);
	unpatch_ptr(cpufreq_boost_addr + offsetof(struct device_attribute, show),
		    (void *)saved_boost_show);
	unpatch_ptr(related_cpus_addr + offsetof(struct device_attribute, show),
		    (void *)saved_related_show);

	if (spoof_uts)
		uts_spoof_remove();

	cpuinfo_op_addr = 0;
	dev_attr_online_addr = 0;
	dev_attr_offline_addr = 0;
	dev_attr_kernel_max_addr = 0;
	dev_attr_isolated_addr = 0;
	dev_attr_core_id_addr = 0;
	dev_attr_pkg_id_addr = 0;
	dev_attr_die_id_addr = 0;
	cpufreq_avail_addr = 0;
	cpufreq_boost_addr = 0;
	related_cpus_addr = 0;
	installed = 0;
}

/* ---- control node ---- */

static ssize_t ctl_write(struct file *f, const char __user *ubuf, size_t len,
			 loff_t *off)
{
	char buf[16] = {0};
	size_t n = min(len, sizeof(buf) - 1);

	(void)f; (void)off;
	if (copy_from_user(buf, ubuf, n))
		return -EFAULT;

	if (strncmp(buf, "enable", 6) == 0)
		do_install();
	else if (strncmp(buf, "disable", 7) == 0)
		do_remove();
	else
		return -EINVAL;
	return len;
}

static ssize_t ctl_read(struct file *f, char __user *ubuf, size_t len,
			loff_t *off)
{
	char buf[160];
	int n;

	(void)f;
	if (*off)
		return 0;
	n = snprintf(buf, sizeof(buf),
		     "spoof=%s uts=%d cpuinfo=%d online=%d topology=%d cpufreq=%d related=%d affinity=%d\n",
		     installed ? "on" : "off", spoof_uts, spoof_cpuinfo,
		     spoof_online, spoof_topology, spoof_cpufreq,
		     spoof_related, spoof_affinity);
	if (copy_to_user(ubuf, buf, n))
		return -EFAULT;
	*off = n;
	return n;
}

static const struct proc_ops ctl_ops = {
	.proc_read = ctl_read,
	.proc_write = ctl_write,
};

static int __init cpuinfo_spoof_init(void)
{
	int r;

	init_kallsyms();

	pr_info("cpuinfo_spoof: init_uts_ns at %px (extern ref)\n",
		(void *)&init_uts_ns);

	ctl_entry = proc_create("cpuinfo_spoof", 0644, NULL, &ctl_ops);
	if (!ctl_entry)
		return -ENOMEM;

	if (spoof_enable) {
		r = do_install();
		if (r)
			pr_warn("cpuinfo_spoof: install failed %d\n", r);
	}

	pr_info("cpuinfo_spoof: loaded spoof=%s uts=%d cpuinfo=%d online=%d topology=%d cpufreq=%d related=%d affinity=%d\n",
		installed ? "on" : "off", spoof_uts, spoof_cpuinfo,
		spoof_online, spoof_topology, spoof_cpufreq, spoof_related,
		spoof_affinity);

	/*
	 * Pin the module: unpatching a live seq_file/device-attribute pointer
	 * while another CPU is inside our fake_* show function races with code
	 * unload and panics the device ("works once, then dies").  Refusing to
	 * unload keeps the fake functions resident and eliminates the race.
	 * Reboot to remove.
	 */
	__module_get(THIS_MODULE);

	return 0;
}

static void __exit cpuinfo_spoof_exit(void)
{
	do_remove();
	if (ctl_entry)
		proc_remove(ctl_entry);
	pr_info("cpuinfo_spoof: unloaded\n");
}

module_init(cpuinfo_spoof_init);
module_exit(cpuinfo_spoof_exit);
