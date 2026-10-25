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

#include "kirin9020.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("cpuinfo_spoof");

extern struct uts_namespace init_uts_ns;

static int spoof_enable = 1;
module_param(spoof_enable, int, 0644);

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

static int patch_ptr(unsigned long addr, void *new_ptr, void **saved)
{
	void **slot = (void **)addr;
	if (!addr)
		return -EINVAL;
	*saved = *slot;
	*slot = new_ptr;
	return 0;
}

static unsigned long cpuinfo_op_addr = 0;
static int (*saved_cpuinfo_show)(struct seq_file *, void *) = NULL;

static unsigned long dev_attr_online_addr = 0;
static ssize_t (*saved_online_show)(struct device *,
				    struct device_attribute *, char *) = NULL;

static int fake_c_show(struct seq_file *m, void *v)
{
	int cpu;

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

static ssize_t fake_online_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	(void)dev; (void)attr;
	return snprintf(buf, 64, "0-%d\n", FAKE_N_CPUS - 1);
}

static struct new_utsname saved_uts;

static int uts_spoof_install(void)
{
	memcpy(&saved_uts, &init_uts_ns.name, sizeof(saved_uts));
	strncpy(init_uts_ns.name.release, FAKE_UTS_RELEASE,
		sizeof(init_uts_ns.name.release) - 1);
	strncpy(init_uts_ns.name.version, FAKE_UTS_VERSION,
		sizeof(init_uts_ns.name.version) - 1);
	strncpy(init_uts_ns.name.machine, FAKE_UTS_MACHINE,
		sizeof(init_uts_ns.name.machine) - 1);
	return 0;
}

static void uts_spoof_remove(void)
{
	memcpy(&init_uts_ns.name, &saved_uts, sizeof(saved_uts));
}

static struct kprobe kp_sched_getaffinity;

static void sched_ga_post(struct kprobe *p, struct pt_regs *regs,
			  unsigned long flags)
{
	unsigned long mask_ptr = regs->regs[2];
	unsigned long len = regs->regs[1];
	unsigned long fake_mask;

	if (len < sizeof(fake_mask))
		return;

	fake_mask = (1UL << FAKE_N_CPUS) - 1;
	if (copy_to_user((void __user *)mask_ptr, &fake_mask,
			 sizeof(fake_mask)) == 0)
		regs->regs[0] = sizeof(fake_mask);
}

static int installed = 0;
static struct proc_dir_entry *ctl_entry;

static int cpuinfo_spoof_install(void)
{
	int r;

	cpuinfo_op_addr = ksym_lookup("cpuinfo_op");
	if (!cpuinfo_op_addr) {
		pr_warn("cpuinfo_spoof: cpuinfo_op not found\n");
		return -ENOENT;
	}

	r = patch_ptr(cpuinfo_op_addr +
		      offsetof(struct seq_operations, show),
		      fake_c_show, (void **)&saved_cpuinfo_show);
	if (r) {
		pr_warn("cpuinfo_spoof: cpuinfo show patch failed %d\n", r);
		cpuinfo_op_addr = 0;
		return r;
	}

	dev_attr_online_addr = ksym_lookup("dev_attr_online");
	if (dev_attr_online_addr) {
		r = patch_ptr(dev_attr_online_addr +
			      offsetof(struct device_attribute, show),
			      fake_online_show, (void **)&saved_online_show);
		if (r)
			pr_warn("cpuinfo_spoof: online show patch failed %d\n", r);
	} else {
		pr_warn("cpuinfo_spoof: dev_attr_online not found\n");
	}

	return 0;
}

static void cpuinfo_spoof_remove(void)
{
	if (cpuinfo_op_addr && saved_cpuinfo_show)
		patch_ptr(cpuinfo_op_addr +
			  offsetof(struct seq_operations, show),
			  saved_cpuinfo_show, (void **)&saved_cpuinfo_show);
	if (dev_attr_online_addr && saved_online_show)
		patch_ptr(dev_attr_online_addr +
			  offsetof(struct device_attribute, show),
			  saved_online_show, (void **)&saved_online_show);
	cpuinfo_op_addr = 0;
	dev_attr_online_addr = 0;
}

static int do_install(void)
{
	int r;

	if (installed)
		return 0;

	r = cpuinfo_spoof_install();
	if (r)
		return r;

	uts_spoof_install();

	if (spoof_affinity) {
		kp_sched_getaffinity.symbol_name = "__arm64_sys_sched_getaffinity";
		kp_sched_getaffinity.post_handler = sched_ga_post;
		r = register_kprobe(&kp_sched_getaffinity);
		if (r)
			pr_warn("cpuinfo_spoof: sched_getaffinity kprobe failed %d\n", r);
	}

	installed = 1;
	return 0;
}

static void do_remove(void)
{
	if (!installed)
		return;
	if (kp_sched_getaffinity.addr)
		unregister_kprobe(&kp_sched_getaffinity);
	cpuinfo_spoof_remove();
	uts_spoof_remove();
	installed = 0;
}

static ssize_t ctl_write(struct file *f, const char __user *ubuf, size_t len,
			 loff_t *off)
{
	char buf[16] = {0};
	size_t n = min(len, sizeof(buf) - 1);
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
	char buf[32];
	int n;
	if (*off)
		return 0;
	n = snprintf(buf, sizeof(buf), "spoof=%s\n", installed ? "on" : "off");
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
	init_kallsyms();

	ctl_entry = proc_create("cpuinfo_spoof", 0644, NULL, &ctl_ops);
	if (!ctl_entry)
		return -ENOMEM;

	if (spoof_enable) {
		int r = do_install();
		if (r)
			pr_warn("cpuinfo_spoof: install failed %d\n", r);
	}

	pr_info("cpuinfo_spoof: loaded, spoof=%s affinity=%s\n",
		installed ? "on" : "off", spoof_affinity ? "on" : "off");
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
