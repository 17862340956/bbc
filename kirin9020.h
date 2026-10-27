#ifndef _KIRIN9020_H
#define _KIRIN9020_H

#define FAKE_N_CPUS 12
/* Restore the original project fixture: 4 + 6 + 2, not the later 4+4+4 edit.
 * These are project display presets, not newly verified Huawei hardware data.
 */
static const unsigned int fake_cpu_part[FAKE_N_CPUS] __maybe_unused = {
	0xd23, 0xd23, 0xd23, 0xd23,
	0xd46, 0xd46, 0xd46, 0xd46, 0xd46, 0xd46,
	0xd05, 0xd05,
};

static const int fake_core_id[FAKE_N_CPUS] = {
	0, 1, 2, 3, 0, 1, 2, 3, 4, 5, 0, 1,
};

static const int fake_pkg_id[FAKE_N_CPUS] = {
	0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 2, 2,
};

#define FAKE_IMPLEMENTER 0x48
#define FAKE_VARIANT 0x2
#define FAKE_ARCH 8
#define FAKE_REVISION 1
#define FAKE_DIE_ID (-1)
#define FAKE_KERNEL_MAX (FAKE_N_CPUS - 1)

#define FAKE_UTS_RELEASE "5.15.167-HUAWEI-Kirin9020"
#define FAKE_UTS_VERSION "#1 SMP PREEMPT Fri Sep 5 06:37:22 UTC 2025"
#define FAKE_UTS_MACHINE "aarch64"

#define FAKE_HARDWARE "HUAWEI Kirin9020"
#define FAKE_BOGOMIPS "38.40"

#define FAKE_FEATURES \
	"fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp " \
	"cpuid asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 asimddp sha512 " \
	"asimdfhm dit uscat ilrcpc flagm sb paca pacg dcpodp flagm2 frint " \
	"i8mm bf16 bti"

#define FAKE_AVAIL_FREQS \
	"307200 441600 556800 672000 787200 902400 1017600 1113600 " \
	"1228800 1344000 1459200 1555200 1670400 1785600 1900800 2016000 " \
	"2188800 2323200 2457600 2592000 2707200 2803200 2918400 3000000 " \
	"3187200"

#define FAKE_BOOST_FREQS "3187200"

#endif
