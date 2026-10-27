#!/system/bin/sh
# r3: one stage per boot, exact sibling KO, no rmmod, mounts or GPU writes.
REV=qilin-r3-20261027
TARGET_RELEASE=5.15.167-android13-8-o-01144-gb3f32e037fab
SELF_DIR=$(CDPATH= cd "$(dirname "$0")" 2>/dev/null && pwd)
[ "$(id -u)" = 0 ] || { echo '请在 MT 管理器选择 ROOT 执行。'; exit 1; }
umask 077
BASE=/data/adb
[ -d "$BASE" ] && [ -w "$BASE" ] || BASE=/data/local/tmp
OUT="$BASE/qilin_r3_$(date '+%Y%m%d_%H%M%S')_$$"
mkdir -p "$OUT/pstore" || exit 1
LOG="$OUT/run.txt"
say() { printf '%s\n' "$*"; printf '%s\n' "$*" >> "$LOG"; }
checkpoint() { say "STEP=$1"; printf '%s\n' "$1" > "$OUT/last_step.txt"; sync; }
finish() {
    dmesg > "$OUT/dmesg_after.txt" 2> "$OUT/dmesg_error.txt"
    grep -iE 'cpuinfo_spoof|CFI failure|CFI check|panic|Oops|Call trace|Unable to handle' "$OUT/dmesg_after.txt" > "$OUT/kernel_hits.txt"
    sync
    ARCHIVE="$OUT.tar.gz"
    if tar -czf "$ARCHIVE" -C "$BASE" "${OUT##*/}" 2> "$OUT/archive_error.txt"; then
        say "日志压缩包：$ARCHIVE"
    else
        say "日志目录：$OUT"
    fi
}
stop() { say "$1"; finish; exit 1; }

say "=== CPU 单项测试 $REV ==="
say "日志：$OUT"
# Preserve the previous boot's evidence before doing anything else.
for FILE in /sys/fs/pstore/*; do
    [ ! -f "$FILE" ] || cat "$FILE" > "$OUT/pstore/${FILE##*/}" 2>> "$OUT/read_errors.txt"
done
[ ! -r /proc/last_kmsg ] || cat /proc/last_kmsg > "$OUT/last_kmsg.txt" 2>> "$OUT/read_errors.txt"
dmesg > "$OUT/dmesg_before.txt" 2> "$OUT/dmesg_error.txt"
cat /proc/modules > "$OUT/modules.txt" 2>> "$OUT/read_errors.txt"

MODE=${1:-}
if [ -z "$MODE" ]; then
    say '1 = 只读预检（默认；不发布修改）'
    say '2 = 只测试 version / uname'
    say '3 = 只测试 cpus 的 online / possible / present（实验项）'
    say '4 = 只测试 topology 的三个 ID（实验项）'
    say '5 = 只测试 cpufreq 的两个频率列表（实验项）'
    say '0 = 只收集状态，不加载模块'
    CHOICE=1
    if [ -t 0 ]; then
        printf '输入编号后回车，直接回车选1：'
        IFS= read -r ANSWER || ANSWER=
        [ -z "$ANSWER" ] || CHOICE=$ANSWER
    fi
    case "$CHOICE" in
        1) MODE=inspect ;; 2) MODE=uts ;; 3) MODE=cpus ;;
        4) MODE=topology ;; 5) MODE=cpufreq ;; 0) MODE=status ;;
        *) stop '编号无效，本次未加载。' ;;
    esac
fi
case "$MODE" in inspect|uts|cpus|topology|cpufreq|status) : ;; *) stop '不支持该项目；没有 all、affinity 或 bind 模式。' ;; esac
say "选择项目：$MODE"
checkpoint before_module_check

if [ -d /sys/module/cpuinfo_spoof ]; then
    cat /sys/module/cpuinfo_spoof/version > "$OUT/loaded_version.txt" 2>> "$OUT/read_errors.txt"
    cat /proc/cpuinfo_spoof > "$OUT/status.txt" 2>> "$OUT/read_errors.txt"
    say '模块已经加载，本次只读取状态，不卸载、不重新启用。'
    cat "$OUT/status.txt"
    if [ "$MODE" != status ]; then
        say '要测试另一个项目或新版本，请重启后再运行。'
    fi
    finish
    exit 0
fi
if [ "$MODE" = status ]; then
    say '当前没有加载模块。'
    finish
    exit 0
fi

KO="$SELF_DIR/cpuinfo_spoof.ko"
REPORT="$SELF_DIR/build_report.json"
[ -f "$KO" ] || stop '请将新 cpuinfo_spoof.ko 与本 SH 放在同一个目录。'
[ -f "$REPORT" ] || stop '缺少 build_report.json，请把新 Actions 产物中的三个文件一起复制过来。'
command -v strings >/dev/null 2>&1 || stop '缺少 strings 工具，本次不加载。'
command -v sha256sum >/dev/null 2>&1 || stop '缺少 sha256sum 工具，本次不加载。'
strings "$KO" > "$OUT/module_strings.txt"
grep -qx "version=$REV" "$OUT/module_strings.txt" || stop '检测到旧版或不匹配的 KO，本次不加载。'
grep -qx 'name=cpuinfo_spoof' "$OUT/module_strings.txt" || stop '模块名不匹配。'
grep -q "^vermagic=$TARGET_RELEASE " "$OUT/module_strings.txt" || stop 'vermagic 不匹配。'
ACTUAL=$(sha256sum "$KO" | awk '{print $1}')
EXPECTED=$(awk -F '"' '/"sha256"/ {print $4; exit}' "$REPORT")
[ -n "$EXPECTED" ] && [ "$ACTUAL" = "$EXPECTED" ] || stop 'KO 与编译校验报告的哈希不一致，本次不加载。'
cp "$REPORT" "$OUT/build_report.json"
printf '%s  %s\n' "$ACTUAL" "$KO" > "$OUT/module_sha256.txt"
[ "$(uname -r)" = "$TARGET_RELEASE" ] || stop '当前内核 release 不匹配，先检查其他伪装模块是否仍在运行。'

FLAGS="stage=$MODE"
case "$MODE" in cpus|topology|cpufreq) FLAGS="$FLAGS pointer_tests=1" ;; esac
say "模块文件：$KO"
say "加载参数：$FLAGS"
checkpoint "before_insmod_$MODE"
insmod "$KO" $FLAGS > "$OUT/insmod.txt" 2>&1
RC=$?
cat "$OUT/insmod.txt"
printf 'insmod_exit=%s\n' "$RC" >> "$LOG"
[ "$RC" = 0 ] || stop '模块返回错误，已保存完整错误和内核日志，不继续验证。'
checkpoint "after_insmod_$MODE"
cat /proc/cpuinfo_spoof > "$OUT/status.txt" 2>> "$OUT/read_errors.txt"
cat "$OUT/status.txt"
grep -qx "revision=$REV" "$OUT/status.txt" || stop '已加载模块的版本标识不匹配。'
if [ "$MODE" = inspect ]; then
    grep -qx 'applied=0' "$OUT/status.txt" || stop '预检状态异常，停止后续操作。'
    say '只读预检结束，未启用伪装。请先把日志发来核对。'
else
    grep -qx 'state=active' "$OUT/status.txt" || stop '修改未全部成功，按实际状态处理，不判为通过。'
    checkpoint "before_read_$MODE"
    case "$MODE" in
        uts)
            { uname -a; cat /proc/version; } > "$OUT/result.txt" 2>&1
            if [ "$(uname -r)" = 5.15.167-HUAWEI-Kirin9020 ]; then
                say 'PASS：uname release 已改变；具体进程可能使用其他 UTS namespace。'
            else
                say 'FAIL：当前进程 uname 未达到目标值。'
            fi
            ;;
        cpus)
            { for KEY in online possible present; do printf '%s=' "$KEY"; cat "/sys/devices/system/cpu/$KEY"; done; } > "$OUT/result.txt" 2>&1
            ;;
        topology)
            { for CPU in 0 1 2 3 4 5 6 7; do
                for KEY in core_id physical_package_id die_id; do
                    printf 'cpu%s/%s=' "$CPU" "$KEY"
                    cat "/sys/devices/system/cpu/cpu$CPU/topology/$KEY"
                done
            done; } > "$OUT/result.txt" 2>&1
            ;;
        cpufreq)
            { for KEY in scaling_available_frequencies scaling_boost_frequencies; do
                printf '%s=' "$KEY"; cat "/sys/devices/system/cpu/cpu0/cpufreq/$KEY"
            done; } > "$OUT/result.txt" 2>&1
            ;;
    esac
    cat "$OUT/result.txt"
    checkpoint "after_read_$MODE"
    say '本项目已执行。换版本或换项目请重启；脚本不会连续启用其他项目。'
fi
finish
exit 0
