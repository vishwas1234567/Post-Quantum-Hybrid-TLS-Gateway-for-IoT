"""Read CPU time and memory of the gateway process, locally or in a container.

target formats:
    pid:1234            a local process
    docker:gateway-pqc  PID 1 inside that container (the gateway execs into PID 1)
"""
import os
import subprocess

try:
    CLK_TCK = os.sysconf("SC_CLK_TCK")
except (ValueError, OSError, AttributeError):
    CLK_TCK = 100


def _parse(stat_text, status_text):
    # /proc/PID/stat: the 2nd field (comm) may contain spaces -> split after ')'
    fields = stat_text.rsplit(")", 1)[1].split()
    utime, stime = int(fields[11]), int(fields[12])      # fields 14 and 15
    kb = {}
    for line in status_text.splitlines():
        if line.startswith(("VmRSS:", "VmHWM:")):
            kb[line.split(":")[0]] = int(line.split()[1])
    return {"cpu_s": (utime + stime) / CLK_TCK,
            "rss_kb": kb.get("VmRSS", 0), "hwm_kb": kb.get("VmHWM", 0)}


def read_proc(target):
    kind, _, ref = target.partition(":")
    if kind == "pid":
        with open("/proc/%s/stat" % ref) as a, open("/proc/%s/status" % ref) as b:
            return _parse(a.read(), b.read())
    if kind == "docker":
        out = subprocess.run(
            ["docker", "exec", ref, "sh", "-c",
             "cat /proc/1/stat; echo ===; cat /proc/1/status"],
            capture_output=True, text=True, check=True).stdout
        stat, status = out.split("===", 1)
        return _parse(stat, status)
    raise ValueError("bad target %r" % target)
