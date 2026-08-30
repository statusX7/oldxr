//go:build linux

package main

import (
	"expvar"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

var (
	runtimePolicyGOMAXPROCS   = expvar.NewInt("oldxr_gomaxprocs")
	runtimePolicyEffectiveCPU = expvar.NewInt("oldxr_effective_cpus")
	runtimePolicyAutoApplied  = expvar.NewInt("oldxr_gomaxprocs_auto_applied")
	runtimePolicyOwnerEnabled = expvar.NewInt("oldxr_socket_owner_enabled")
)

func applyRuntimePolicy() {
	ownerEnabled := false
	effectiveCPUs := effectiveCPUCount()
	// Go's default scheduler width preserves throughput headroom across the
	// supported CPU matrix. Operators can still set GOMAXPROCS explicitly.
	runtimePolicyAutoApplied.Set(0)
	runtimePolicyGOMAXPROCS.Set(int64(runtime.GOMAXPROCS(0)))
	runtimePolicyEffectiveCPU.Set(int64(effectiveCPUs))
	if ownerEnabled {
		runtimePolicyOwnerEnabled.Set(1)
	} else {
		runtimePolicyOwnerEnabled.Set(0)
	}
}

func effectiveCPUCount() int {
	available := runtime.NumCPU()
	quota, period, ok := currentCPUQuota()
	if !ok || quota <= 0 || period <= 0 {
		return available
	}
	limited := int(quota / period)
	if limited < 1 {
		limited = 1
	}
	if limited < available {
		return limited
	}
	return available
}

func currentCPUQuota() (int64, int64, bool) {
	for _, candidate := range currentCgroupCandidates() {
		if candidate.v2 {
			contents, err := os.ReadFile(filepath.Join(candidate.path, "cpu.max"))
			if err != nil {
				continue
			}
			return parseCPUQuotaV2(string(contents))
		}
		quotaContents, quotaErr := os.ReadFile(filepath.Join(candidate.path, "cpu.cfs_quota_us"))
		periodContents, periodErr := os.ReadFile(filepath.Join(candidate.path, "cpu.cfs_period_us"))
		if quotaErr != nil || periodErr != nil {
			continue
		}
		quota, quotaErr := strconv.ParseInt(strings.TrimSpace(string(quotaContents)), 10, 64)
		period, periodErr := strconv.ParseInt(strings.TrimSpace(string(periodContents)), 10, 64)
		if quotaErr == nil && periodErr == nil && quota > 0 && period > 0 {
			return quota, period, true
		}
	}
	return 0, 0, false
}

type cgroupCandidate struct {
	path string
	v2   bool
}

func currentCgroupCandidates() []cgroupCandidate {
	candidates := make([]cgroupCandidate, 0, 8)
	contents, _ := os.ReadFile("/proc/self/cgroup")
	for _, line := range strings.Split(string(contents), "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 {
			continue
		}
		relative := strings.TrimPrefix(filepath.Clean("/"+fields[2]), "/")
		if fields[0] == "0" && fields[1] == "" {
			candidates = append(candidates, cgroupCandidate{path: filepath.Join("/sys/fs/cgroup", relative), v2: true})
			continue
		}
		controllers := "," + fields[1] + ","
		if strings.Contains(controllers, ",cpu,") {
			candidates = append(candidates,
				cgroupCandidate{path: filepath.Join("/sys/fs/cgroup/cpu", relative)},
				cgroupCandidate{path: filepath.Join("/sys/fs/cgroup/cpu,cpuacct", relative)},
			)
		}
	}
	candidates = append(candidates,
		cgroupCandidate{path: "/sys/fs/cgroup", v2: true},
		cgroupCandidate{path: "/sys/fs/cgroup/cpu"},
		cgroupCandidate{path: "/sys/fs/cgroup/cpu,cpuacct"},
	)
	return candidates
}

func parseCPUQuotaV2(contents string) (int64, int64, bool) {
	fields := strings.Fields(contents)
	if len(fields) != 2 || fields[0] == "max" {
		return 0, 0, false
	}
	quota, quotaErr := strconv.ParseInt(fields[0], 10, 64)
	period, periodErr := strconv.ParseInt(fields[1], 10, 64)
	if quotaErr != nil || periodErr != nil || quota <= 0 || period <= 0 {
		return 0, 0, false
	}
	return quota, period, true
}
