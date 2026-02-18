package version

import (
	"strconv"
	"strings"
)

type semver struct {
	major int
	minor int
	patch int
}

func IsOutdated(current, latest string) bool {
	cur, okCur := parseSemver(current)
	lat, okLat := parseSemver(latest)
	if !okCur || !okLat {
		return false
	}
	if cur.major != lat.major {
		return cur.major < lat.major
	}
	if cur.minor != lat.minor {
		return cur.minor < lat.minor
	}
	return cur.patch < lat.patch
}

func parseSemver(v string) (semver, bool) {
	s := strings.TrimSpace(v)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")
	if s == "" {
		return semver{}, false
	}
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) == 0 {
		return semver{}, false
	}
	num := [3]int{}
	for i := 0; i < len(parts) && i < 3; i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil || n < 0 {
			return semver{}, false
		}
		num[i] = n
	}
	return semver{major: num[0], minor: num[1], patch: num[2]}, true
}
