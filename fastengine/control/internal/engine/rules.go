package engine

import (
	"bufio"
	"os"
	"regexp"
	"strings"
)

type Rules struct {
	exact map[string]struct{}
	regex []*regexp.Regexp
}

func LoadRules(path string) (*Rules, error) {
	rules := &Rules{exact: make(map[string]struct{})}
	if path == "" {
		return rules, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "regexp:") {
			re, err := regexp.Compile(strings.TrimPrefix(line, "regexp:"))
			if err != nil {
				return nil, err
			}
			rules.regex = append(rules.regex, re)
			continue
		}
		rules.exact[strings.ToLower(line)] = struct{}{}
	}
	return rules, scanner.Err()
}

func (r *Rules) Blocked(host string) bool {
	if r == nil {
		return false
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if _, blocked := r.exact[host]; blocked {
		return true
	}
	for _, re := range r.regex {
		if re.MatchString(host) {
			return true
		}
	}
	return false
}
