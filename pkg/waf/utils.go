package waf

import (
	wafv2types "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
)

func removesString(slice []string, s string) []string {
	for i, item := range slice {
		if item == s {
			return append(slice[:i], slice[i+1:]...)
		}
	}

	return slice
}

func removeRuleFromRuleGroup(rules []wafv2types.Rule, name string) []wafv2types.Rule {
	for i, r := range rules {
		if *r.Name == name {
			return append(rules[:i], rules[i+1:]...)
		}
	}

	return rules
}

func removeIpSetFromSlice(sets []*WAFIpSet, ipset *WAFIpSet) []*WAFIpSet {
	for i, s := range sets {
		if s == ipset {
			return append(sets[:i], sets[i+1:]...)
		}
	}

	return sets
}

func uniqueSlice[S comparable](s []S) []S {
	m := make(map[S]bool)
	for _, v := range s {
		if _, ok := m[v]; !ok {
			m[v] = true
		}
	}

	var result []S
	for k := range m {
		result = append(result, k)
	}

	return result
}
