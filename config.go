package main

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
)

type bouncerConfig struct {
	APIKey             string      `yaml:"api_key"`
	APIUrl             string      `yaml:"api_url"`
	UpdateFrequency    string      `yaml:"update_frequency"`
	InsecureSkipVerify bool        `yaml:"insecure_skip_verify"`
	Daemon             bool        `yaml:"daemon"`
	LogLevel           string      `yaml:"log_level"`
	LogMedia           string      `yaml:"log_media"`
	LogDir             string      `yaml:"log_dir"`
	WebACLConfig       []AclConfig `yaml:"waf_config"`
}

type ruleAction struct {
	Type           string `yaml:"type"`
	CustomBodyFile string `yaml:"custom_body_file"`
}

type AclConfig struct {
	WebACLName  string `yaml:"web_acl_name"`
	RuleName    string `yaml:"rule_name"`
	Region      string `yaml:"region"`
	Scope       string `yaml:"scope"`
	IPSetConfig struct {
		IPv4SetName   string `yaml:"ipv4_set_name"`
		IPv6SetName   string `yaml:"ipv6_set_name"`
		RuleGroupName string `yaml:"rule_group_name"`
	} `yaml:"ipset_config"`
	Action ruleAction `yaml:"action"`
}

var validActions = []string{"ALLOW", "BLOCK", "COUNT", "CAPTCHA"}
var validScopes = []string{"REGIONAL", "CLOUDFRONT"}

func newConfig(configPath string) (bouncerConfig, error) {
	content, err := os.ReadFile(configPath)
	if err != nil {
		return bouncerConfig{}, err
	}
	var config bouncerConfig
	err = yaml.UnmarshalStrict(content, &config)
	if err != nil {
		return bouncerConfig{}, err
	}
	if config.APIKey == "" {
		return bouncerConfig{}, fmt.Errorf("api_key is required")
	}
	if config.APIUrl == "" {
		return bouncerConfig{}, fmt.Errorf("api_url is required")
	}
	if config.UpdateFrequency == "" {
		config.UpdateFrequency = "10s"
	}
	if config.LogLevel == "" {
		config.LogLevel = "INFO"
	}
	for _, c := range config.WebACLConfig {
		if c.Action.Type == "" {
			return bouncerConfig{}, fmt.Errorf("action is required")
		}
		if !contains(validActions, c.Action.Type) {
			return bouncerConfig{}, fmt.Errorf("action must be one of %v", validActions)
		}
		if c.RuleName == "" {
			return bouncerConfig{}, fmt.Errorf("rule_name is required")
		}
		if c.Scope == "" {
			return bouncerConfig{}, fmt.Errorf("scope is required")
		}
		if !contains(validScopes, c.Scope) {
			return bouncerConfig{}, fmt.Errorf("scope must be one of %v", validScopes)
		}
		if c.IPSetConfig.IPv4SetName == "" {
			return bouncerConfig{}, fmt.Errorf("ipv4_set_name is required")
		}
		if c.IPSetConfig.IPv6SetName == "" {
			return bouncerConfig{}, fmt.Errorf("ipv6_set_name is required")
		}
		if c.IPSetConfig.RuleGroupName == "" {
			return bouncerConfig{}, fmt.Errorf("rule_group_name is required")
		}
		if c.Region == "" && strings.ToUpper(c.Scope) == "REGIONAL" {
			return bouncerConfig{}, fmt.Errorf("region is required when scope is REGIONAL")
		}
		if c.Action.CustomBodyFile != "" && strings.ToUpper(c.Action.Type) != "BLOCK" {
			return bouncerConfig{}, fmt.Errorf("custom_body_file is only valid when action is BLOCK")
		}
	}
	return config, nil
}
