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

type AclConfig struct {
	WebACLName     string `yaml:"web_acl_name"`
	RuleGroupName  string `yaml:"rule_group_name"`
	Region         string `yaml:"region"`
	Scope          string `yaml:"scope"`
	IpsetPrefix    string `yaml:"ipset_prefix"`
	FallbackAction string `yaml:"fallback_action"`
}

var validActions = []string{"ban", "captcha"}
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
		if c.FallbackAction == "" {
			return bouncerConfig{}, fmt.Errorf("fallback_action is required")
		}
		if !contains(validActions, c.FallbackAction) {
			return bouncerConfig{}, fmt.Errorf("fallback_action must be one of %v", validActions)
		}
		if c.RuleGroupName == "" {
			return bouncerConfig{}, fmt.Errorf("rule_group_name is required")
		}
		if c.Scope == "" {
			return bouncerConfig{}, fmt.Errorf("scope is required")
		}
		if !contains(validScopes, c.Scope) {
			return bouncerConfig{}, fmt.Errorf("scope must be one of %v", validScopes)
		}
		if c.IpsetPrefix == "" {
			return bouncerConfig{}, fmt.Errorf("ipset_prefix is required")
		}
		if c.Region == "" && strings.ToUpper(c.Scope) == "REGIONAL" {
			return bouncerConfig{}, fmt.Errorf("region is required when scope is REGIONAL")
		}
		/*if c.Action.CustomBodyFile != "" && strings.ToUpper(c.Action.Type) != "BLOCK" {
			return bouncerConfig{}, fmt.Errorf("custom_body_file is only valid when action is BLOCK")
		}*/
	}
	return config, nil
}
