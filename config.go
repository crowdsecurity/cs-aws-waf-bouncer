package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
	"gopkg.in/yaml.v2"
)

type bouncerConfig struct {
	APIKey             string      `yaml:"api_key"`
	APIUrl             string      `yaml:"api_url"`
	UpdateFrequency    string      `yaml:"update_frequency"`
	InsecureSkipVerify bool        `yaml:"insecure_skip_verify"`
	Daemon             bool        `yaml:"daemon"`
	LogLevel           log.Level   `yaml:"log_level"`
	LogMedia           string      `yaml:"log_media"`
	LogDir             string      `yaml:"log_dir"`
	LogMaxSize         int         `yaml:"log_max_size"`
	LogMaxAge          int         `yaml:"log_max_age"`
	LogMaxFiles        int         `yaml:"log_max_backups"`
	CompressLogs       *bool       `yaml:"compress_logs"`
	WebACLConfig       []AclConfig `yaml:"waf_config"`
}

type AclConfig struct {
	WebACLName       string `yaml:"web_acl_name"`
	RuleGroupName    string `yaml:"rule_group_name"`
	Region           string `yaml:"region"`
	Scope            string `yaml:"scope"`
	IpsetPrefix      string `yaml:"ipset_prefix"`
	FallbackAction   string `yaml:"fallback_action"`
	AWSProfile       string `yaml:"aws_profile"`
	IPHeader         string `yaml:"ip_header"`
	IPHeaderPosition string `yaml:"ip_header_position"`
	Capacity         int    `yaml:"capacity"`
}

var validActions = []string{"ban", "captcha"}
var validScopes = []string{"REGIONAL", "CLOUDFRONT"}
var validIpHeaderPosition = []string{"FIRST", "LAST", "ANY"}

func getConfigFromEnv(config *bouncerConfig) {
	var key string
	var value string
	var acl *AclConfig
	var err error
	acls := make(map[byte]*AclConfig, 0)

	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "BOUNCER_") {
			s := strings.Split(env, "=")
			if len(s) == 2 {
				key = strings.Split(env, "=")[0]
				value = strings.Split(env, "=")[1]
			} else {
				log.Warnf("Invalid environment variable: %s", env)
				continue
			}
			if strings.HasPrefix(key, "BOUNCER_WAF_CONFIG_") {
				k2 := strings.TrimPrefix(key, "BOUNCER_WAF_CONFIG_")
				if k2[0] < '0' || k2[0] > '9' || len(k2) < 3 {
					log.Warnf("Invalid name for %s: BOUNCER_WAF_CONFIG_* must be in the form BOUNCER_WAF_CONFIG_0_XXX, BOUNCER_WAF_CONFIG_1_XXX", key)
				}
				if _, ok := acls[k2[0]]; !ok {
					acl = &AclConfig{}
					acls[k2[0]] = acl
				} else {
					acl = acls[k2[0]]
				}
				k2 = k2[2:]
				switch k2 {
				case "WEB_ACL_NAME":
					acl.WebACLName = value
				case "RULE_GROUP_NAME":
					acl.RuleGroupName = value
				case "REGION":
					acl.Region = value
				case "SCOPE":
					acl.Scope = value
				case "IPSET_PREFIX":
					acl.IpsetPrefix = value
				case "FALLBACK_ACTION":
					acl.FallbackAction = value
				case "AWS_PROFILE":
					acl.AWSProfile = value
				case "IP_HEADER":
					acl.IPHeader = value
				case "IP_HEADER_POSITION":
					acl.IPHeaderPosition = value
				case "CAPACITY":
					acl.Capacity, err = strconv.Atoi(value)
					if err != nil {
						log.Warnf("Invalid value for %s: %s", key, value)
						acl.Capacity = 300
					}
				}
			} else {
				switch key {
				case "BOUNCER_API_KEY":
					config.APIKey = value
				case "BOUNCER_API_URL":
					config.APIUrl = value
				case "BOUNCER_UPDATE_FREQUENCY":
					config.UpdateFrequency = value
				case "BOUNCER_INSECURE_SKIP_VERIFY":
					config.InsecureSkipVerify = value == "true"
				case "BOUNCER_DAEMON":
					config.Daemon = value == "true"
				case "BOUNCER_LOG_LEVEL":
					level, err := log.ParseLevel(value)
					if err != nil {
						log.Warnf("Invalid log level: %s, using INFO", value)
						config.LogLevel = log.InfoLevel
					} else {
						config.LogLevel = level
					}
				case "BOUNCER_LOG_MEDIA":
					config.LogMedia = value
				case "BOUNCER_LOG_DIR":
					config.LogDir = value
				case "BOUNCER_LOG_MAX_SIZE":
					config.LogMaxSize, err = strconv.Atoi(value)
					if err != nil {
						log.Warnf("Invalid log max size from env: %s, using 40", value)
						config.LogMaxSize = 40
					}
				case "BOUNCER_LOG_MAX_AGE":
					config.LogMaxAge, err = strconv.Atoi(value)
					if err != nil {
						log.Warnf("Invalid log max age from env: %s, using 7", value)
						config.LogMaxAge = 7
					}
				case "BOUNCER_LOG_MAX_FILES":
					config.LogMaxFiles, err = strconv.Atoi(value)
					if err != nil {
						log.Warnf("Invalid log max files from env: %s, using 7", value)
						config.LogMaxFiles = 7
					}
				case "BOUNCER_COMPRESS_LOGS":
					config.CompressLogs = aws.Bool(value == "true")
				}
			}
		}
	}
	for _, v := range acls {
		config.WebACLConfig = append(config.WebACLConfig, *v)
	}
}

func newConfig(configPath string) (bouncerConfig, error) {
	var config bouncerConfig
	ipsetPrefix := make(map[string]bool)
	ruleGroupNames := make(map[string]bool)

	if configPath != "" {
		content, err := os.ReadFile(configPath)
		if err != nil {
			return bouncerConfig{}, err
		}
		err = yaml.UnmarshalStrict(content, &config)
		if err != nil {
			return bouncerConfig{}, err
		}
	}

	getConfigFromEnv(&config)

	if config.LogMedia == "" {
		config.LogMedia = "stdout"
	}

	if config.LogLevel == 0 {
		config.LogLevel = log.InfoLevel
	}

	if err := types.SetDefaultLoggerConfig(config.LogMedia, config.LogDir, config.LogLevel, config.LogMaxSize, config.LogMaxFiles, config.LogMaxAge, config.CompressLogs); err != nil {
		log.Fatal(err.Error())
	}

	if config.LogMedia == "file" {
		if config.LogDir == "" {
			config.LogDir = "/var/log/"
		}
		_maxsize := 40
		if config.LogMaxSize != 0 {
			_maxsize = config.LogMaxSize
		}
		_maxfiles := 3
		if config.LogMaxFiles != 0 {
			_maxfiles = config.LogMaxFiles
		}
		_maxage := 30
		if config.LogMaxAge != 0 {
			_maxage = config.LogMaxAge
		}
		_compress := true
		if config.CompressLogs != nil {
			_compress = *config.CompressLogs
		}
		logOutput := &lumberjack.Logger{
			Filename:   config.LogDir + "/crowdsec-aws-waf-bouncer.log",
			MaxSize:    _maxsize,
			MaxBackups: _maxfiles,
			MaxAge:     _maxage,
			Compress:   _compress,
		}
		log.SetOutput(logOutput)
		log.SetFormatter(&log.TextFormatter{TimestampFormat: "02-01-2006 15:04:05", FullTimestamp: true})
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

	if len(config.WebACLConfig) == 0 {
		return bouncerConfig{}, fmt.Errorf("waf_config is required")
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

		if c.IPHeader != "" && c.IPHeaderPosition == "" {
			return bouncerConfig{}, fmt.Errorf("ip_header_position is required when ip_header is set")
		}

		if c.IPHeaderPosition != "" && !contains(validIpHeaderPosition, c.IPHeaderPosition) {
			return bouncerConfig{}, fmt.Errorf("ip_header_position must be one of %v", validIpHeaderPosition)
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
		if _, ok := ipsetPrefix[c.IpsetPrefix]; ok {
			return bouncerConfig{}, fmt.Errorf("ipset_prefix value must be unique")
		} else {
			ipsetPrefix[c.IpsetPrefix] = true
		}
		if _, ok := ruleGroupNames[c.RuleGroupName]; ok {
			return bouncerConfig{}, fmt.Errorf("rule_group_name value must be unique")
		} else {
			ruleGroupNames[c.RuleGroupName] = true
		}

		if c.Capacity == 0 {
			c.Capacity = 300
		}
	}
	return config, nil
}
