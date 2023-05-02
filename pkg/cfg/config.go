package cfg

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v2"
)

type bouncerConfig struct {
	APIKey             string        `yaml:"api_key"`
	APIUrl             string        `yaml:"api_url"`
	UpdateFrequency    string        `yaml:"update_frequency"`
	InsecureSkipVerify bool          `yaml:"insecure_skip_verify"`
	Daemon             bool          `yaml:"daemon"`
	Logging            LoggingConfig `yaml:",inline"`
	LogLevel           log.Level     `yaml:"log_level"`
	LogMedia           string        `yaml:"log_media"`
	LogDir             string        `yaml:"log_dir"`
	LogMaxSize         int           `yaml:"log_max_size"`
	LogMaxAge          int           `yaml:"log_max_age"`
	LogMaxFiles        int           `yaml:"log_max_backups"`
	CompressLogs       *bool         `yaml:"compress_logs"`
	WebACLConfig       []AclConfig   `yaml:"waf_config"`
	KeyPath            string        `yaml:"key_path"`
	CertPath           string        `yaml:"cert_path"`
	CAPath             string        `yaml:"ca_cert_path"`
	SupportedActions   []string      `yaml:"supported_actions"`
}

type AclConfig struct {
	WebACLName           string `yaml:"web_acl_name"`
	RuleGroupName        string `yaml:"rule_group_name"`
	Region               string `yaml:"region"`
	Scope                string `yaml:"scope"`
	IpsetPrefix          string `yaml:"ipset_prefix"`
	FallbackAction       string `yaml:"fallback_action"`
	AWSProfile           string `yaml:"aws_profile"`
	IPHeader             string `yaml:"ip_header"`
	IPHeaderPosition     string `yaml:"ip_header_position"`
	Capacity             int    `yaml:"capacity"`
	CloudWatchEnabled    bool   `yaml:"cloudwatch_enabled"`
	CloudWatchMetricName string `yaml:"cloudwatch_metric_name"`
	SampleRequests       bool   `yaml:"sample_requests"`
}

var ValidActions = []string{"ban", "captcha", "count"}
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
				case "CLOUDWATCH_ENABLED":
					acl.CloudWatchEnabled, err = strconv.ParseBool(value)
					if err != nil {
						log.Warnf("Invalid value for %s: %s, defaulting to false", key, value)
						acl.CloudWatchEnabled = false
					}
				case "CLOUDWATCH_METRIC_NAME":
					acl.CloudWatchMetricName = value
				case "SAMPLE_REQUESTS":
					acl.SampleRequests, err = strconv.ParseBool(value)
					if err != nil {
						log.Warnf("Invalid value for %s: %s, defaulting to false", key, value)
						acl.SampleRequests = false
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
				case "BOUNCER_CERT_PATH":
					config.CertPath = value
				case "BOUNCER_KEY_PATH":
					config.KeyPath = value
				case "BOUNCER_CA_PATH":
					config.CAPath = value
				case "BOUNCER_SUPPORTED_ACTIONS":
					config.SupportedActions = strings.Split(value, ",")
				}

			}
		}
	}
	for _, v := range acls {
		config.WebACLConfig = append(config.WebACLConfig, *v)
	}
}

func NewConfig(configPath string) (bouncerConfig, error) {
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

	if err := config.Logging.setup("crowdsec-aws-waf-bouncer.log"); err != nil {
		return bouncerConfig{}, err
	}

	if config.APIKey == "" && config.CertPath == "" && config.KeyPath == "" {
		return bouncerConfig{}, fmt.Errorf("api_key or certificates paths are required")
	}

	if config.APIUrl == "" {
		return bouncerConfig{}, fmt.Errorf("api_url is required")
	}

	if !strings.HasSuffix(config.APIUrl, "/") {
		config.APIUrl = config.APIUrl + "/"
	}

	if config.UpdateFrequency == "" {
		config.UpdateFrequency = "10s"
	}

	for _, action := range config.SupportedActions {
		if !slices.Contains(ValidActions, action) {
			return bouncerConfig{}, fmt.Errorf("supported_actions must be a list from %v", ValidActions)
		}
	}

	if len(config.SupportedActions) == 0 {
		config.SupportedActions = ValidActions
	}

	if len(config.WebACLConfig) == 0 {
		return bouncerConfig{}, fmt.Errorf("waf_config is required")
	}
	for _, c := range config.WebACLConfig {
		if c.FallbackAction == "" {
			return bouncerConfig{}, fmt.Errorf("fallback_action is required")
		}
		if !slices.Contains(ValidActions, c.FallbackAction) {
			return bouncerConfig{}, fmt.Errorf("fallback_action must be one of %v", ValidActions)
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

		if c.IPHeaderPosition != "" && !slices.Contains(validIpHeaderPosition, c.IPHeaderPosition) {
			return bouncerConfig{}, fmt.Errorf("ip_header_position must be one of %v", validIpHeaderPosition)
		}

		if !slices.Contains(validScopes, c.Scope) {
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
