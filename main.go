package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/coreos/go-systemd/v22/daemon"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/crowdsecurity/cs-aws-waf-bouncer/pkg/version"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

type Decisions struct {
	v4Add        map[string][]*string
	v6Add        map[string][]*string
	v4Del        map[string][]*string
	v6Del        map[string][]*string
	countriesAdd map[string][]*string
	countriesDel map[string][]*string
}

var wafInstances []*WAF = make([]*WAF, 0)

func cleanup() {
	for _, waf := range wafInstances {
		waf.logger.Infof("Cleaning up ressources")
		err := waf.Cleanup()
		if err != nil {
			log.Errorf("Error cleaning up WAF: %s", err)
		}
	}
	os.Exit(0)
}

func signalHandler() {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan,
		syscall.SIGTERM,
		syscall.SIGINT)
	go func() {
		<-signalChan
		log.Info("Received SIGTERM, exiting")
		cleanup()
	}()
}

func processDecisions(decisions *models.DecisionsStreamResponse, supportedActions []string) Decisions {
	d := Decisions{
		v4Add:        make(map[string][]*string),
		v6Add:        make(map[string][]*string),
		v4Del:        make(map[string][]*string),
		v6Del:        make(map[string][]*string),
		countriesAdd: make(map[string][]*string),
		countriesDel: make(map[string][]*string),
	}

	for _, decision := range decisions.New {
		decisionType := strings.ToLower(*decision.Type)
		if !contains(supportedActions, decisionType) {
			decisionType = "fallback"
		}
		if strings.ToLower(*decision.Scope) == "ip" || strings.ToLower(*decision.Scope) == "range" {
			if strings.Contains(*decision.Value, ":") {
				if !strings.Contains(*decision.Value, "/") {
					d.v6Add[decisionType] = append(d.v6Add[decisionType], aws.String(fmt.Sprintf("%s/128", *decision.Value)))
				} else {
					d.v6Add[decisionType] = append(d.v6Add[decisionType], decision.Value)
				}
			} else {
				if !strings.Contains(*decision.Value, "/") {
					d.v4Add[decisionType] = append(d.v4Add[decisionType], aws.String(fmt.Sprintf("%s/32", *decision.Value)))
				} else {
					d.v4Add[decisionType] = append(d.v4Add[decisionType], decision.Value)
				}
			}
		} else if strings.ToLower(*decision.Scope) == "country" {
			d.countriesAdd[decisionType] = append(d.countriesAdd[decisionType], decision.Value)
		} else {
			log.Errorf("unsupported scope: %s", *decision.Scope)
		}
	}

	for _, decision := range decisions.Deleted {
		decisionType := strings.ToLower(*decision.Type)
		if !contains(supportedActions, decisionType) {
			decisionType = "fallback"
		}
		if strings.ToLower(*decision.Scope) == "ip" || strings.ToLower(*decision.Scope) == "range" {
			if strings.Contains(*decision.Value, ":") {
				if !strings.Contains(*decision.Value, "/") {
					d.v6Del[decisionType] = append(d.v6Del[decisionType], aws.String(fmt.Sprintf("%s/128", *decision.Value)))
				} else {
					d.v6Del[decisionType] = append(d.v6Del[decisionType], decision.Value)
				}
			} else {
				if !strings.Contains(*decision.Value, "/") {
					d.v4Del[decisionType] = append(d.v4Del[decisionType], aws.String(fmt.Sprintf("%s/32", *decision.Value)))
				} else {
					d.v4Del[decisionType] = append(d.v4Del[decisionType], decision.Value)
				}
			}
		} else if strings.ToLower(*decision.Scope) == "country" {
			d.countriesDel[decisionType] = append(d.countriesDel[decisionType], decision.Value)
		} else {
			log.Errorf("unsupported scope: %s", *decision.Scope)
		}
	}

	return d
}

func main() {
	configPath := flag.String("c", "", "path to crowdsec-aws-waf-bouncer.yaml")
	bouncerVersion := flag.Bool("version", false, "display version and exit")
	traceMode := flag.Bool("trace", false, "set trace mode")
	debugMode := flag.Bool("debug", false, "set debug mode")
	testConfig := flag.Bool("t", false, "test config and exit")

	flag.Parse()

	if *bouncerVersion {
		fmt.Printf("%s", version.ShowStr())
		os.Exit(0)
	}

	config, err := newConfig(*configPath)

	if debugMode != nil && *debugMode {
		log.SetLevel(log.DebugLevel)
	}

	if traceMode != nil && *traceMode {
		log.SetLevel(log.TraceLevel)
	}

	if err != nil {
		log.Fatalf("could not parse configuration: %s", err)
	}

	if *testConfig {
		for _, wafConfig := range config.WebACLConfig {
			log.Debugf("Create WAF instance with config: %+v", wafConfig)
			_, err := NewWaf(wafConfig)
			if err != nil {
				log.Fatalf("Configuration error: %s", err)
			}
		}
		log.Info("valid config")
		return
	}

	bouncer := &csbouncer.StreamBouncer{
		APIKey:             config.APIKey,
		APIUrl:             config.APIUrl,
		TickerInterval:     config.UpdateFrequency,
		InsecureSkipVerify: aws.Bool(config.InsecureSkipVerify),
		UserAgent:          fmt.Sprintf("crowdsec-aws-waf-bouncer/%s", version.VersionStr()),
		Scopes:             []string{"ip", "range", "country"},
		CertPath:           config.CertPath,
		KeyPath:            config.KeyPath,
		CAPath:             config.CAPath,
	}

	if err := bouncer.Init(); err != nil {
		log.Fatalf(err.Error())
	}

	defer cleanup()

	for _, wafConfig := range config.WebACLConfig {
		log.Debugf("Create WAF instance with config: %+v", wafConfig)
		w, err := NewWaf(wafConfig)
		if err != nil {
			log.Errorf("could not create waf instance: %s", err)
			return
		}
		err = w.Init()
		if err != nil {
			log.Errorf("could not initialize waf instance: %s", err)
		}
		wafInstances = append(wafInstances, w)
	}

	g, ctx := errgroup.WithContext(context.Background())

	go signalHandler()

	g.Go(func() error {
		bouncer.Run(ctx)
		return fmt.Errorf("stream api init failed")
	})

	if config.Daemon {
		sent, err := daemon.SdNotify(false, "READY=1")
		if !sent && err != nil {
			log.Warnf("failed to notify: %v", err)
		}
	}

	g.Go(func() error {
		log.Info("Starting processing decisions")
		for {
			select {
			case <-ctx.Done():
				log.Info("terminating bouncer process")
				for _, w := range wafInstances {
					w.t.Kill(nil)
				}
				return nil
			case decisions := <-bouncer.Stream:
				log.Info("Polling decisions")

				d := processDecisions(decisions, config.SupportedActions)
				for _, w := range wafInstances {
					w.decisionsChan <- d
				}
			}
		}
	})

	if err := g.Wait(); err != nil {
		log.Fatalf("process return with error: %s", err)
	}
}
