package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	log "github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
)

func main() {

	wafInstances := make([]WAF, 0)

	configPath := flag.String("c", "", "path to crowdsec-firewall-bouncer.yaml")
	//verbose := flag.Bool("v", false, "set verbose mode")
	//bouncerVersion := flag.Bool("V", false, "display version and exit")
	traceMode := flag.Bool("trace", false, "set trace mode")
	debugMode := flag.Bool("debug", false, "set debug mode")
	testConfig := flag.Bool("t", false, "test config and exit")

	flag.Parse()

	if debugMode != nil && *debugMode {
		log.SetLevel(log.DebugLevel)
	}

	if traceMode != nil && *traceMode {
		log.SetLevel(log.TraceLevel)
	}

	config, err := newConfig(*configPath)

	if err != nil {
		log.Fatalf("could not parse configuration: %s", err)
	}

	if *testConfig {
		log.Info("valid config")
		return
	}

	for _, wafConfig := range config.WebACLConfig {
		log.Debugf("Create WAF instance with config: %+v", wafConfig)
		w, err := NewWaf(wafConfig)
		if err != nil {
			log.Fatalf("could not create waf instance: %s", err)
		}
		err = w.Init()
		if err != nil {
			log.Fatalf("could not initialize waf instance: %s", err)
		}
		wafInstances = append(wafInstances, w)
	}

	bouncer := &csbouncer.StreamBouncer{
		APIKey:             config.APIKey,
		APIUrl:             config.APIUrl,
		TickerInterval:     config.UpdateFrequency,
		InsecureSkipVerify: aws.Bool(config.InsecureSkipVerify),
		UserAgent:          "cs-aws-waf-bouncer/0.0.1",
	}

	if err := bouncer.Init(); err != nil {
		log.Fatalf(err.Error())
	}

	go bouncer.Run()

	t := &tomb.Tomb{}

	t.Go(func() error {
		log.Info("Starting processing decisions")
		for {
			select {
			case <-t.Dying():
				log.Info("tomb is dying")
				return nil
			case decisions := <-bouncer.Stream:
				log.Info("got decisions")
				v4toAdd := make([]*string, 0)
				v6toAdd := make([]*string, 0)
				v4toDelete := make([]*string, 0)
				v6toDelete := make([]*string, 0)
				for _, decision := range decisions.New {
					if strings.Contains(*decision.Value, ":") {
						if !strings.Contains(*decision.Value, "/") {
							v6toAdd = append(v6toAdd, aws.String(fmt.Sprintf("%s/128", *decision.Value)))
						} else {
							v6toAdd = append(v6toAdd, decision.Value)
						}
					} else {
						if !strings.Contains(*decision.Value, "/") {
							v4toAdd = append(v4toAdd, aws.String(fmt.Sprintf("%s/32", *decision.Value)))
						} else {
							v4toAdd = append(v4toAdd, decision.Value)
						}
					}
				}
				for _, decision := range decisions.Deleted {
					if strings.Contains(*decision.Value, ":") {
						if !strings.Contains(*decision.Value, "/") {
							v6toDelete = append(v6toDelete, aws.String(fmt.Sprintf("%s/128", *decision.Value)))
						} else {
							v6toDelete = append(v6toDelete, decision.Value)
						}
					} else {
						if !strings.Contains(*decision.Value, "/") {
							v4toDelete = append(v4toDelete, aws.String(fmt.Sprintf("%s/32", *decision.Value)))
						} else {
							v4toDelete = append(v4toDelete, decision.Value)
						}
					}
				}
				log.Infof("Adding %d IPv4 | Deleting %d IPv4 | Adding %d IPv6 | Deleting %d IPv6", len(v4toAdd), len(v4toDelete), len(v6toAdd), len(v6toDelete))
				for _, waf := range wafInstances {
					err := waf.UpdateSetsContent(v4toAdd, v6toAdd, v4toDelete, v6toDelete)
					if err != nil {
						waf.logger.Errorf("could not update ipset: %s", err)
					}
				}
			}
		}
	})

	err = t.Wait()
	if err != nil {
		log.Error(err)
	}
}
