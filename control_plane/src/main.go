/*
# Copyright 2022-present Ralf Kundel
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
*/
package main

import (
	"net"
	"os"
	"os/signal"
	"p4hc-upf/src/dataplane"
	"p4hc-upf/src/lib"
	"p4hc-upf/src/pfcpClient"
	"syscall"
	"time"

	tofino "p4hc-upf/src/dataplane/tofino/driver"

	log "github.com/sirupsen/logrus"
)

type MainState struct {
	N4Agent *pfcpClient.PfcpAgent
	Tofino  dataplane.DataPlaneInterface
}

func setupPorts(cfg *lib.Config, ms MainState) {
	log.Infoln("Setup Tofino Ports")
	//install downstream rules for all GNBs
	for _, ConnectedGnB := range cfg.UpfConfiguration.GTPu.ConnectedGnB {
		port := cfg.UpfConfiguration.GTPu.SwitchPort
		ms.Tofino.SetupAccessPort(port.Speed, port.PipelinePort, port.Macaddr, net.ParseIP(port.Ipv4addr), port.AutoNeg, net.ParseIP(ConnectedGnB.Ipv4addr))
	}
	for _, dnn := range cfg.UpfConfiguration.DnnList {
		port := dnn.SwitchPort
		ms.Tofino.SetupCorePort(port.Speed, port.PipelinePort, port.Macaddr, net.ParseIP(port.Ipv4addr), port.AutoNeg, net.ParseIP(dnn.NatIP))
	}

	if cfg.UpfConfiguration.QosChip.EnableQoS {
		port := cfg.UpfConfiguration.QosChip.SwitchPort
		fpga_address := cfg.UpfConfiguration.QosChip.PCIeAgentAddress
		ms.Tofino.SetupQoSPort(port.Speed, port.PipelinePort, port.Macaddr, port.AutoNeg, fpga_address)
	}
}

func main() {
	ms := MainState{}
	SetupCloseHandler(&ms)
	argsWithoutProg := os.Args[1:]
	var config_path string
	if len(argsWithoutProg) > 0 {
		config_path = argsWithoutProg[0]
	} else {
		config_path = "config/p4hc-upf.yaml"
	}
	cfg := lib.ParseUpfConfig(config_path)

	level := log.TraceLevel

	switch cfg.UpfConfiguration.LogLevel {
	case "TraceLevel":
		level = log.TraceLevel
	case "DebugLevel":
		level = log.DebugLevel
	case "InfoLevel":
		level = log.InfoLevel
	case "WarnLevel":
		level = log.WarnLevel
	case "ErrorLevel":
		level = log.ErrorLevel
	case "FatalLevel":
		level = log.FatalLevel
	}

	log.SetLevel(level) //TraceLevel, DebugLevel, InfoLevel, WarnLevel, ErrorLevel, FatalLevel

	if cfg.UpfConfiguration.QosChip.EnableQoS {
		ms.Tofino = tofino.NewTofinoFpgaDriver()
	} else {
		ms.Tofino = tofino.NewTofinoDriver()
	}

	slow_port := cfg.UpfConfiguration.SlowPath.SwitchPort
	ms.Tofino.Connect(cfg.UpfConfiguration.TofinoGrpc.Ipv4addr, cfg.UpfConfiguration.TofinoGrpc.GetPort(), net.ParseIP(slow_port.Ipv4addr), net.ParseIP(cfg.UpfConfiguration.SlowPath.Ipv4addr))
	//TODO: cleanup all prefilled tables (e.g. if run_switchd is running longer than the controller)

	ms.Tofino.SetupSlowpath(slow_port.Speed, slow_port.PipelinePort, slow_port.Macaddr, net.ParseIP(slow_port.Ipv4addr), slow_port.AutoNeg, net.ParseIP(cfg.UpfConfiguration.SlowPath.Ipv4addr))
	setupPorts(cfg, ms)

	rib := pfcpClient.NewRIB()
	ms.N4Agent = pfcpClient.NewPfcpAgent(cfg, rib, ms.Tofino)
	ms.N4Agent.Receive()

}

func SetupCloseHandler(ms *MainState) {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		log.Infoln("\r- Ctrl+C pressed in Terminal")

		if ms.Tofino != nil {
			ms.Tofino.Close()
		}

		if ms.N4Agent != nil {
			ms.N4Agent.Close()
		}

		time.Sleep(1 * time.Second)
		os.Exit(0)
	}()
}
