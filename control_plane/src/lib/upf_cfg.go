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
package lib

import (
	"io/ioutil"
	"strconv"

	"gopkg.in/yaml.v2"
)

type Config struct {
	Info             Info             `yaml:"info"`
	UpfConfiguration UpfConfiguration `yaml:"configuration"`
}
type Info struct {
	Version string `yaml:"version"`

	Description string `yaml:"description"`
}

type UpfConfiguration struct {
	UpfName     string            `yaml:"upfName"`
	LogLevel    string            `yaml:"logLevel"`
	N4Interface N4InterfaceConfig `yaml:"N4Interface"`
	TofinoGrpc  TofinoGrpcConfig  `yaml:"tofino_grpc"`
	GTPu        Gtpu              `yaml:"gtpu"`
	DnnList     []DnnConfig       `yaml:"dnn_list"`
	SlowPath    SlowPathConfig    `yaml:"slowpath_connection"`
	QosChip     QosChipConfig     `yaml:"qos_chip"`
}

type QosChipConfig struct {
	EnableQoS        bool       `yaml:"enable_qos"`
	PCIeAgentAddress string     `yaml:"addr"`
	SwitchPort       SwitchPort `yaml:"switch_port"`
}

type SlowPathConfig struct {
	SwitchPort SwitchPort `yaml:"switch_port"`
	Ipv4addr   string     `yaml:"sp_ipv4"`
}

type N4InterfaceConfig struct {
	Ipv4addr string `yaml:"addr"`
	Port     string `yaml:"port"`
}

type TofinoGrpcConfig struct {
	Ipv4addr string `yaml:"addr"`
	Port     string `yaml:"port"`
}

func (me *TofinoGrpcConfig) GetPort() int {
	i, err := strconv.Atoi(me.Port)
	_ = err
	return i
}

type Gtpu struct {
	SwitchPort   SwitchPort `yaml:"switch_port"`
	ConnectedGnB []L23Tuple `yaml:"connected_gnb"`
}

type L23Tuple struct {
	Ipv4addr string `yaml:"addr"`
	Macaddr  string `yaml:"mac_addr"`
}

type SwitchPort struct {
	Ipv4addr     string `yaml:"addr"`
	Macaddr      string `yaml:"mac_addr"`
	PipelinePort uint16 `yaml:"pipeline_port"`
	ChassisPort  string `yaml:"chassis_port"`
	AutoNeg      string `yaml:"autoneg"`
	Speed        string `yaml:"link_speed"`
}

type DnnConfig struct {
	DnnName    string     `yaml:"dnn"`
	Cidr       string     `yaml:"cidr"`
	SwitchPort SwitchPort `yaml:"switch_port"`
	NatIP      string     `yaml:"nat_ip"`
}

func ParseUpfConfig(f string) (parsedConfig *Config) {
	content, err := ioutil.ReadFile(f)
	_ = err
	parsedConfig = &Config{}
	err = yaml.Unmarshal([]byte(content), &parsedConfig)

	return parsedConfig
}
