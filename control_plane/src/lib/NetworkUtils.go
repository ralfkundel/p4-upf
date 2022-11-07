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
	"net"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"
)

func GetMacAddr(ipv4 string) (string, error) {
	ifas, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, ifa := range ifas {
		addrs, _ := ifa.Addrs()
		for _, addr := range addrs {
			if strings.Contains(addr.String(), ipv4) {
				return ifa.HardwareAddr.String(), nil
			}
		}

	}
	return "ff:ff:ff:ff:ff:ff", nil
}

func AddSystemArpEntry(ipv4 net.IP, mac string) {
	//"arp -s 172.16.5.80 ca:fe:ba:be:22:09"
	app := "arp"
	arg0 := "-s"
	arg1 := ipv4.To4().String()
	cmd := exec.Command("sudo", app, arg0, arg1, mac)
	stdout, err := cmd.Output()

	if err != nil {
		log.Warnln(err.Error())
		log.Warnln("did you run the init.sh script?")
		log.Warnln("Failed in adding a arp entry")
	}

	// Print the output
	log.Infoln(string(stdout))
}
