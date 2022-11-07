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
package slowpath

import (
	"net"

	log "github.com/sirupsen/logrus"
)

type ArpCache struct {
	ownPorts  []SwitchPort
	knownMACs []arpEntry
}

type SwitchPort struct {
	p4_port uint16
	mac     string
	ipv4    net.IP
	access  bool
	core    bool
}

type arpEntry struct {
	p4_port uint16
	mac     string
	ipv4    net.IP
}

func NewArpCache() ArpCache {
	c := ArpCache{}
	return c

}

func (me *ArpCache) AddOwnPort(p4_port uint16, mac string, ipv4 net.IP, access bool, core bool) {
	sp := SwitchPort{
		p4_port: p4_port,
		mac:     mac,
		ipv4:    ipv4,
		access:  access,
		core:    core,
	}
	me.ownPorts = append(me.ownPorts, sp)

}

func (me *ArpCache) Find(ipv4 net.IP) (string, uint16) {

	for _, x := range me.knownMACs {
		if x.ipv4.Equal(ipv4) {
			return x.mac, x.p4_port
		}
	}

	return "", uint16(0)
}

func (me *ArpCache) Learn(mac string, ip net.IP, p4_port uint16) {
	for _, x := range me.knownMACs {
		if x.ipv4.Equal(ip) {
			x.p4_port = p4_port
			x.mac = mac
			return
		}
	}

	ae := arpEntry{
		p4_port: p4_port,
		mac:     mac,
		ipv4:    ip,
	}
	me.knownMACs = append(me.knownMACs, ae)
	log.Debugln("[ARP-cache] known MACs:")
	log.Debugln(me.knownMACs)
}

func (me *ArpCache) GetOwn(ipv4 net.IP, port uint16) string {
	for _, x := range me.ownPorts {
		if x.ipv4.Equal(ipv4) && port == x.p4_port {
			return x.mac
		}
	}

	return ""
}

func (me *ArpCache) GetSwitchPorts() []SwitchPort {
	return me.ownPorts
}
