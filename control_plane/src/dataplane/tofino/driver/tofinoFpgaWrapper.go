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

package tofino

import (
	"net"
	"p4hc-upf/src/dataplane/fpga"
	"p4hc-upf/src/dataplane/slowpath"
	"p4hc-upf/src/lib"
	"time"

	log "github.com/sirupsen/logrus"
)

type TofinoFpgaWrapper struct {
	Tofino        AsicDriver
	slowPath      *slowpath.SlowPath
	fpgaDriver    *fpga.FpgaDriver
	fpga_port     uint16
	next_free_qid uint32
}

func NewTofinoFpgaDriver() *TofinoFpgaWrapper {
	tofinoWrapper := TofinoFpgaWrapper{}
	return &tofinoWrapper
}

func (me *TofinoFpgaWrapper) Connect(host string, grpc_port int, switch_sp_ip net.IP, sp_ip net.IP) {
	me.Tofino = NewAsicDriver()
	me.Tofino.Connect(host, grpc_port)

	if me.slowPath != nil {
		me.slowPath.Terminate()
	}
	me.slowPath = slowpath.NewSlowPath(sp_ip, switch_sp_ip)

	me.fpgaDriver = fpga.NewFpgaDriver()
}

func (me *TofinoFpgaWrapper) Close() {
	log.Infoln("Close TofinoFPGA Wrapper")
	me.Tofino.Close()
	me.slowPath.Terminate()
	if me.fpgaDriver != nil {
		me.fpgaDriver.Terminate()
	}

}

func (me *TofinoFpgaWrapper) SetupSlowpath(LinkSpeed string, p4_port uint16, upf_mac string, upf_ip net.IP, auto_negotiation string, sp_ip net.IP) {
	me.slowPath.StartListener()

	sp_mac, _ := lib.GetMacAddr(sp_ip.To4().String()) //TODO check: must be a valid IP on the controller
	log.Infoln("sp_mac:")
	log.Infoln(sp_mac)
	me.Tofino.SetupSlowpath(LinkSpeed, p4_port, upf_mac, upf_ip, auto_negotiation, sp_ip, sp_mac)
	lib.AddSystemArpEntry(upf_ip, upf_mac)
}

func (me *TofinoFpgaWrapper) SetupQoSPort(LinkSpeed string, p4_port uint16, mac string, auto_negotiation string, fpga_addr string) {
	me.Tofino.SetupPort(LinkSpeed, p4_port, mac, auto_negotiation)
	me.Tofino.ConfigureQosChipPort(p4_port)
	me.fpgaDriver.StartFpgaDriver(fpga_addr)
	me.fpga_port = p4_port
	me.next_free_qid = 0
}

func (me *TofinoFpgaWrapper) SetupAccessPort(LinkSpeed string, p4_port uint16, mac string, ipv4 net.IP, auto_negotiation string, GnbIP net.IP) {
	me.slowPath.ArpCache.AddOwnPort(p4_port, mac, ipv4, true, false)
	port := me.Tofino.SetupPort(LinkSpeed, p4_port, mac, auto_negotiation)
	time.Sleep(3 * time.Second)
	GnbMac, _ := me.slowPath.GetMac(GnbIP, true, false) //TODO remove GnoeB --> check in downstream subscriber if known
	if GnbMac == "" {
		log.Warnln("No Mac entry found for gnb IP")
		return
	}
	me.Tofino.SetupAccessPort(port, GnbMac, GnbIP)
}

func (me *TofinoFpgaWrapper) SetupCorePort(LinkSpeed string, p4_port uint16, mac string, ipv4 net.IP, auto_negotiation string, NatIP net.IP) {
	me.slowPath.ArpCache.AddOwnPort(p4_port, mac, ipv4, false, true)
	port := me.Tofino.SetupPort(LinkSpeed, p4_port, mac, auto_negotiation)
	time.Sleep(3 * time.Second)
	NatMac, _ := me.slowPath.GetMac(NatIP, false, true)
	if NatMac == "" {
		log.Warnln("No Mac entry found for NAT IP")
		return
	}
	me.Tofino.SetupCorePort(port, NatMac)
}

func (me *TofinoFpgaWrapper) InstallDownstreamSubscriber(ue_ip net.IP, teid uint32, upfIP net.IP, gNodeBIP net.IP, update bool) {
	me.Tofino.InstallDownstreamSubscriber(ue_ip, teid, upfIP, gNodeBIP, update)
}

func (me *TofinoFpgaWrapper) InstallDownstreamQoS(teid uint32, sessionMBRDL uint64) {
	var qid uint32 = me.next_free_qid //TODO dynamic
	me.next_free_qid = me.next_free_qid + 1
	me.Tofino.InstallFpgaQoSRule(teid, me.fpga_port, qid)
	me.fpgaDriver.SetRateLimit(sessionMBRDL, qid)
}

func (me *TofinoFpgaWrapper) InstallUpstreamSubscriber(gNodeBPort uint16, ue_ip net.IP, teid uint32, update bool) {
	me.Tofino.InstallUpstreamSubscriber(gNodeBPort, ue_ip, teid, update)
}

func (me *TofinoFpgaWrapper) DeleteDownstreamSubscriber(ue_ip net.IP) {
	me.Tofino.DeleteDownstreamSubscriber(ue_ip)
}

func (me *TofinoFpgaWrapper) DeleteUpstreamSubscriber(gnodeb_port uint16, ue_ip net.IP, teid uint32) {
	me.Tofino.DeleteUpstreamSubscriber(gnodeb_port, ue_ip, teid)
}
