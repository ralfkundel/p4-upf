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

package dataplane

import (
	"net"
)

type DataPlaneInterface interface {
	Close()
	Connect(host string, port int, upf_ip net.IP, sp_ip net.IP)

	SetupQoSPort(LinkSpeed string, p4_port uint16, mac string, auto_negotiation string, fpga_addr string)
	SetupAccessPort(LinkSpeed string, p4_port uint16, mac string, ipv4 net.IP, auto_negotiation string, GnbIP net.IP)
	SetupCorePort(LinkSpeed string, p4_port uint16, mac string, ipv4 net.IP, auto_negotiation string, NatIP net.IP)
	SetupSlowpath(LinkSpeed string, p4_port uint16, upf_mac string, upf_ip net.IP, auto_negotiation string, sp_ip net.IP)

	InstallDownstreamSubscriber(ue_ip net.IP, teid uint32, upfIP net.IP, gNodeBIP net.IP, update bool)
	InstallDownstreamQoS(teid uint32, sessionMBRDL uint64)
	InstallUpstreamSubscriber(gNodeBPort uint16, ue_ip net.IP, teid uint32, update bool)

	DeleteDownstreamSubscriber(ue_ip net.IP)
	DeleteUpstreamSubscriber(gnodeb_port uint16, ue_ip net.IP, teid uint32)
}
