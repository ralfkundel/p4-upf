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

package pfcpClient

import (
	"fmt"
	"net"
)

type PDR_HASH_ID struct {
	SEID_ID uint64
	PDR_ID  uint16
}

type PDR struct {
	//SEID
	SEID_IPv4 net.IP
	SEID_ID   uint64

	PDR_ID                         uint16
	Precedence                     uint32 //unused
	OuterHeaderRemovalForDetection bool
	SourceType                     uint8 //0=access, 1=core, 3=CP
	Source_Network_Instance        *UserPlaneResourceInformation
	UeIpAddress_v4                 net.IP
	FAR_ID                         uint32
	QER_ID                         uint32

	//upstream ++:
	PdiTEID uint32
	PdiIPv4 net.IP //dstIP = UPF

	NeedsUpdate bool
}

func NewPDR(SEID_IPv4 net.IP, SEID_ID uint64, pdr_id uint16, far_id uint32, qer_id uint32, precedence uint32, outerHeaderRemoval bool) *PDR {
	new_pdr := PDR{}

	new_pdr.SEID_IPv4 = make(net.IP, len(SEID_IPv4))
	copy(new_pdr.SEID_IPv4, SEID_IPv4)

	new_pdr.SEID_ID = SEID_ID
	new_pdr.PDR_ID = pdr_id
	new_pdr.FAR_ID = far_id
	new_pdr.QER_ID = qer_id //0 means --> no QER
	new_pdr.Precedence = precedence
	new_pdr.OuterHeaderRemovalForDetection = outerHeaderRemoval

	return &new_pdr
}

func (me *PDR) getPdrId() PDR_HASH_ID {
	ret := PDR_HASH_ID{SEID_ID: me.SEID_ID, PDR_ID: me.PDR_ID}
	return ret
}

func (me *PDR) isDownstream() bool { //TODO: a enum would be cooler
	if me.SourceType == 1 {
		return true
	}
	return false
}

func (me *PDR) isUpstream() bool {
	if me.SourceType == 0 {
		return true
	}
	return false
}

func (me *PDR) isCPfunction() bool {
	if me.SourceType == 3 {
		return true
	}
	return false
}

func (me *PDR) SetFTEID(tobesetIP net.IP, tobeSetTEID uint32) {
	me.PdiIPv4 = make(net.IP, len(tobesetIP))
	copy(me.PdiIPv4, tobesetIP)
	me.PdiTEID = tobeSetTEID
}

func (me *PDR) SetUeIP(new_ue_ipv4 net.IP) {
	me.UeIpAddress_v4 = make(net.IP, len(new_ue_ipv4))
	copy(me.UeIpAddress_v4, new_ue_ipv4)
}

func (me *PDR) IsComplete() bool {
	if me.isDownstream() {
		var ueIp_v4_b []byte
		ueIp_v4_b = me.UeIpAddress_v4.To4()
		if len(ueIp_v4_b) == 0 {
			return false
		}
		return true
	}
	if me.isUpstream() {
		return true
	}
	return false //TODO
}

func (me PDR) String() string {
	return_string := "PDR(ID: " + fmt.Sprint(me.PDR_ID) + ", FAR_ID: " + fmt.Sprint(me.FAR_ID) + ", QER_ID: " + fmt.Sprint(me.QER_ID)

	switch me.SourceType {
	case 0:
		return_string = return_string + ", source: ACCESS(0)"
	case 1:
		return_string = return_string + ", source: CORE(1)"
	case 3:
		return_string = return_string + ", source: CP-function(3)"
	}

	if me.OuterHeaderRemovalForDetection {
		return_string = return_string + ", OuterHeaderRemoval: true, F-TEID: [" + me.PdiIPv4.String() + ", TEID: " + fmt.Sprint(me.PdiTEID) + "]"
	}

	return_string = return_string + ")"
	return return_string
}
