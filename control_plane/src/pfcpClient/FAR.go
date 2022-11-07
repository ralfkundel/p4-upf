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

type FAR_HASH_ID struct {
	SEID_ID uint64
	FAR_ID  uint32
}

type FAR struct { //Forwarding Action Rule
	//SEID
	SEID_IPv4 net.IP
	SEID_ID   uint64

	FAR_ID       uint32
	Apply_Action uint8

	Destination_Interface_Type   uint8 //0 == access, 2==core, compare: 8.2.118 https://www.etsi.org/deliver/etsi_ts/129200_129299/129244/16.04.00_60/ts_129244v160400p.pdf
	Destination_Network_Instance *UserPlaneResourceInformation

	//outer header
	OuterHeaderIPv4 net.IP //destination IP = gNodeB
	OuterHeaderTEID uint32

	NeedsUpdate bool
}

func NewFAR(SEID_IPv4 net.IP, SEID_ID uint64, far_id uint32, apply_action uint8) *FAR {
	new_far := FAR{}
	new_far.SEID_IPv4 = SEID_IPv4
	new_far.SEID_IPv4 = make(net.IP, len(SEID_IPv4))
	copy(new_far.SEID_IPv4, SEID_IPv4)
	new_far.SEID_ID = SEID_ID
	new_far.FAR_ID = far_id
	new_far.Apply_Action = apply_action
	return &new_far
}

func (me *FAR) getFarId() FAR_HASH_ID {
	ret := FAR_HASH_ID{SEID_ID: me.SEID_ID, FAR_ID: me.FAR_ID}
	return ret
}

func (me *FAR) SetOuterHeaderCreation(tobesetIP net.IP, tobeSetTEID uint32) {
	me.OuterHeaderIPv4 = make(net.IP, len(tobesetIP))
	copy(me.OuterHeaderIPv4, tobesetIP)
	me.OuterHeaderTEID = tobeSetTEID
}

func (me *FAR) IsComplete() bool {
	if me.Destination_Interface_Type == 0 && me.OuterHeaderIPv4 != nil && me.OuterHeaderTEID != 0 { //packets to access
		return true
	}
	if me.Destination_Interface_Type == 1 || me.Destination_Interface_Type == 2 { //packets to core     ///&& me.Destination_Network_Instance != nil
		return true
	}
	return false
}

func (me FAR) String() string {
	return_string := "FAR(ID: " + fmt.Sprint(me.FAR_ID) + ", Destination_Interface_Type: " + fmt.Sprint(me.Destination_Interface_Type)

	if me.Apply_Action == 0 {
		return_string = return_string + ", ApplyAction: DROP(0)"
	}
	if me.Apply_Action == 2 {
		return_string = return_string + ", ApplyAction: FORWARD(2)"
	}

	if me.Destination_Network_Instance != nil {
		return_string = return_string + ", DstInterface: " + me.Destination_Network_Instance.dnn_name
	}

	if me.OuterHeaderIPv4 != nil {
		return_string = return_string + ", OuterHeaderCreation: [" + me.OuterHeaderIPv4.String() + ", TEID: " + fmt.Sprint(me.OuterHeaderTEID) + "]"
	}

	return_string = return_string + ")"
	return return_string
}
