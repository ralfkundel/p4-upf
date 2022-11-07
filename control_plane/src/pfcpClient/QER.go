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

type QER_HASH_ID struct {
	SEID_ID uint64
	QER_ID  uint32
}

type QER struct {
	//SEID
	SEID_IPv4 net.IP
	SEID_ID   uint64

	QER_ID       uint32
	GateStatusDL uint8 //0 = open
	GateStatusUL uint8
	SessionMBRDL uint64
	SessionMBRUL uint64
	QFI          uint8

	NeedsUpdate bool
}

func NewQER(SEID_IPv4 net.IP, SEID_ID uint64, QER_ID uint32, GateStatusDL uint8, GateStatusUL uint8, SessionMBRDL uint64, SessionMBRUL uint64, QFI uint8) *QER {
	newQER := QER{}

	newQER.SEID_IPv4 = make(net.IP, len(SEID_IPv4))
	copy(newQER.SEID_IPv4, SEID_IPv4)
	newQER.SEID_ID = SEID_ID

	newQER.QER_ID = QER_ID
	newQER.GateStatusDL = GateStatusDL
	newQER.GateStatusUL = GateStatusUL
	newQER.SessionMBRDL = SessionMBRDL
	newQER.SessionMBRUL = SessionMBRUL
	newQER.QFI = QFI

	return &newQER
}

func (me *QER) getQerId() QER_HASH_ID {
	ret := QER_HASH_ID{SEID_ID: me.SEID_ID, QER_ID: me.QER_ID}
	return ret
}

func (me QER) String() string {
	return_string := "QER(ID: " + fmt.Sprint(me.QER_ID) + " QFI: " + fmt.Sprint(me.QFI)

	return_string = return_string + ", downlink: " + fmt.Sprint(me.SessionMBRDL)
	return_string = return_string + ", uplink: " + fmt.Sprint(me.SessionMBRUL)

	return_string = return_string + ")"
	return return_string
}
