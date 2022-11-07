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
	"strconv"
	"strings"
)

type RIB struct {
	unassigned_PDRs map[PDR_HASH_ID]*PDR
	PDRs            map[PDR_HASH_ID]*PDR
	FARs            map[FAR_HASH_ID]*FAR
	QERs            map[QER_HASH_ID]*QER
	Sessions        map[uint64]*SESSION
	FlowRules       map[uint64]*Flow

	ResourceInformation []*UserPlaneResourceInformation
}

func NewRIB() *RIB {
	rib := RIB{}
	rib.unassigned_PDRs = make(map[PDR_HASH_ID]*PDR)
	rib.PDRs = make(map[PDR_HASH_ID]*PDR)
	rib.FARs = make(map[FAR_HASH_ID]*FAR)
	rib.QERs = make(map[QER_HASH_ID]*QER)
	rib.Sessions = make(map[uint64]*SESSION)
	rib.FlowRules = make(map[uint64]*Flow)
	return &rib
}

func (me *RIB) addResourceInformation(gtp_ip string, teid_range uint8, dnn_name string, dnn_cidr string, SwitchPort uint16) {
	foo := strings.Split(dnn_cidr, "/")
	ip := foo[0]
	pre, _ := strconv.Atoi(foo[1])
	toadd := UserPlaneResourceInformation{gtp_ip, teid_range, dnn_name, ip, uint8(pre), SwitchPort}
	me.ResourceInformation = append(me.ResourceInformation, &toadd)
}

func (me *RIB) cleanResourceInformation() {
	me.ResourceInformation = []*UserPlaneResourceInformation{}
}

func (me *RIB) getResourceInformation(name string) *UserPlaneResourceInformation {
	for _, inf := range me.ResourceInformation {
		if string(rune(3))+inf.dnn_name == name || string(rune(8))+inf.dnn_name == name { //This is strange why is there a 0x08 or 0x03 in the beginning???
			return inf
		}
	}
	return nil
}

func (me *RIB) getSession(seid uint64) *SESSION {
	return me.Sessions[seid]
}

func (me *RIB) getOrCreateSession(seid uint64) *SESSION {
	ret := me.Sessions[seid]
	if ret == nil {
		ret = &SESSION{SEID_ID: seid}
		me.Sessions[seid] = ret
	}
	return ret
}

func (me *RIB) AddPDR(tobeadded *PDR) {
	me.unassigned_PDRs[tobeadded.getPdrId()] = tobeadded
	me.PDRs[tobeadded.getPdrId()] = tobeadded
	me.getOrCreateSession(tobeadded.SEID_ID).PDRs = append(me.getOrCreateSession(tobeadded.SEID_ID).PDRs, tobeadded)
}

func (me *RIB) GetPDR(SEID_ID uint64, PDR_ID uint16) *PDR {
	pdr_hash_id := PDR_HASH_ID{SEID_ID: SEID_ID, PDR_ID: PDR_ID}
	return me.PDRs[pdr_hash_id]
}

func (me *RIB) AddFAR(tobeadded *FAR) {
	far_id := tobeadded.getFarId()
	me.FARs[far_id] = tobeadded
	me.getOrCreateSession(tobeadded.SEID_ID).FARs = append(me.getOrCreateSession(tobeadded.SEID_ID).FARs, tobeadded)
}

func (me *RIB) GetFAR(SEID_ID uint64, far_id uint32) *FAR {
	far_hash_id := FAR_HASH_ID{SEID_ID: SEID_ID, FAR_ID: far_id}
	res := me.FARs[far_hash_id]
	return res
}

func (me *RIB) AddQER(tobeadded *QER) {
	qer_id := tobeadded.getQerId()
	me.QERs[qer_id] = tobeadded
	me.getOrCreateSession(tobeadded.SEID_ID).QERs = append(me.getOrCreateSession(tobeadded.SEID_ID).QERs, tobeadded)
}

func (me *RIB) GetQER(SEID_ID uint64, QER_ID uint32) *QER {
	qer_hash_id := QER_HASH_ID{SEID_ID: SEID_ID, QER_ID: QER_ID}
	res := me.QERs[qer_hash_id]
	return res
}

func (me *RIB) DeleteSession(SEID uint64) (bool, []*Flow) {
	var toBeDeletedFlows []*Flow
	var success bool = false
	session := me.getSession(SEID)

	if session != nil {
		toBeDeletedFlows = session.Flows

		for _, flow := range session.Flows {
			delete(me.FlowRules, flow.ID)
		}

		for _, element := range session.PDRs {
			delete(me.PDRs, element.getPdrId())
			success = true
		}

		for _, element := range session.FARs {
			delete(me.FARs, element.getFarId())
			success = true
		}

		for _, element := range session.QERs {
			delete(me.QERs, element.getQerId())
		}
		success = true
		delete(me.Sessions, SEID)
	}

	if success {
		return true, toBeDeletedFlows
	}
	return false, nil

}

func (me *RIB) MapPdrFar() {
	for _, element := range me.unassigned_PDRs {
		matchedFar := me.GetFAR(element.SEID_ID, element.FAR_ID)
		matchedQer := me.GetQER(element.SEID_ID, element.QER_ID)
		if matchedFar != nil && matchedFar.IsComplete() && element.IsComplete() {
			newFlow := NewFlow(element, matchedFar, matchedQer)
			me.getSession(matchedFar.SEID_ID).Flows = append(me.getSession(matchedFar.SEID_ID).Flows, newFlow)
			me.FlowRules[newFlow.ID] = newFlow

			//remove PDR from list
			delete(me.unassigned_PDRs, element.getPdrId())
		}
	}
}

func (me *RIB) String() string {
	return fmt.Sprintf("RIB \nresource information:\n%s\nunasignedPDRs: \n%s \nPDRs: \n%s \nFARs \n%s\n QERs\n %s \nFlow Rules:\n%s", me.ResourceInformation, me.unassigned_PDRs, me.PDRs, me.FARs, me.QERs, me.FlowRules)
}
