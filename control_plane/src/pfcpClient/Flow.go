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

import "fmt"

type Flow struct {
	ID          uint64
	PDR         *PDR
	FAR         *FAR
	QER         *QER
	IsInstalled bool
}

var counter uint64 = 0

func NewFlow(pdr *PDR, far *FAR, qer *QER) *Flow {
	newFlow := Flow{}
	newFlow.ID = counter
	counter = counter + 1
	newFlow.PDR = pdr
	newFlow.FAR = far
	newFlow.QER = qer
	newFlow.IsInstalled = false
	return &newFlow
}

func (me *Flow) isDownstream() bool {
	if me.PDR != nil {
		return me.PDR.isDownstream()
	}
	return false
}

func (me *Flow) isUpstream() bool {
	if me.PDR != nil {
		return me.PDR.isUpstream()
	}
	return false
}

func (me *Flow) IsComplete() bool {
	if me.PDR != nil && me.FAR != nil {
		if me.FAR.IsComplete() == false {
			return false
		}
		if me.PDR.IsComplete() == false {
			return false
		}
		return true
	}
	return false
}

func (me *Flow) needsUpdate() bool {
	if me.PDR != nil {
		if me.PDR.NeedsUpdate {
			return true
		}
	}
	if me.FAR != nil {
		if me.PDR.NeedsUpdate {
			return true
		}
	}
	if me.QER != nil {
		if me.QER.NeedsUpdate {
			return true
		}
	}
	return false
}

func (me *Flow) setUpdated() {
	if me.PDR != nil {
		me.PDR.NeedsUpdate = false
	}
	if me.FAR != nil {
		me.FAR.NeedsUpdate = false
	}
}

func (me *Flow) HasSEID(seid uint64) bool {
	if me.PDR != nil && me.PDR.SEID_ID == seid {
		return true
	}
	return false
}

func (me *Flow) String() string {
	if me.QER != nil {
		return fmt.Sprintf("Flow(PDR: %d, FAR: %d, QER: %d)", me.PDR.PDR_ID, me.FAR.FAR_ID, me.QER.QER_ID)
	} else {
		return fmt.Sprintf("Flow(PDR: %d, FAR: %d)", me.PDR.PDR_ID, me.FAR.FAR_ID)
	}
}
