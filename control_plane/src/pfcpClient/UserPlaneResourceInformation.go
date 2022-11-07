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

type UserPlaneResourceInformation struct {
	gtpEndpointIp   string
	teid_range      uint8
	dnn_name        string
	dnn_cidr_ip     string
	dnn_cidr_prefix uint8
	SwitchPort      uint16
}

func (me *UserPlaneResourceInformation) String() string {
	return fmt.Sprintf("UserPlaneResourceInformation (dnn-name: %s, gtpEndpointIp: %s, teid_range: %s, dnn_cidr_ip: %s, dnn_cidr_prefix: %s)", me.dnn_name, me.gtpEndpointIp, fmt.Sprint(me.teid_range), me.dnn_cidr_ip, fmt.Sprint(me.dnn_cidr_prefix))
}
