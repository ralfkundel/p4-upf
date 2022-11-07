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

package fpga

//inspired by: https://github.com/grpc/grpc-go/blob/82d8af8bf09fb889fbe8d5cf8101916e09c5ef74/examples/route_guide/client/client.go
import (
	"context"
	log "github.com/sirupsen/logrus"
	fpga_iface "p4hc-upf/src/dataplane/fpga/protobuf"
	//"time"

	"google.golang.org/grpc"
)

type FpgaDriver struct {
	conn        *grpc.ClientConn
	client      fpga_iface.GenericPciApiClient
	cancel_func context.CancelFunc
	ctx         context.Context
}

func NewFpgaDriver() *FpgaDriver {
	fpgaDriver := FpgaDriver{}
	return &fpgaDriver
}

func (me *FpgaDriver) StartFpgaDriver(fpga_address string) {
	//"172.16.3.12:10000"
	var err error
	log.Infoln("StartFpgaDriver")
	me.conn, err = grpc.Dial(fpga_address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("fail to dial: %v", err)
	}
	me.client = fpga_iface.NewGenericPciApiClient(me.conn)
	me.ctx, me.cancel_func = context.WithCancel(context.Background())

}

func (me *FpgaDriver) Terminate() {
	log.Infoln("Terminate FpgaDriver")
	if me.conn != nil {
		me.conn.Close()
	}
	if me.cancel_func != nil {
		me.cancel_func()
	}
}

func (me *FpgaDriver) SetRateLimit(rate uint64, qid uint32) (resp *fpga_iface.Response, err error) { //rate in kbit/s
	resp, err = me.client.Write32(me.ctx, &fpga_iface.AddressValue32{Address: 0, Value: 250000}) //qos class 0
	var CLOCK_DIVIDER uint64 = 1024
	var CLOCK_FREQUENZY uint64 = 220000000
	rate = rate * 1000
	value := (rate / 8) * CLOCK_DIVIDER / CLOCK_FREQUENZY
	log.Infof("Set rate of queue %d to %d bit/s (which is a t-bucket value of: %d)\n", qid, rate, value)
	resp, err = me.client.Write32(me.ctx, &fpga_iface.AddressValue32{Address: 16777216 + 4*qid, Value: uint32(value)})
	if err != nil {
		log.Warnf("error in SetRateLimit: %s", err)
	}
	return resp, err

}
