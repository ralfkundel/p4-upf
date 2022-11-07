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
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"time"

	bfruntime "p4hc-upf/src/dataplane/tofino/protos/bfruntime"
	"p4hc-upf/src/lib"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

type AsicDriver struct {
	isConnected   bool
	conn          *grpc.ClientConn
	client        bfruntime.BfRuntimeClient
	streamChannel bfruntime.BfRuntime_StreamChannelClient
	ctx           context.Context
	cancel        context.CancelFunc
	clientID      uint32

	BfruntimeInfo         string
	NonP4BfruntimeInfo    string
	JsonTablesStruct      []Table     // holds all regular p4 tables in map
	NonP4JsonTablesStruct []PortTable // holds all other tables (hw port config) in map
}

type Port struct {
	P4_port  []byte
	Speed    string
	Fec      string // NONE | FIRECODE | REED_SOLOMON
	An       string // PM_AN_DEFAULT, PM_AN_FORCE_ENABLE, PM_AN_FORCE_DISABLE
	Activate bool
	Upf_mac  []byte
}

func (me *AsicDriver) Close() {
	log.Infoln("CLOSE GrpcWrapper")
	me.Disconnect()
}

func NewAsicDriver() AsicDriver {
	rand.Seed(time.Now().UnixNano())
	asicDriver := AsicDriver{
		isConnected: false,
		clientID:    uint32(rand.Intn(100)),
	}
	return asicDriver
}

func (g *AsicDriver) Connect(host string, port int) {
	if !g.isConnected {
		log.Infof("Connect to Tofino %s:%d", host, port)

		var err error

		maxSizeOpt := grpc.MaxCallRecvMsgSize(16 * 10e6) //increase grpc message size to 16MB
		g.conn, err = grpc.Dial(fmt.Sprintf("%s:%d", host, port), grpc.WithDefaultCallOptions(maxSizeOpt), grpc.WithInsecure(), grpc.WithBlock())

		if err != nil {
			log.Fatalf("Could not connect to Tofino %v", err)
		}

		log.Info("Gen new Client with ID " + strconv.FormatUint(uint64(g.clientID), 10))
		g.client = bfruntime.NewBfRuntimeClient(g.conn)

		// Create context
		g.ctx, g.cancel = context.WithCancel(context.Background())

		// Open StreamChannel
		g.streamChannel, err = g.client.StreamChannel(g.ctx)

		// Initial Step 1 Subscribe message to device 0
		reqSub := bfruntime.StreamMessageRequest_Subscribe{
			Subscribe: &bfruntime.Subscribe{
				IsMaster: true,
				DeviceId: 0,
				Notifications: &bfruntime.Subscribe_Notifications{
					EnablePortStatusChangeNotifications: false,
					EnableIdletimeoutNotifications:      true,
					EnableLearnNotifications:            true,
				},
			},
		}

		err = g.streamChannel.Send(&bfruntime.StreamMessageRequest{ClientId: g.clientID, Update: &reqSub})

		counter := 0
		for err != nil && counter < 3 {
			log.Warningf("Subscribe Failed : %s trying new id %s", err, fmt.Sprint(g.clientID+1))
			counter = counter + 1
			g.clientID = g.clientID + 1
			err = g.streamChannel.Send(&bfruntime.StreamMessageRequest{ClientId: g.clientID, Update: &reqSub})
		}

		// Step 2 Bind client to CFG & p4 program
		reqFPCfg := bfruntime.SetForwardingPipelineConfigRequest{
			ClientId: g.clientID,
			DeviceId: 0,
			Action:   bfruntime.SetForwardingPipelineConfigRequest_BIND,
		}
		reqFPCfg.Config = append(reqFPCfg.Config, &bfruntime.ForwardingPipelineConfig{P4Name: "upf"})

		var setForwardingPipelineConfigResponse *bfruntime.SetForwardingPipelineConfigResponse
		setForwardingPipelineConfigResponse, err = g.client.SetForwardingPipelineConfig(g.ctx, &reqFPCfg)

		if setForwardingPipelineConfigResponse == nil || setForwardingPipelineConfigResponse.GetSetForwardingPipelineConfigResponseType() != bfruntime.SetForwardingPipelineConfigResponseType_WARM_INIT_STARTED {
			log.Fatalf("tofino ASIC driver: Warm Init Failed : %s", err)
		}
		log.Info("tofino ASIC driver: Warm INIT Started")

		// Step 3 Request Runtime GFG
		reqGFPCfg := bfruntime.GetForwardingPipelineConfigRequest{
			ClientId: g.clientID,
			DeviceId: 0,
		}
		var getForwardingPipelineConfigResponse *bfruntime.GetForwardingPipelineConfigResponse
		getForwardingPipelineConfigResponse, err = g.client.GetForwardingPipelineConfig(g.ctx, &reqGFPCfg)

		if getForwardingPipelineConfigResponse == nil {
			log.Fatalf("Could not get ForwardingPipelineConfig : %s", err)
		}

		g.BfruntimeInfo = string(getForwardingPipelineConfigResponse.Config[0].BfruntimeInfo)
		g.NonP4BfruntimeInfo = string(getForwardingPipelineConfigResponse.NonP4Config.BfruntimeInfo)

		// Step 4
		// Parse BfruntimeInfo json into struct

		g.JsonTablesStruct = UnmarshalBfJson(g.BfruntimeInfo) // jsonParser.go

		// Step 5
		// Parse NonP4BfruntimeInfo json into struct
		g.NonP4JsonTablesStruct = UnmarshalPortJson(g.NonP4BfruntimeInfo) // jsonParser.go

		log.Info("Gather ForwardingPipelineConfig Successfully. Connection is Setup and Ready to use !")

		g.isConnected = true
	}
}

func (g *AsicDriver) SetupPort(LinkSpeed string, p4_port uint16, mac string, auto_negotiation string) Port {
	autoneg := "PM_AN_DEFAULT"
	switch auto_negotiation {
	case "default":
		autoneg = "PM_AN_DEFAULT"
	case "on":
		autoneg = "PM_AN_FORCE_ENABLE"
	case "off":
		autoneg = "PM_AN_FORCE_DISABLE"
	}
	p4Port := lib.Uint16ToByte(p4_port)
	mac_byte := lib.MacStringToByte(mac)
	new_port := Port{P4_port: p4Port, Speed: LinkSpeed, Activate: true, Fec: "NONE", An: autoneg, Upf_mac: mac_byte}
	g.SetPortConfig(new_port)
	g.ActivatePort(new_port)
	return new_port
}

func (g *AsicDriver) SetupAccessPort(port Port, GnbMac string, GnbIP net.IP) { //remove NatMac
	p4Port := port.P4_port
	lib.PaddingByteSliceSize(&p4Port, 2)

	//TODO: this would cause an tofino warning when there are multiple gNBs on a single port --> match on port+src-IP
	byte_array := []byte{1}
	keys1 := map[string]interface{}{"ig_intr_md.ingress_port": p4Port}
	datas1 := map[string]interface{}{"usds": byte_array} //upstream
	err1 := g.SetTableEntry("pipe.SwitchIngress.t_usdssp", keys1, "SwitchIngress.a_usds", datas1, "insert")
	if err1 != nil {
		log.Warning("t_usdssp for port", p4Port, "deploy error:", err1)
	}

	var gNodeBIP []byte = GnbIP.To4()
	gNodeBMac := lib.MacStringToByte(GnbMac)
	keys2 := map[string]interface{}{"meta.dst_ip": gNodeBIP}
	datas2 := map[string]interface{}{"dstAddr": gNodeBMac, "egress_port": p4Port}
	err2 := g.SetTableEntry("pipe.SwitchIngress.downstream.t_ds_route_v4", keys2, "SwitchIngress.downstream.a_forward", datas2, "insert")
	if err2 != nil {
		log.Warning("t_ds_route_v4 for port", p4Port, "deploy error:", err2)
	}
}

func (g *AsicDriver) SetupCorePort(port Port, NatMac string) { //remove NatMac
	p4Port := port.P4_port
	lib.PaddingByteSliceSize(&p4Port, 2)

	const_2 := []byte{2}
	keys1 := map[string]interface{}{"ig_intr_md.ingress_port": p4Port}
	datas1 := map[string]interface{}{"usds": const_2} //downstream
	err1 := g.SetTableEntry("pipe.SwitchIngress.t_usdssp", keys1, "SwitchIngress.a_usds", datas1, "insert")
	if err1 != nil {
		log.Warning("t_usdssp for port", p4Port, "deploy error:", err1)
	}

	natMac := lib.MacStringToByte(NatMac)
	const_0 := []byte{0}
	keys2 := map[string]interface{}{"meta.us_load_balance": const_0} //TODO for future use, e.g. NAT load balancing
	datas2 := map[string]interface{}{"dstAddr": natMac, "egress_port": p4Port}
	err2 := g.SetTableEntry("pipe.SwitchIngress.upstream.t_us_route", keys2, "SwitchIngress.upstream.a_forward", datas2, "insert")
	if err2 != nil {
		log.Warning("t_route_v4 for port", p4Port, "deploy error:", err2)
	}

}

func (g *AsicDriver) SetupSlowpath(LinkSpeed string, p4_port uint16, upf_mac string, upf_ip net.IP, auto_negotiation string, sp_ip net.IP, sp_mac string) {
	port := g.SetupPort(LinkSpeed, p4_port, upf_mac, auto_negotiation)
	p4Port := port.P4_port
	lib.PaddingByteSliceSize(&p4Port, 2)

	const_0 := []byte{0}
	var sp_ip_b []byte = sp_ip.To4()
	var upf_ip_b []byte = upf_ip.To4()

	keys1 := map[string]interface{}{"meta.is_processed": const_0}
	datas1 := map[string]interface{}{"dstAddr": lib.MacStringToByte(sp_mac), "srcAddr": lib.MacStringToByte(upf_mac), "sp_ip": sp_ip_b, "upf_ip": upf_ip_b, "egress_port": p4Port}
	err1 := g.SetTableEntry("pipe.SwitchIngress.t_sp_encap", keys1, "SwitchIngress.a_sp_encap", datas1, "insert")
	if err1 != nil {
		log.Warning("t_sp_encap for port", p4Port, "deploy error:", err1)
	}

	const_3 := []byte{3}
	keys2 := map[string]interface{}{"ig_intr_md.ingress_port": p4Port}
	datas2 := map[string]interface{}{"usds": const_3} //downstream
	err2 := g.SetTableEntry("pipe.SwitchIngress.t_usdssp", keys2, "SwitchIngress.a_usds", datas2, "insert")
	if err2 != nil {
		log.Warning("t_usdssp for port", p4Port, "deploy error:", err1)
	}
}

func (g *AsicDriver) ConfigureQosChipPort(p4_port uint16) {
	p4Port := lib.Uint16ToByte(p4_port)
	const_4 := []byte{4}
	keys := map[string]interface{}{"ig_intr_md.ingress_port": p4Port}
	datas := map[string]interface{}{"usds": const_4} //downstream
	err := g.SetTableEntry("pipe.SwitchIngress.t_usdssp", keys, "SwitchIngress.a_usds", datas, "insert")
	if err != nil {
		log.Warning("t_usdssp for port", p4Port, "deploy error:", err)
	}

	keys = map[string]interface{}{"eg_intr_md.egress_port": p4Port}
	datas = map[string]interface{}{} //downstream
	err = g.SetTableEntry("pipe.SwitchEgress.t_ds_qos_egress", keys, "SwitchEgress.a_set_queue_id", datas, "insert")
	if err != nil {
		log.Warning("t_ds_qos_egress for port", p4Port, "deploy error:", err)
	}

	keys = map[string]interface{}{"ingress_port": p4Port}
	datas = map[string]interface{}{} //downstream
	err = g.SetTableEntry("pipe.SwitchIngressParser.fpga_port", keys, "", datas, "insert")
	if err != nil {
		log.Warning("SwitchIngressParser.fpga_port for port", p4Port, "deploy error:", err)
	}

}

// works for Table IDs or Action IDs (because they're unique)
func (g *AsicDriver) GetIDByName(searched_name string) (ret uint32) {
	ret = 0
	for _, tbl_value := range g.JsonTablesStruct {
		if tbl_value.name == searched_name {
			return uint32(tbl_value.id)
		}
		for _, action_value := range tbl_value.actions {
			if action_value.name == searched_name {
				ret = uint32(action_value.id)
			}
		}
	}
	// not found? Look in ports table
	for _, tbl_value := range g.NonP4JsonTablesStruct {
		if tbl_value.name == searched_name {
			return uint32(tbl_value.id)
		}
		// No actions in Port tables
	}

	return ret
}

// returns ID for searched key with given table ID (retrieved with GetIDByName())
func (g *AsicDriver) GetKeyIDByName(searched_name string, tbl_id uint32) (id uint32, matchtype string) {
	id = 0
	matchtype = "Exact"
	for _, tbl_value := range g.JsonTablesStruct {
		if uint32(tbl_value.id) == tbl_id {
			for _, key_value := range tbl_value.keys {
				if key_value.name == searched_name {
					matchtype = key_value.match_type
					id = uint32(key_value.id)
				}
			}
		}
	}
	// not found? Look in ports table
	for _, tbl_value := range g.NonP4JsonTablesStruct {
		if uint32(tbl_value.id) == tbl_id {
			for _, key_value := range tbl_value.keys {
				if key_value.name == searched_name {
					id = uint32(key_value.id)
				}
			}
		}
	}
	return id, matchtype
}

// returns ID for searched Data entry with given action ID (retrieved with GetIDByName())
func (g *AsicDriver) GetDataIDByName(searched_name string, action_id uint32) (ret uint32) {
	ret = 0
	for _, tbl_value := range g.JsonTablesStruct {
		for _, action_value := range tbl_value.actions {
			if uint32(action_value.id) == action_id {
				for _, data_value := range action_value.datas {
					if data_value.name == searched_name {
						return uint32(data_value.id)
					}
				}
			}
		}
	}
	return ret
}

// Port table consists of key[] and data[] and not actions[data[]]
func (g *AsicDriver) GetPortDataIDByName(searched_name string, tbl_id uint32) (ret uint32) {
	ret = 0
	for _, tbl_value := range g.NonP4JsonTablesStruct {
		if uint32(tbl_value.id) == tbl_id {
			for _, data_value := range tbl_value.datas {
				if data_value.name == searched_name {
					ret = uint32(data_value.id)
				}
			}
		}
	}
	return ret
}

func (g *AsicDriver) SetTableEntry(table_name string, keys map[string]interface{}, action_name string, datas map[string]interface{}, update_mode string) error {
	table_id := g.GetIDByName(table_name)
	if table_id == 0 {
		return errors.New("Table ID not found for name " + table_name)
	}
	// ONLY EXACT MATCHING SUPPORTED RIGHT NOW
	var bf_key_fields []*bfruntime.KeyField
	for key_name, key_value := range keys {
		asserted_key_value := key_value.([]byte)
		key_id, key_type := g.GetKeyIDByName(key_name, table_id)
		if key_id == 0 {
			return errors.New("Key ID not found for name " + key_name)
		}
		var bf_key_field *bfruntime.KeyField = nil
		switch key_type {
		case "Exact":
			bf_key_field = &bfruntime.KeyField{
				FieldId: key_id,
				MatchType: &bfruntime.KeyField_Exact_{
					Exact: &bfruntime.KeyField_Exact{
						Value: asserted_key_value,
					},
				},
			}
		case "Ternary":
			tmp := lib.Uint16ToByte(0x1ff) //TODO this is very dirty
			bf_key_field = &bfruntime.KeyField{
				FieldId: key_id,
				MatchType: &bfruntime.KeyField_Ternary_{
					Ternary: &bfruntime.KeyField_Ternary{
						Value: asserted_key_value,
						Mask:  tmp,
					},
				},
			}
		}
		bf_key_fields = append(bf_key_fields, bf_key_field)
	}

	action_id := g.GetIDByName(action_name)
	if action_id == 0 && table_name != "$PORT" && action_name != "" { //TODO
		return errors.New("Action ID not found for name " + action_name)
	}

	// little trick to force same order for $PORT table ...
	var datas_keys []string
	if table_name == "$PORT" {
		datas_keys = []string{"$SPEED", "$AUTO_NEGOTIATION", "$FEC", "$PORT_ENABLE"}
	} else { // doesn't care for other tables
		for data_name, _ := range datas {
			datas_keys = append(datas_keys, data_name)
		}
	}

	var bf_data_fields []*bfruntime.DataField

	// iterate over datas_keys and use as map[key] to force order of unordered map
	for _, data_name := range datas_keys {
		data_value := datas[data_name]
		var data_id uint32
		data_id = g.GetDataIDByName(data_name, action_id)
		if data_id == 0 {
			data_id = g.GetPortDataIDByName(data_name, table_id)
			if data_id == 0 {
				return errors.New("Data ID not found for name " + data_name)
			}
		}

		var bf_data_field *bfruntime.DataField
		if data_name == "$SPEED" || data_name == "$FEC" || data_name == "$AUTO_NEGOTIATION" {
			asserted_data_value := data_value.(string)
			bf_data_field = &bfruntime.DataField{
				FieldId: data_id,
				Value: &bfruntime.DataField_StrVal{
					StrVal: asserted_data_value,
				},
			}
		} else if data_name == "$PORT_ENABLE" {
			asserted_data_value := data_value.(bool)
			bf_data_field = &bfruntime.DataField{
				FieldId: data_id,
				Value: &bfruntime.DataField_BoolVal{
					BoolVal: asserted_data_value,
				},
			}
		} else {
			asserted_data_value := data_value.([]byte)
			bf_data_field = &bfruntime.DataField{
				FieldId: data_id,
				Value: &bfruntime.DataField_Stream{
					Stream: asserted_data_value,
				},
			}
		}

		bf_data_fields = append(bf_data_fields, bf_data_field)
	}

	var myEntry1 bfruntime.TableEntry
	if table_name == "$PORT" {
		myEntry1 = bfruntime.TableEntry{
			TableId: table_id,
			Value: &bfruntime.TableEntry_Key{
				Key: &bfruntime.TableKey{
					Fields: bf_key_fields,
				},
			},
			Data: &bfruntime.TableData{
				//ActionId: action_id,
				Fields: bf_data_fields,
			},
			IsDefaultEntry: false,
		}
	} else {
		if action_id > 0 {
			myEntry1 = bfruntime.TableEntry{
				TableId: table_id,
				Value: &bfruntime.TableEntry_Key{
					Key: &bfruntime.TableKey{
						Fields: bf_key_fields,
					},
				},
				Data: &bfruntime.TableData{
					ActionId: action_id,
					Fields:   bf_data_fields,
				},
				IsDefaultEntry: false,
			}
		} else {
			myEntry1 = bfruntime.TableEntry{
				TableId: table_id,
				Value: &bfruntime.TableEntry_Key{
					Key: &bfruntime.TableKey{
						Fields: bf_key_fields,
					},
				},
			}
		}
	}

	upd_mod := bfruntime.Update_INSERT
	switch update_mode {
	case "insert":
		upd_mod = bfruntime.Update_INSERT
	case "delete":
		upd_mod = bfruntime.Update_DELETE
	case "modify":
		upd_mod = bfruntime.Update_MODIFY
	default:
		log.Warn("tofino grpc: invalid command (insert, delete, modify)")
		return nil
	}

	update := []*bfruntime.Update{
		&bfruntime.Update{
			Type:   upd_mod,
			Entity: &bfruntime.Entity{Entity: &bfruntime.Entity_TableEntry{TableEntry: &myEntry1}},
		},
	}

	writeRequest := bfruntime.WriteRequest{
		ClientId:  g.clientID,
		Atomicity: bfruntime.WriteRequest_CONTINUE_ON_ERROR,
		Target:    &bfruntime.TargetDevice{DeviceId: 0, PipeId: 0xffff, PrsrId: 255, Direction: 255},
		Updates:   update,
	}
	_, err := g.client.Write(g.ctx, &writeRequest)

	if err != nil {
		return err
	} else {
		log.Debug("Populated table " + table_name + " sucessfully")
		return nil
	}
}

// activates a port similar to ucli/pm/port-add but with p4_ports instead of e.g. 1/1
// If breakout cable is used (10G) all 4 ports must be activated
func (g *AsicDriver) ActivatePort(port Port) {
	p4_port := port.P4_port
	lib.PaddingByteSliceSize(&p4_port, 4)
	an := port.An
	keys0 := map[string]interface{}{"$DEV_PORT": p4_port}
	datas0 := map[string]interface{}{"$SPEED": "BF_SPEED_" + port.Speed, "$FEC": "BF_FEC_TYP_" + port.Fec, "$PORT_ENABLE": true, "$AUTO_NEGOTIATION": an}
	err0 := g.SetTableEntry("$PORT", keys0, "", datas0, "insert")
	if err0 != nil {
		log.Warning("$PORT deploy error:", err0)
		log.Warning(port)
	}
}

func (g *AsicDriver) SetPortConfig(port Port) {

	p4_port := port.P4_port
	lib.PaddingByteSliceSize(&p4_port, 2)
	//pipe.SwitchIngress.t_set_upf_cfg
	keys1 := map[string]interface{}{"ig_intr_tm_md.ucast_egress_port": p4_port}
	datas1 := map[string]interface{}{"src_mac": port.Upf_mac}
	err1 := g.SetTableEntry("pipe.SwitchIngress.t_set_src_mac", keys1, "SwitchIngress.set_src_mac", datas1, "insert")
	if err1 != nil {
		log.Warning("t_set_upf_cfg for port", p4_port, "deploy error:", err1)
	}

}

func (g *AsicDriver) InstallDownstreamSubscriber(ue_ip net.IP, teid uint32, upfIP net.IP, gNodeBIP net.IP, update bool) {
	//
	// DOWNSTREAM
	//
	teid_b := lib.Uint32ToByte(teid)
	var gnodeb_ip_b []byte
	gnodeb_ip_b = gNodeBIP.To4()
	var ueIp_v4_b []byte
	ueIp_v4_b = ue_ip.To4()
	var upf_ip_b []byte
	upf_ip_b = upfIP.To4()

	log.Debugf("%s\n%s\n%x\n", ue_ip, gNodeBIP, teid)

	//pipe.SwitchIngress.downstream.t_ds_encap_v4
	keys := map[string]interface{}{"hdr.ipv4.dstAddr": ueIp_v4_b}
	datas := map[string]interface{}{"gnodeb_ip": gnodeb_ip_b, "teid": teid_b, "upf_ip": upf_ip_b}
	err := error(nil)
	if update {
		err = g.SetTableEntry("pipe.SwitchIngress.downstream.t_ds_encap_v4", keys, "SwitchIngress.downstream.update_addresses", datas, "modify")
	} else {
		err = g.SetTableEntry("pipe.SwitchIngress.downstream.t_ds_encap_v4", keys, "SwitchIngress.downstream.update_addresses", datas, "insert")
	}
	if err != nil {
		log.Warning("AddDownStreamSubscriber deploy error:", err)
		log.Warnf("%s\n%s\n%x\n", ue_ip, gNodeBIP, teid)
	}

}

func (g *AsicDriver) InstallUpstreamSubscriber(gNodeBPort uint16, ue_ip net.IP, teid uint32, update bool) {
	//
	// UPSTREAM
	//
	teid_b := lib.Uint32ToByte(teid)
	gNodeBPort_b := lib.Uint16ToByte(gNodeBPort)
	var ueIp_v4_b []byte
	ueIp_v4_b = ue_ip.To4()

	table_name := "pipe.SwitchIngress.upstream.t_us_decap_antispoof_v4"

	//pipe.SwitchIngress.upstream.t_us_decap_antispoof_v4
	keys := map[string]interface{}{"ig_intr_md.ingress_port": gNodeBPort_b, "hdr.gtp_v1.teid": teid_b, "hdr.ipv4_inner.srcAddr": ueIp_v4_b}
	action := "SwitchIngress.upstream.terminate"
	datas := map[string]interface{}{}

	if len(ueIp_v4_b) == 0 {
		table_name = "pipe.SwitchIngress.upstream.t_us_decap_v4"
		keys = map[string]interface{}{"ig_intr_md.ingress_port": gNodeBPort_b, "hdr.gtp_v1.teid": teid_b}
		action = "SwitchIngress.upstream.terminate_no_antispoof"
	}

	err := error(nil)
	if update {
		err = g.SetTableEntry(table_name, keys, action, datas, "modify")
	} else {
		err = g.SetTableEntry(table_name, keys, action, datas, "insert")
	}
	if err != nil {
		log.Warning("AddUpStreamSubscriber deploy error:", err)
		log.Warnf("gNodeBPort: %x, teid: %x, ue_ip: %s\n", gNodeBPort, teid, ue_ip)
		log.Warnln(table_name)
		log.Warnln(keys)
		log.Warnln(action)

	}
}

func (g *AsicDriver) InstallFpgaQoSRule(teid uint32, port uint16, qid uint32) {
	teid_b := lib.Uint32ToByte(teid)
	qid_b := lib.Uint32ToByte(qid)
	port_b := lib.Uint16ToByte(port)
	keys := map[string]interface{}{"hdr.gtp_v1.teid": teid_b}
	datas := map[string]interface{}{"queue_id": qid_b, "egress_port": port_b}
	err := g.SetTableEntry("pipe.SwitchIngress.downstream.t_ds_qos", keys, "SwitchIngress.downstream.a_send_to_qos_chip", datas, "insert")

	if err != nil {
		log.Warning("InstallFpgaQoSRule deploy error:", err)
	}
}

func (g *AsicDriver) DeleteDownstreamSubscriber(ue_ip net.IP) {
	//
	// DOWNSTREAM
	//
	var ueIp_v4_b []byte
	ueIp_v4_b = ue_ip.To4()

	//pipe.SwitchIngress.downstream.t_ds_encap_v4
	keys := map[string]interface{}{"hdr.ipv4.dstAddr": ueIp_v4_b}
	datas := map[string]interface{}{}
	err := g.SetTableEntry("pipe.SwitchIngress.downstream.t_ds_encap_v4", keys, "SwitchIngress.downstream.update_addresses", datas, "delete")
	if err != nil {
		log.Warning("DeleteDownstreamSubscriber deploy error:", err)
	}
}
func (g *AsicDriver) DeleteUpstreamSubscriber(gnodeb_port uint16, ue_ip net.IP, teid uint32) {
	//
	// UPSTREAM
	//

	teid_b := lib.Uint32ToByte(teid)
	gNodeBPort_b := lib.Uint16ToByte(gnodeb_port)
	var ueIp_v4_b []byte
	ueIp_v4_b = ue_ip.To4()

	table_name := "pipe.SwitchIngress.upstream.t_us_decap_antispoof_v4"

	//pipe.SwitchIngress.upstream.t_us_decap_antispoof_v4
	keys := map[string]interface{}{"ig_intr_md.ingress_port": gNodeBPort_b, "hdr.gtp_v1.teid": teid_b, "hdr.ipv4_inner.srcAddr": ueIp_v4_b}
	action := "SwitchIngress.upstream.terminate"
	datas := map[string]interface{}{}

	if len(ueIp_v4_b) == 0 {
		table_name = "pipe.SwitchIngress.upstream.t_us_decap_v4"
		keys = map[string]interface{}{"ig_intr_md.ingress_port": gNodeBPort_b, "hdr.gtp_v1.teid": teid_b}
		action = "SwitchIngress.upstream.terminate_no_antispoof"
	}

	err := g.SetTableEntry(table_name, keys, action, datas, "delete")
	if err != nil {
		log.Warning("RemoveUpStreamSubscriber deploy error:", err)
	}
}

func (g *AsicDriver) Disconnect() {
	if g.isConnected {
		g.client = nil
		g.conn.Close()
		g.cancel()
		g.ctx.Done()
		g.isConnected = false
	}
}
