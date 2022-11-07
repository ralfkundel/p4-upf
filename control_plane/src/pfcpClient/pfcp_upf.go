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
	"flag"
	"fmt"
	"net"
	"p4hc-upf/src/dataplane"
	"p4hc-upf/src/lib"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

type PfcpAgent struct {
	conn          *net.UDPConn
	addr          net.Addr
	cfg           *lib.Config
	rib           *RIB
	dpi           dataplane.DataPlaneInterface
	pfcp_attached bool
	pfcp_seq      uint32
}

func (me *PfcpAgent) Close() {
	fmt.Println("CLOSE PfcpAgent")

	if me.conn != nil {

		if me.pfcp_attached == true {
			//send release message
			me.initAssociationRelease()
			time.Sleep(200 * time.Millisecond)
		}
		if me.conn != nil {
			me.conn.Close()
		}
	}
}

func NewPfcpAgent(cfg *lib.Config, rib *RIB, dpi dataplane.DataPlaneInterface) *PfcpAgent {
	agent := &PfcpAgent{}
	agent.SetCfg(cfg)
	agent.rib = rib
	agent.dpi = dpi
	agent.pfcp_attached = false
	agent.pfcp_seq = 0
	return agent
}

func (me *PfcpAgent) SetCfg(conf *lib.Config) {
	me.cfg = conf
}

func (me *PfcpAgent) initAssociationRelease() {
	release_msg := message.NewAssociationReleaseRequest(me.pfcp_seq, ie.NewNodeID(me.cfg.UpfConfiguration.N4Interface.Ipv4addr, "", ""))
	me.pfcp_seq = me.pfcp_seq + 1
	log.Infoln("Sent Association Release message to SMF")
	me.sendMsg(release_msg)
}

func (me *PfcpAgent) Receive() {
	n4_ip := me.cfg.UpfConfiguration.N4Interface.Ipv4addr
	n4_port := me.cfg.UpfConfiguration.N4Interface.Port

	var listen = flag.String("s", ("" + n4_ip + ":" + n4_port), "addr/port to listen on")
	flag.Parse()

	laddr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	me.conn, err = net.ListenUDP("udp", laddr)
	if err != nil {
		log.Fatal(err)
	}

	buf := make([]byte, 1500)
	for {
		log.Debugf("waiting for messages to come on: %s \n", laddr)

		var n int
		n, me.addr, err = me.conn.ReadFrom(buf)
		if err != nil {
			if me.pfcp_attached == false {
				log.Infoln("Terminate receive thread as pfcp attachment \n")
				return
			} else {
				log.Fatal(err)
			}
		}

		//convert message to pfcp message
		msg, err := message.Parse(buf[:n])
		if err != nil {
			log.Debugf("ignored undecodable message: %x, error: %s", buf[:n], err)
			continue
		}

		switch msg.(type) {
		default:
			log.Infof("Unexpected PFCP message: %s", msg)
		case *message.HeartbeatRequest:
			hb_msg := msg.(*message.HeartbeatRequest)
			me.handleHeartbeatRequest(hb_msg)
		case *message.AssociationSetupRequest:
			log.Infof("received AssociationSetupRequest")
			asr_msg := msg.(*message.AssociationSetupRequest)
			me.handleAssociationSetupRequest(asr_msg)
		case *message.SessionEstablishmentRequest:
			log.Debugf("received SessionEstablishmentRequest")
			asr_msg := msg.(*message.SessionEstablishmentRequest)
			me.handleSessionEstablishmentRequest(asr_msg)
		case *message.SessionModificationRequest:
			log.Debugf("received SessionModificationRequest")
			asmr_msg := msg.(*message.SessionModificationRequest)
			me.handleSessionModificationRequest(asmr_msg)
		case *message.SessionDeletionRequest:
			log.Debugf("received SessionDeletionRequest")
			asdr_msg := msg.(*message.SessionDeletionRequest)
			me.handleSessionDeletionRequest(asdr_msg)
		case *message.AssociationReleaseRequest:
			log.Infof("received AssociationReleaseRequest")
			arr_msg := msg.(*message.AssociationReleaseRequest)
			me.handleAssociationReleaseRequest(arr_msg)
		case *message.AssociationReleaseResponse:
			log.Infof("received AssociationReleaseResponse")
			arresp_msg := msg.(*message.AssociationReleaseResponse)
			me.handleAssociationReleaseResponse(arresp_msg)

		}

		me.rib.MapPdrFar()
		me.updateFlowRules()

		log.Debugln(me.rib)

	}

}

func (me *PfcpAgent) updateFlowRules() {
	for _, flow := range me.rib.FlowRules {
		if !flow.IsInstalled || flow.needsUpdate() {
			if !flow.IsComplete() { //this is redundant to the check in RIB.go
				continue
			}
			if flow.isDownstream() {
				upf_ip := net.ParseIP(me.cfg.UpfConfiguration.GTPu.SwitchPort.Ipv4addr)
				me.dpi.InstallDownstreamSubscriber(flow.PDR.UeIpAddress_v4, flow.FAR.OuterHeaderTEID, upf_ip, flow.FAR.OuterHeaderIPv4, flow.IsInstalled)
				if me.cfg.UpfConfiguration.QosChip.EnableQoS && flow.QER != nil {
					// process QER here iff present
					me.dpi.InstallDownstreamQoS(flow.FAR.OuterHeaderTEID, flow.QER.SessionMBRDL)
				}
			} else if flow.isUpstream() {
				me.dpi.InstallUpstreamSubscriber(me.cfg.UpfConfiguration.GTPu.SwitchPort.PipelinePort, flow.PDR.UeIpAddress_v4, flow.PDR.PdiTEID, flow.IsInstalled)
			}
			flow.IsInstalled = true
			flow.setUpdated()
		}
	}
}

func (me *PfcpAgent) deleteFlowRuleFromUserPlane(flows []*Flow) bool {
	for _, flow := range flows {
		log.Debugln("deleteFlowRuleFromUserPlane: " + fmt.Sprint(flow))
		if flow.isDownstream() {
			me.dpi.DeleteDownstreamSubscriber(flow.PDR.UeIpAddress_v4)
		} else if flow.isUpstream() {
			me.dpi.DeleteUpstreamSubscriber(me.cfg.UpfConfiguration.GTPu.SwitchPort.PipelinePort, flow.PDR.UeIpAddress_v4, flow.PDR.PdiTEID)
		}
	}
	return true
}

func (me *PfcpAgent) sendMsg(msg message.Message) {
	bytearray := make([]byte, msg.MarshalLen())
	msg.MarshalTo(bytearray)
	me.conn.WriteTo(bytearray, me.addr)

}

func (me *PfcpAgent) handleHeartbeatRequest(msg *message.HeartbeatRequest) {
	//see: https://github.com/wmnsk/go-pfcp/blob/master/examples/heartbeat/hb-server/main.go
	ts, err := msg.RecoveryTimeStamp.RecoveryTimeStamp()
	if err != nil {
		log.Warnf("got Heartbeat Request with invalid timestamp: %s", err)
		return
	} else {
		log.Infof("got Heartbeat Request with timestamp: %s", ts)
	}

	if !me.pfcp_attached {
		log.Warnf("Received Heartbeat Request but no pfcp session is established")
		return
	}

	response := message.NewHeartbeatResponse(msg.SequenceNumber, ie.NewRecoveryTimeStamp(time.Now()))
	me.sendMsg(response)
}

func (me *PfcpAgent) handleAssociationSetupRequest(msg *message.AssociationSetupRequest) {
	if msg.CPFunctionFeatures == nil {
		log.Warnln(lib.WarningColor, "Received PFCP Association Request which is not of type CPFunctionFeatures")
	}
	//TEID: Tunnel Endpoint Identifier - A 32-bit(4-octet) field used to multiplex different connections in the same GTP tunnel.
	response := message.NewAssociationSetupResponse(
		msg.SequenceNumber,
		ie.NewNodeID(me.cfg.UpfConfiguration.N4Interface.Ipv4addr, "", ""),
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewRecoveryTimeStamp(time.Now()))

	var teid_range uint8
	teid_range = 0
	for i, resInf := range me.cfg.UpfConfiguration.DnnList {
		_ = i
		//dnn = data network name
		//p159: https://www.etsi.org/deliver/etsi_ts/129200_129299/129244/15.02.00_60/ts_129244v150200p.pdf
		//flags: Bit 3-5 – TEID Range Indication (TEIDRI): the value of this field indicates the number of bits in the most
		//significant octet of a TEID that are used to partition the TEID range, e.g. if this field is set to "4", then the first 4
		//bits in the TEID are used to partition the TEID range
		//flags==0x25 -->TEID range indication == 1
		response.IEs = append(response.IEs, ie.NewUserPlaneIPResourceInformation(0x25, teid_range, me.cfg.UpfConfiguration.GTPu.SwitchPort.Ipv4addr, "", "\b"+resInf.DnnName, 0))
		me.rib.addResourceInformation(me.cfg.UpfConfiguration.GTPu.SwitchPort.Ipv4addr, teid_range, resInf.DnnName, resInf.Cidr, resInf.SwitchPort.PipelinePort)
		//teid_range++
		//Octet 6 (TEID Range) shall be present if the TEID Range Indication is not set to zero and shall contain a value of the bits which are
		// used to partition the TEID range. E.g. if the TEID Range Indication is set to "4", then Octet 6 shall be one of values between 0 and 15.
		// When TEID Range Indication is set to zero, the Octet 6 shall not be present, the TEID is not partitioned, i.e. all TEID values are available for use by the CP function.
	}
	log.Debugf("\nAssociationSetupRequestResponse: %s\n\n\n", response)

	me.sendMsg(response)
	me.pfcp_attached = true
	me.pfcp_seq = 0
}

func (me *PfcpAgent) handleAssociationReleaseRequest(msg *message.AssociationReleaseRequest) {
	//TODO not yet tested

	me.pfcp_attached = false
	me.rib.cleanResourceInformation()

	response := message.NewAssociationReleaseResponse(
		msg.SequenceNumber,
		ie.NewNodeID(me.cfg.UpfConfiguration.N4Interface.Ipv4addr, "", ""),
		ie.NewCause(ie.CauseRequestAccepted))

	log.Infof("\nAssociationReleaseResponse: %s\n\n\n", response)

	me.sendMsg(response)
}

func (me *PfcpAgent) handleAssociationReleaseResponse(msg *message.AssociationReleaseResponse) {
	me.pfcp_attached = false
	if me.conn != nil {
		me.conn.Close()
	}
}

func (me *PfcpAgent) updatePDRpdi(pdis []*ie.IE, pdr *PDR) {
	pdr.NeedsUpdate = true
	for _, pdi := range pdis {

		switch pdi.Type {
		default:
			log.Debugf(lib.WarningColor, "unknown pdi type")
		case ie.SourceInterface:
			//source interface: CORE(1) or ACCESS (0) or CP-Plane (3)
			pdr.SourceType, _ = pdi.SourceInterface()
		case ie.FTEID:
			//F-TEID: TEID + IP(UPF-UP)
			pdi_fteid, _ := pdi.FTEID()
			//TODO: what if there is no IPv4 address?
			//see: https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=3111
			//section 8.2.3
			pdr.SetFTEID(pdi_fteid.IPv4Address, pdi_fteid.TEID)
		case ie.NetworkInstance:
			//network instance: e.g., internet or EMPTY(8bit 0)
			networkInstance, _ := pdi.NetworkInstance()
			pdr.Source_Network_Instance = me.rib.getResourceInformation(networkInstance)

		//UE IP address
		case ie.UEIPAddress:
			ueIP, _ := pdi.UEIPAddress()
			pdr.SetUeIP(ueIP.IPv4Address)
		}
	}
}

func (me *PfcpAgent) updateFARflags(orig_far *ie.IE, far *FAR) {
	notifyCP := orig_far.HasNOCP()
	drop := orig_far.HasDROP()
	forward := orig_far.HasFORW()
	buff := orig_far.HasBUFF()
	log.Tracef("updateFARflags: notifyCP: %t\n", notifyCP)
	log.Tracef("updateFARflags: drop: %t\n", drop)
	log.Tracef("updateFARflags: forward: %t\n", forward)
	log.Tracef("updateFARflags: buff: %t\n", buff)
	//TODO: currently ignored
}

func (me *PfcpAgent) updateFARparams(fwd_params []*ie.IE, far *FAR) {
	far.NeedsUpdate = true
	for _, fwd_param := range fwd_params {
		//Forwarding Parameters: Destination Interface (e.g. N6-Lan - wohl nur den type) & Network Instance: (e.g. internet)   //optional
		switch fwd_param.Type {
		default:
			log.Debugf("Unknown fwd param type")
		case ie.DestinationInterface:
			dst_int, _ := fwd_param.DestinationInterface()
			far.Destination_Interface_Type = dst_int
		case ie.NetworkInstance:
			network_instance, _ := fwd_param.NetworkInstance()
			res_inf := me.rib.getResourceInformation(network_instance) //network_instance
			if res_inf == nil && len(network_instance) > 0 {
				log.Warnf(lib.WarningColor, res_inf)
				log.Fatalf(lib.ErrorColor, "unknown resource information in SessionEstablishmentRequest")
			}
			far.Destination_Network_Instance = res_inf
		case ie.OuterHeaderCreation:
			outerHeaderCreationFields, _ := fwd_param.OuterHeaderCreation()
			if outerHeaderCreationFields.OuterHeaderCreationDescription != 256 {
				log.Fatalf(lib.ErrorColor, "Outer Header Creation Field Description is not 256")
			}
			far.SetOuterHeaderCreation(outerHeaderCreationFields.IPv4Address, outerHeaderCreationFields.TEID)
		}
	}
}

func (me *PfcpAgent) handleSessionEstablishmentRequest(msg *message.SessionEstablishmentRequest) {
	// sehr gute doku: eventhelix.com/5G/standalone-access-registration/SMF.pdf

	//1 Understand the request
	SequenceNumber := msg.SequenceNumber
	//the SEID is null in the request but available, the actual SEID is in the F-SEID IE. according ETSI TS 129 244

	//1.1 PDN-Type: e.g. IPv4
	if msg.PDNType != nil && msg.PDNType.Type == ie.PDNType { //TODO: should be present if upstream or downstream. only not existing iff from CP
		pdnTypeFlags := msg.PDNType.Payload[0]
		if pdnTypeFlags != 0x01 {
			log.Fatalf(lib.WarningColor, "INVALID PDNType in SessionEstablishmentRequest")
			return
		}
	}

	//1.2 nodeID: SMF Endpoint - immer auf port 8805, wird nicht mitgeschickt
	if msg.NodeID.Type == ie.NodeID {
		nodeId, _ := msg.NodeID.NodeID()
		_ = nodeId
	}

	//1.3 F-SEID: neue SEID
	var fseid_seid uint64
	var fseid_ipv4 net.IP
	if msg.CPFSEID.Type == ie.FSEID {
		fseidFields, _ := msg.CPFSEID.FSEID()
		if fseidFields.Flags != 0x2 {
			log.Warnf(lib.ErrorColor, "strange PFCP Session Establishment Request F-SEID flags")
			return
		}
		fseid_seid = fseidFields.SEID
		fseid_ipv4 = fseidFields.IPv4Address //ip of SMF which is connecting
		log.Debugf("fseid_ipv4: %s", fseid_ipv4)
		log.Debugf("fseid: %s", fseid_seid)
	}

	//TODO: handle here retransmits
	session := me.rib.getSession(fseid_seid)

	if session == nil { //dangerous pfcp retransmission detection --> what iff second session establishment message has different content? i.e. retransmit with changed state?
		//PDR = packet detection rule
		//FAR = Forwarding Action Rule
		//1.4 createPDR (Typ == 1)
		for _, pdr := range msg.CreatePDR {

			pdr_id, _ := pdr.PDRID()
			precedence, _ := pdr.Precedence()
			//maps to FAR-IDtoBeDeletedFlows
			far_id, _ := pdr.FARID()
			qer_id, err := pdr.QERID()
			if err != nil {
				log.Debugln("handleSessionEstablishmentRequest(): no QER found")
				qer_id = 0
			}

			//Outer Header Removal: 0=IPv4, 1=IPv6 - This IE shall be present if the UP function is required to remove one or more outer header(s) from the packets matching this PDR.
			var outerHeaderRemoval bool = false
			tmp, _ := pdr.OuterHeaderRemoval()
			if len(tmp) > 0 && tmp[0] == 0 {
				outerHeaderRemoval = true
			}
			new_pdr := NewPDR(fseid_ipv4, fseid_seid, pdr_id, far_id, qer_id, precedence, outerHeaderRemoval)

			//PDI (packet detection information)
			pdis, _ := pdr.PDI()
			me.updatePDRpdi(pdis, new_pdr)

			me.rib.AddPDR(new_pdr)
		}

		//1.5 createFAR (Typ == 3)
		for _, far := range msg.CreateFAR {
			farid, _ := far.FARID()
			//Apply Action: e.g.: FORWARD(2), Drop(0), Buffer(4), NotifyCP(8), Duplicate(16)  //pfcp for golang has only uint8 type --> 16 is impossible ...
			apply_action, _ := far.ApplyAction()
			fwd_params, _ := far.ForwardingParameters()

			new_far := NewFAR(fseid_ipv4, fseid_seid, farid, apply_action)
			me.updateFARflags(far, new_far)
			me.updateFARparams(fwd_params, new_far)

			me.rib.AddFAR(new_far)
		}

		//1.6 create QER (Type 7)
		for _, qer := range msg.CreateQER {

			qerid, _ := qer.QERID()
			gate_dl, _ := qer.GateStatusDL() //0 = open
			gate_ul, _ := qer.GateStatusUL()
			mbr_dl, _ := qer.MBRDL()
			mbr_ul, _ := qer.MBRUL()
			qfi, _ := qer.QFI()

			new_qer := NewQER(fseid_ipv4, fseid_seid, qerid, gate_dl, gate_ul, mbr_dl, mbr_ul, qfi)
			me.rib.AddQER(new_qer)
		}
	} else {
		log.Debugf("\nSkip Handling Session Establishment Request as session already exists: \n")
	}

	//2. Create an response
	var mp uint8 = 0  //message priority 0 or 1
	var pri uint8 = 4 // this value is only used iff mp==1 - unused
	var fo uint8 = 0  // three "spare bits"
	//pfcp header code: Flags = ((ver & 0x7) << 5) | (fo << 2) | (mp << 1) | s,
	//F-SEID: Fully Qualified SEID
	//SEID: Session Endpoint Identifier
	var seq uint32 = SequenceNumber //sequence number
	response := message.NewSessionEstablishmentResponse(mp, fo, fseid_seid, seq, pri)
	response.IEs = append(response.IEs, ie.NewNodeID(me.cfg.UpfConfiguration.N4Interface.Ipv4addr, "", ""))
	response.IEs = append(response.IEs, ie.NewCause(ie.CauseRequestAccepted))
	var ipv4 net.IP = net.ParseIP(me.cfg.UpfConfiguration.N4Interface.Ipv4addr) //is the Session between SMF and UPF???
	//var ipv6 net.IP = net.IPv6zero
	response.IEs = append(response.IEs, ie.NewFSEID(fseid_seid, ipv4, nil))

	log.Debugf("\nSessionEstablishmentRequestResponse: %s\n\n\n", response)
	me.sendMsg(response)
}

func (me *PfcpAgent) handleSessionModificationRequest(msg *message.SessionModificationRequest) {
	log.Debugf("handleSessionModificationRequest")
	SequenceNumber := msg.SequenceNumber
	SEID := msg.SEID()
	var F_SEID_ip *net.IP
	F_SEID_ip = nil
	if msg.CPFSEID != nil { //F-SEID in session modification is optional, only normal SEID in pfcp must be present
		F_SEID, _ := msg.CPFSEID.FSEID()
		F_SEID_ip = &F_SEID.IPv4Address
		SEID = F_SEID.SEID
	}
	_ = F_SEID_ip

	//----------------------------------------------------
	// parse Update PDR
	//----------------------------------------------------
	for _, pdr := range msg.UpdatePDR {
		pdr_id, _ := pdr.PDRID()
		pdr_entry := me.rib.GetPDR(SEID, pdr_id)
		pdis, _ := pdr.PDI()
		me.updatePDRpdi(pdis, pdr_entry)
	}

	//----------------------------------------------------
	// parse Update FAR
	//----------------------------------------------------
	for _, far := range msg.UpdateFAR {
		far_id, _ := far.FARID()
		far_entry := me.rib.GetFAR(SEID, far_id)
		fwd_params, _ := far.UpdateForwardingParameters()
		me.updateFARflags(far, far_entry)
		me.updateFARparams(fwd_params, far_entry)
	}

	//----------------------------------------------------
	// parse Update QER
	//----------------------------------------------------
	for _, qer := range msg.UpdateQER {
		qer_id, _ := qer.QERID()
		me.updateQer(SEID, qer_id, qer)
		log.Debugf("update QER ID: %d\n", qer_id)
	}

	// ---------------------------------------------------
	//create an response
	// ---------------------------------------------------
	var mp uint8 = 0 //message priority 0 or 1
	//if msg.HasMP() {
	//	mp = 1
	//}
	var pri uint8 = 0
	//var pri uint8 = msg.MP() // this value is only used iff mp==1 - bug in libray --> 0
	var fo uint8 = 0                // three "spare bits"
	var seq uint32 = SequenceNumber //sequence number
	response := message.NewSessionModificationResponse(mp, fo, SEID, seq, pri)
	response.IEs = append(response.IEs, ie.NewCause(ie.CauseRequestAccepted))

	log.Debugf("\nSessionModificationResponse: %s\n\n\n", response)
	me.sendMsg(response)
}

func (me *PfcpAgent) updateQer(seid uint64, qerid uint32, pfcp_qer *ie.IE) {
	qer := me.rib.GetQER(seid, qerid)
	qer.NeedsUpdate = true

	qer.GateStatusDL, _ = pfcp_qer.GateStatusDL()
	qer.GateStatusUL, _ = pfcp_qer.GateStatusUL()
	qer.SessionMBRDL, _ = pfcp_qer.MBRDL()
	qer.SessionMBRUL, _ = pfcp_qer.MBRUL()
	qer.QFI, _ = pfcp_qer.QFI()

}

func (me *PfcpAgent) handleSessionDeletionRequest(msg *message.SessionDeletionRequest) {

	var mp uint8 = 0
	var fo uint8 = 0
	var seid uint64 = msg.SEID()
	var seq uint32 = msg.SequenceNumber
	var prio uint8 = 0
	var cause *ie.IE

	success, toBeDeletedFlows := me.rib.DeleteSession(seid)
	if success {
		success = me.deleteFlowRuleFromUserPlane(toBeDeletedFlows)
	}
	if success {
		cause = ie.NewCause(ie.CauseRequestAccepted)
	} else {
		cause = ie.NewCause(ie.CauseRequestRejected)
	}

	response := message.NewSessionDeletionResponse(mp, fo, seid, seq, prio, cause)
	log.Debugf("\nSessionDeletionResponse: %s\n\n\n", response)
	me.sendMsg(response)
}
