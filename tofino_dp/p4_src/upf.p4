/*
# Copyright 2022-present Ralf Kundel, Fridolin Siegmund
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

#include <core.p4>
#include <tna.p4>
#include "header.p4"

#define ETH_HDR_SIZE 14
////////////////// PARSER START ///////////////////////////

// taken from util.p4
parser TofinoIngressParser(
        packet_in pkt,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        transition reject;
    }

    state parse_port_metadata {
        pkt.advance(64);
        transition accept;
    }
}

struct pvs_data {
    bit<9> ingress_port;
}

parser SwitchIngressParser(packet_in packet, out headers_t hdr, out metadata_t meta, out ingress_intrinsic_metadata_t ig_intr_md) {
    TofinoIngressParser() tofino_parser;

    value_set<pvs_data>(8) fpga_port;

    state start {
        meta.us_load_balance = 2w0x0;
        meta.is_processed = 1w0x0;
        meta.is_encap = 1w0x0;
		tofino_parser.apply(packet, ig_intr_md);
		transition parse_ethernet;
	}

	state parse_ethernet {
		packet.extract(hdr.ethernet);
		transition select(hdr.ethernet.etherType) {
			16w0x0800: parse_ipv4;
			default: accept;
		}
	}

	state parse_ipv4 {
		packet.extract(hdr.ipv4);
        meta.dst_ip = hdr.ipv4.dstAddr;
        transition select(ig_intr_md.ingress_port){
            fpga_port: accept;
            default: parse_ipv4_2;
        }
	}

    state parse_ipv4_2 {
		transition select(hdr.ipv4.protocol) {
			8w0x11: pre_parse_udp;
			default: accept;
		}
    }

    // first check if it's really needed to parse UDP
    // prevents parsing of UDP header if packet is *not* encapsulated in GTP
    // To encpasulate hdr.udp.setValid() would overwrite inner UDP header
    state pre_parse_udp {
        transition select(packet.lookahead<udp_t>().dstPort) { // lookahead srcPort
            16w0x0868: parse_udp; // srcPort and dstPort are same for GTP
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            16w0x0868: parse_gtp;  // port 2152
            default: accept;
        }
	}

    state parse_gtp {
        packet.extract(hdr.gtp_v1);
        transition select(hdr.gtp_v1.seq_flag ++ hdr.gtp_v1.ex_flag) {
            2w0x0: parse_ipv4_inner;
            default: parse_gtp_seq;
        }
    }

    state parse_gtp_seq {
        packet.extract(hdr.gtp_v1_seq);
        transition pre_parse_gtp_extension;
    }
    
    state pre_parse_gtp_extension {
    	transition select(hdr.gtp_v1.ex_flag) {
            1w0x1: parse_gtp_extension;
            1w0x0: parse_ipv4_inner;
        }
    }


    state parse_gtp_extension {
        packet.extract(hdr.gtp_v1_ext_pdu);
        //TODO: make it recursive
        transition parse_ipv4_inner;
    }

    // inner IPv4 header, encapsulated by GTP
    state parse_ipv4_inner {
        packet.extract(hdr.ipv4_inner);
        transition accept;
    }


}

////////////////// PARSER END ///////////////////////////


////////////////// INGRESS START ////////////////////////

control Upstream(
	inout headers_t hdr,
	inout metadata_t meta,
	in ingress_intrinsic_metadata_t ig_intr_md,
	inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {
	
	
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) direct_counter;
	DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) direct_counter_no_antispoof;
	
        // removes all gtp headers and forwards 
        action terminate(){
            hdr.gtp_v1.setInvalid();
            hdr.gtp_v1_seq.setInvalid();
            hdr.gtp_v1_ext_pdu.setInvalid();
            hdr.udp.setInvalid(); // gtp is udp based
            hdr.ipv4.setInvalid();
            
            direct_counter.count();
        }

        action terminate_no_antispoof(){
            hdr.gtp_v1.setInvalid();
            hdr.gtp_v1_seq.setInvalid();
            hdr.gtp_v1_ext_pdu.setInvalid();
            hdr.udp.setInvalid(); // gtp is udp based
            hdr.ipv4.setInvalid();
            
            direct_counter_no_antispoof.count();
        }

        table t_us_decap_antispoof_v4 {
            key = {
                ig_intr_md.ingress_port: exact; //TODO needed?
                //hdr.ipv4.srcAddr: exact;  //gNodeB IP
                hdr.gtp_v1.teid: exact; 
                hdr.ipv4_inner.srcAddr: exact; //UE IP --> antispoof
            }
            actions = {
                terminate;
            }
            size = 64;
            counters = direct_counter;
        }
        table t_us_decap_v4 {
            key = {
                ig_intr_md.ingress_port: exact; //TODO needed?
                //hdr.ipv4.srcAddr: exact;  //gNodeB IP
                hdr.gtp_v1.teid: exact; 
                //hdr.ipv4_inner.srcAddr: exact; //UE IP --> antispoof
            }
            actions = {
                terminate_no_antispoof;
            }
            size = 64;
            counters = direct_counter_no_antispoof;
        }
        
        action a_forward(bit<48> dstAddr, bit<9> egress_port){
            hdr.ethernet.dstAddr = dstAddr;
            ig_intr_tm_md.ucast_egress_port = egress_port; 
            meta.is_processed = 1w0x1;
        }
        
	    table t_us_route{
            key = {
                meta.us_load_balance: exact;
            }
            actions = {
                a_forward;
            }
            size = 4;
        }

        apply {
            if(hdr.gtp_v1.isValid()){
                t_us_decap_antispoof_v4.apply();
                t_us_decap_v4.apply();
                t_us_route.apply();
            }
        }


}

control Downstream(
        inout headers_t hdr,
        inout metadata_t meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

        action update_addresses(bit<32> gnodeb_ip, bit<32> teid, bit<32> upf_ip){

            // outer ipv4      
            hdr.ipv4_outer.setValid();
            hdr.ipv4_outer.version = 4w0x4;
            hdr.ipv4_outer.ihl = 4w0x5;
            hdr.ipv4_outer.diffServ = 8w0x0;
            hdr.ipv4_outer.srcAddr = upf_ip; //TODO: das muss zentraler // meta.addr.upf_src = upf_ip; 
            hdr.ipv4_outer.dstAddr = gnodeb_ip;
            hdr.ipv4_outer.protocol = 8w0x11; //UDP=17
            hdr.ipv4_outer.ttl = 8w0x40; //64
            hdr.ipv4_outer.id = 16w0x01;

            meta.dst_ip = gnodeb_ip;


            // udp
            hdr.udp.setValid();
            hdr.udp.srcPort = 16w0x0868;  // port 2152
            hdr.udp.dstPort = 16w0x0868;  // port 2152
            hdr.udp.len = 16w0x0; // fill in egress, eg_intr_md.pkt_length only in egress available
            hdr.udp.checksum = 0;

            //gtp
            hdr.gtp_v1.setValid();
            hdr.gtp_v1.version = 3w0x1;
            hdr.gtp_v1.protocolType = 1w0x1;
            hdr.gtp_v1.reserved = 1w0x0;
            hdr.gtp_v1.ex_flag = 1w0x1; //TODO
            hdr.gtp_v1.npdu_flag = 1w0x0;
            hdr.gtp_v1.messageType = 8w0xff;
            hdr.gtp_v1.messageLength = 16w0x0; // => fill in egress, eg_intr_md.pkt_length only in egress available
            hdr.gtp_v1.teid = teid;


            //add qfi extension
            hdr.gtp_v1.seq_flag = 1w0x0;
            hdr.gtp_v1_seq.setValid();
            hdr.gtp_v1_seq.next_extension_hdr_type = 8w0x85;
            hdr.gtp_v1_ext_pdu.setValid();
            hdr.gtp_v1_ext_pdu.extension_length = 1;
            hdr.gtp_v1_ext_pdu.foo = 16w0x0009;
            hdr.gtp_v1_ext_pdu.next_extension_hdr_type = 8w0x0;
            
            meta.is_encap = 1w0x1;
            

            
        }

        table t_ds_encap_v4 {
            key = {
                hdr.ipv4.dstAddr : exact; // match IP of UPF
            }
            actions = {
                update_addresses;
            }
            size = 64;
        }
                
                
        action a_send_to_qos_chip(bit<32> queue_id, bit<9> egress_port){
            ig_intr_tm_md.ucast_egress_port = egress_port; 
            meta.is_processed = 1w0x1;
            //TODO store queue_id in dst_mac
        }
        
        table t_ds_qos {
            key = {
                hdr.gtp_v1.teid : exact;
            }
            actions = {
                a_send_to_qos_chip;
            }
            size = 64;
        }
                
        action a_forward(bit<48> dstAddr, bit<9> egress_port){
            hdr.ethernet.dstAddr = dstAddr;
            ig_intr_tm_md.ucast_egress_port = egress_port; 
            meta.is_processed = 1w0x1;
        }


        
        table t_ds_route_v4{
            actions = {
                a_forward;
            }
            key = {
                meta.dst_ip:   exact;
            }
            size = 4096;
        }
        

        apply {
            if(!hdr.gtp_v1.isValid() && meta.usds == 2 ){
                if (t_ds_encap_v4.apply().hit){
                    t_ds_qos.apply();
                }                
            }
            if(meta.usds == 4 || (meta.is_encap==1 && meta.is_processed == 0) ) { //4 = from fpga or 
                t_ds_route_v4.apply();
            }
        }

}

control SwitchIngress(
		inout headers_t hdr,
		inout metadata_t meta,
		in ingress_intrinsic_metadata_t ig_intr_md,
		in ingress_intrinsic_metadata_from_parser_t ig_intr_parser_md,
		inout ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr,
		inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {


        action a_usds(bit<3> usds){ //0 unused, 1 upstream, 2 downstream, 3 from softwareswitch
            meta.usds = usds;
        }
        table t_usdssp {
            key = {
                ig_intr_md.ingress_port : exact;
            }
            actions = {
                a_usds;
            }
            size = 64;
        }


        action a_sp_encap(bit<32> sp_ip, bit<32> upf_ip, bit<48> dstAddr, bit<48> srcAddr, bit<9> egress_port){
            hdr.ethernet_inner.setValid();
            hdr.ethernet_inner.etherType = hdr.ethernet.etherType;
            hdr.ethernet_inner.dstAddr = hdr.ethernet.dstAddr;
            hdr.ethernet_inner.srcAddr = hdr.ethernet.srcAddr; 
            
            hdr.ethernet.etherType = 16w0x0800;
            hdr.ethernet.dstAddr = dstAddr;
            hdr.ethernet.srcAddr = srcAddr;  //TODO needed? 
            //upf_ip --> das kann zentraler //TODO
                        
            hdr.ipv4_outer.setValid();
            hdr.ipv4_outer.version = 4w0x4;
            hdr.ipv4_outer.ihl = 4w0x5;
            hdr.ipv4_outer.diffServ = 8w0x0;
            hdr.ipv4_outer.srcAddr = upf_ip; 
            hdr.ipv4_outer.dstAddr = sp_ip;
            hdr.ipv4_outer.protocol = 8w0x11; //UDP=17
            hdr.ipv4_outer.ttl = 8w0x40; //64
            hdr.ipv4_outer.id = 16w0x01;

            // udp
            hdr.udp.setValid();
            hdr.udp.srcPort = 16w0x0868;  // port 2152
            hdr.udp.dstPort = 16w0x0868;  // port 2152
            hdr.udp.len = 16w0x0; // fill in egress, eg_intr_md.pkt_length only in egress available
            hdr.udp.checksum = 0;

            //gtp
            hdr.gtp_v1.setValid();
            hdr.gtp_v1.version = 3w0x1;
            hdr.gtp_v1.protocolType = 1w0x1;
            hdr.gtp_v1.reserved = 1w0x0;
            hdr.gtp_v1.ex_flag = 1w0x0;
            hdr.gtp_v1.npdu_flag = 1w0x0;
            hdr.gtp_v1.messageType = 8w0xff;
            hdr.gtp_v1.messageLength = 16w0x0; // => fill in egress, eg_intr_md.pkt_length only in egress available
            hdr.gtp_v1.teid = 23w0x0 ++ ig_intr_md.ingress_port;

            //egress port
            ig_intr_tm_md.ucast_egress_port = egress_port; 
        }

        table t_sp_encap {
            key = {
                meta.is_processed: exact;
            }
            actions = {
                a_sp_encap;
            }
            size = 2;
        }
        

        action set_src_mac(bit<48> src_mac) {
            hdr.ethernet.srcAddr = src_mac;
        }

        table t_set_src_mac { //applied on all packets
            key = {
                ig_intr_tm_md.ucast_egress_port : exact;
            }
            actions = {
                set_src_mac;
            }
            size = 64;
        }

        action a_sp_decap(){
            ig_intr_tm_md.ucast_egress_port = (bit<9>) hdr.gtp_v1.teid; 
            hdr.ethernet.setInvalid();
            hdr.ipv4.setInvalid();
            hdr.udp.setInvalid();
            hdr.gtp_v1.setInvalid();
        }

        
        Upstream() upstream;
        Downstream() downstream;

        apply {
        

            t_usdssp.apply();

            if(meta.usds ==1){
                upstream.apply(hdr, meta, ig_intr_md, ig_intr_tm_md);
            }else if (meta.usds==2 || meta.usds ==4){
                downstream.apply(hdr, meta, ig_intr_md, ig_intr_tm_md);
            } else if (meta.usds==3) {
            	//TODO slow path inject
                a_sp_decap();
                meta.is_processed = 1w0x1;
            }

            t_sp_encap.apply();

            if(hdr.ethernet.isValid()){
                t_set_src_mac.apply();
            }
        }
}

control SwitchIngressDeparser(packet_out packet, inout headers_t hdr, in metadata_t meta, in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply{
        packet.emit(hdr.ethernet);
        //opt:
        packet.emit(hdr.ipv4_outer);
        packet.emit(hdr.udp);
        packet.emit(hdr.gtp_v1);
        packet.emit(hdr.gtp_v1_seq);
        packet.emit(hdr.gtp_v1_ext_pdu);
        
        packet.emit(hdr.ipv4); 
        //xor
        packet.emit(hdr.ipv4_inner);
        packet.emit(hdr.ethernet_inner);
    }
}

////////////////// INGRESS END ////////////////////////

////////////////// EGRESS START ////////////////////////

parser TofinoEgressParser(packet_in pkt, out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

parser SwitchEgressParser(packet_in packet, out headers_t hdr, out metadata_t meta, out egress_intrinsic_metadata_t eg_intr_md) {

	TofinoEgressParser() tofino_parser;
    // until now no egress pipeline needed

    state start {
		tofino_parser.apply(packet, eg_intr_md);
		transition parse_ethernet;
	}

	state parse_ethernet {
		packet.extract(hdr.ethernet);
		transition select(hdr.ethernet.etherType) {
			16w0x0800: parse_ipv4;
			default: accept;
		}
	}

	state parse_ipv4 {
		packet.extract(hdr.ipv4);
		transition select(hdr.ipv4.protocol) {
			8w0x11: parse_udp;
			default: accept;
		}
	}

    state parse_udp {
		packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            16w0x0868: parse_gtp;  // port 2152
            16w0x0869: parse_gtp;  // port 2153
            default: accept;
        }
	}

    state parse_gtp {
        packet.extract(hdr.gtp_v1);
        transition select(hdr.gtp_v1.seq_flag ++ hdr.gtp_v1.ex_flag) {
            2w0x0: accept;
            default: parse_gtp_seq;
        }
    }

    state parse_gtp_seq {
        packet.extract(hdr.gtp_v1_seq);
        transition pre_parse_gtp_extension;
    }
    
    state pre_parse_gtp_extension {
    	transition select(hdr.gtp_v1.ex_flag) {
            1w0x1: parse_gtp_extension;
            1w0x0: accept;
        }
    }


    state parse_gtp_extension {
        packet.extract(hdr.gtp_v1_ext_pdu);
        //TODO: make it recursive
        transition accept;
    }

}

control SwitchEgress(
    inout headers_t hdr,
	inout metadata_t meta,
	in egress_intrinsic_metadata_t eg_intr_md,
	in egress_intrinsic_metadata_from_parser_t eg_intr_parser_md,
	inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
	inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {
	
        action a_set_queue_id(){
            hdr.queue_id.setValid();
            hdr.queue_id.queue_id = 15; //TODO
        }

        table t_ds_qos_egress {
            key = {
                eg_intr_md.egress_port : exact; // match for FPGA (QoS chip) port
            }
            actions = {
                a_set_queue_id;
            }
            size = 64;
        }
        

    apply{ 
        if(hdr.gtp_v1.isValid()){
            // 0x0 indicates empty fields from ingress
            if(hdr.gtp_v1.messageLength == 16w0x0){
                if(hdr.gtp_v1_ext_pdu.isValid()){
                    hdr.ipv4.paketlen = (bit<16>)(eg_intr_md.pkt_length + 26);
                    hdr.gtp_v1.messageLength = (bit<16>) (eg_intr_md.pkt_length - 10); // -14 eth header - 20 ipv4 header - 8 udp header - 8 byte GTP header
                    hdr.udp.len = (bit<16>)(eg_intr_md.pkt_length + 6);               // -14 eth header - 20 ipv4 header
                }else{
                    hdr.ipv4.paketlen = (bit<16>)(eg_intr_md.pkt_length + 18);
                    hdr.gtp_v1.messageLength = (bit<16>) (eg_intr_md.pkt_length - 18); // -14 eth header - 20 ipv4 header - 8 udp header - 8 byte GTP header
                    hdr.udp.len = (bit<16>)(eg_intr_md.pkt_length - 2);               // -14 eth header - 20 ipv4 header
            }
            }
        }
        t_ds_qos_egress.apply();
    }

}

control SwitchEgressDeparser(packet_out packet, inout headers_t hdr, in metadata_t meta, in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    Checksum() ipv4_checksum;

    apply{
        if(hdr.ipv4.isValid()){
            hdr.ipv4.header_checksum = ipv4_checksum.update({
                    hdr.ipv4.version,
                    hdr.ipv4.ihl,
                    hdr.ipv4.diffServ,
                    hdr.ipv4.paketlen,
                    hdr.ipv4.id,
                    hdr.ipv4.flags,
                    hdr.ipv4.fragOffset,
                    hdr.ipv4.ttl,
                    hdr.ipv4.protocol,
                    hdr.ipv4.srcAddr,
                    hdr.ipv4.dstAddr
            });
        }

        //packet.emit(hdr);
        // necessary otherwise header order is confused
        packet.emit(hdr.queue_id);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.gtp_v1);
        packet.emit(hdr.gtp_v1_seq);
        packet.emit(hdr.gtp_v1_ext_pdu);
    }
}

// there must be Parser/main/Deparser for both Ingress and Egress when using "Switch(pipe)" -> tofino TNA model
Pipeline(SwitchIngressParser(),
	SwitchIngress(),
	SwitchIngressDeparser(),
	SwitchEgressParser(), 
	SwitchEgress(),
	SwitchEgressDeparser()) pipe;

Switch(pipe) main;
