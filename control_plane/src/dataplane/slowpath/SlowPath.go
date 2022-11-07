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
package slowpath

import (
	"context"
	"net"
	"p4hc-upf/src/lib"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"
)

type SlowPath struct {
	ip         net.IP
	switchSpIp net.IP
	wg         sync.WaitGroup
	ArpCache   ArpCache
	udp_out    *net.UDPConn
}

func NewSlowPath(ip net.IP, switchSpIp net.IP) *SlowPath {
	arpCache := NewArpCache()
	slowPath := SlowPath{
		ip:         ip,
		switchSpIp: switchSpIp,
		ArpCache:   arpCache,
	}
	return &slowPath
}

func (me *SlowPath) Terminate() {
	log.Infoln("Terminate SlowPath Wrapper")
	me.wg.Done()
	me.udp_out.Close()
	me.wg.Wait()
}

func (me *SlowPath) GetMac(ip net.IP, access bool, core bool) (string, uint16) {

	for i := 1; i <= 5; i++ {

		mac, port := me.ArpCache.Find(ip)
		if mac != "" {
			return mac, port
		}
		me.generateArpRequests(ip, access, core)
		time.Sleep(100 * time.Millisecond)
	}

	return "", 0
}

func (me *SlowPath) StartListener() {
	me.wg.Add(1)
	ctx, _ := context.WithCancel(context.Background())

	go me.runListener(ctx)

	var err error
	addr := net.UDPAddr{
		Port: 2152,
		IP:   me.switchSpIp,
	}
	me.udp_out, err = net.DialUDP("udp", nil, &addr)
	if err != nil {
		log.Warnf("Error While setting up dial out udp conn: %v\n", err)
	}

}

func (me *SlowPath) runListener(ctx context.Context) {
	p := make([]byte, 2048)
	addr := net.UDPAddr{
		Port: 2152,
		IP:   me.ip,
	}
	ser, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Warnf("Slow Path start listener error: %v\n", err)
		return
	}
	for {
		select {
		case <-ctx.Done():
			log.Infoln("Terminated slow path")
			ser.Close()
			return
		default:
		}

		_, remoteaddr, err := ser.ReadFromUDP(p)
		if err != nil {
			log.Warnf("Some error while receiving a packet in slowpath: %v", err)
			continue
		}
		if !remoteaddr.IP.Equal(me.switchSpIp) {
			log.Warnf("Received a message from unknown sender: %v. payload: %s \n", remoteaddr, p)
		}

		var packet gopacket.Packet = gopacket.NewPacket(p, layers.LayerTypeGTPv1U, gopacket.Lazy)
		//var gtp layers.LayerTypeGTPv1U = packet.Layer(layers.LayerTypeGTPv1U)

		if gtpLayer := packet.Layer(layers.LayerTypeGTPv1U); gtpLayer != nil {
			gtp, _ := gtpLayer.(*layers.GTPv1U)
			innerPacket := gopacket.NewPacket(gtp.LayerPayload(), layers.LayerTypeEthernet, gopacket.Default)
			me.processPacket(innerPacket, gtp.TEID)
		}
	}
}

func (me *SlowPath) processPacket(packet gopacket.Packet, port uint32) {
	log.Debugln("This is a incoming packet on port: %d!\n", port)

	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		arp, _ := arpLayer.(*layers.ARP)
		if arp.Operation == 1 {
			me.handleArpRequest(arp, port)
		} else if arp.Operation == 2 {
			me.handleArpResponse(arp, port)
		}
		return
	}
}

func (me *SlowPath) sendPacket(packet []byte, port uint32) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buf, opts,
		&layers.GTPv1U{
			Version:             1,
			ProtocolType:        1,
			ExtensionHeaderFlag: false,
			SequenceNumberFlag:  false,
			NPDUFlag:            false,
			MessageType:         255,
			MessageLength:       uint16(len(packet)),
			TEID:                port,
		},
		gopacket.Payload(packet),
	)
	me.udp_out.Write(buf.Bytes())
}

func (me *SlowPath) handleArpRequest(arp *layers.ARP, port uint32) {
	dst_ip := net.IP(arp.DstProtAddress)
	resp_mac := me.ArpCache.GetOwn(dst_ip, uint16(port))
	if resp_mac == "" { //check if the dst_ip belongs to us
		return
	}

	//1. learn remote arp address
	src_ip := net.IP(arp.SourceProtAddress)
	me.ArpCache.Learn(lib.ByteToMac(arp.SourceHwAddress), src_ip, uint16(port))

	//2. response to request

	resp_mac_b := lib.MacStringToByte(resp_mac)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{
			SrcMAC:       resp_mac_b,
			DstMAC:       arp.SourceHwAddress,
			EthernetType: layers.EthernetTypeARP,
		},
		&layers.ARP{
			AddrType:          arp.AddrType,
			Protocol:          arp.Protocol,
			HwAddressSize:     arp.HwAddressSize,
			ProtAddressSize:   arp.ProtAddressSize,
			Operation:         2,
			SourceHwAddress:   resp_mac_b,
			SourceProtAddress: arp.DstProtAddress,
			DstHwAddress:      arp.SourceHwAddress,
			DstProtAddress:    arp.SourceProtAddress,
		},
	)
	packetData := buf.Bytes()
	log.Debugf("Answer to ARP request from: " + src_ip.String())
	me.sendPacket(packetData, port)
}

func (me *SlowPath) handleArpResponse(arp *layers.ARP, port uint32) {
	src_ip := net.IP(arp.SourceProtAddress)
	me.ArpCache.Learn(lib.ByteToMac(arp.SourceHwAddress), src_ip, uint16(port))
}

func (me *SlowPath) generateArpRequests(ip net.IP, access bool, core bool) {
	for _, x := range me.ArpCache.GetSwitchPorts() {
		if access && !x.access {
			continue
		}
		if core && !x.core {
			continue
		}
		me.generateArpRequest(ip, x)
	}
}
func (me *SlowPath) generateArpRequest(ip net.IP, own_port SwitchPort) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	var ip_b []byte = ip.To4()
	var own_ip_b []byte = own_port.ipv4.To4()
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{
			SrcMAC:       lib.MacStringToByte(own_port.mac),
			DstMAC:       lib.MacStringToByte("ff:ff:ff:ff:ff:ff"),
			EthernetType: layers.EthernetTypeARP,
		},
		&layers.ARP{
			AddrType:          1,
			Protocol:          0x0800, //IPv4
			HwAddressSize:     6,
			ProtAddressSize:   4,
			Operation:         1,
			SourceHwAddress:   lib.MacStringToByte(own_port.mac),
			SourceProtAddress: own_ip_b,
			DstHwAddress:      lib.MacStringToByte("00:00:00:00:00:00"),
			DstProtAddress:    ip_b,
		},
	)
	packetData := buf.Bytes()
	log.Infof("Send arp request to: " + ip.String() + " on port: " + strconv.FormatUint(uint64(own_port.p4_port), 10))
	me.sendPacket(packetData, uint32(own_port.p4_port))
}
