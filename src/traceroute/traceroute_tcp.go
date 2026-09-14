package traceroute_tcp

import (
	"bufio"
	"dns_tools/common"
	"dns_tools/common/tcp_common"
	"dns_tools/config"
	"dns_tools/logging"
	"encoding/binary"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type Tcp_traceroute struct {
	common.Base
	tcp_common.Tcp_sender
	lowest_port   uint16
	highest_port  uint16
	init_finished []bool
	write_chan    chan *tracert_param
}

func (tcpt *Tcp_traceroute) Traceroute_init() {
	tcpt.Base_init()
	tcpt.lowest_port = 61024 // smallest multiple of 32 outside random port range
	tcpt.write_chan = make(chan *tracert_param, 256)
	tcpt.L2_sender = &tcpt.L2_v4
}

type tracert_hop struct {
	hop_count   int
	ts          time.Time
	response_ip net.IP
}

type tracert_param struct {
	traceroute_mutex     sync.Mutex
	all_syns_sent        int64
	all_dns_packets_sent int64
	syn_ack_received     int64
	dns_reply_received   int64
	initial_ip           net.IP
	first_to_syn_ack     net.IP
	dns_traceroute_port  layers.TCPPort
	finished             int64
	written              bool
	syntr_hops           []tracert_hop
	dnstr_hops           []tracert_hop
	dns_answers          []net.IP
}

func (params *tracert_param) zero() {
	params.all_dns_packets_sent = -1
	params.all_syns_sent = -1
	params.syn_ack_received = -1
	params.dns_reply_received = -1
	params.written = false
	params.finished = -1
	params.dns_traceroute_port = layers.TCPPort(0)
	params.syntr_hops = []tracert_hop{}
	params.dnstr_hops = []tracert_hop{}
	params.dns_answers = []net.IP{}
	params.initial_ip = nil
}

func (params *tracert_param) str_dns_answers() []string {
	dns_answers_str := ""
	for idx, answer := range params.dns_answers {
		dns_answers_str += answer.String()
		if idx < len(params.dns_answers)-1 {
			dns_answers_str += ","
		}
	}
	dns_slice := []string{"DNSANS", "", "", dns_answers_str}
	logging.Println(6, "str_dns_answers", "dns_answers slice:", dns_slice)
	return dns_slice
}

var tracert_params = map[int]*tracert_param{}
var tracert_mutex sync.Mutex

func (tcpt *Tcp_traceroute) build_ack_with_dns(dst_ip net.IP, src_port layers.TCPPort, seq_num uint32, ack_num uint32, ttl uint8) (layers.IPv4, layers.TCP, []byte) {
	// === build packet ===
	// Create ip layer
	ip := layers.IPv4{
		Version:  4,
		TTL:      ttl,
		SrcIP:    net.ParseIP(config.Cfg.Iface_ip),
		DstIP:    dst_ip,
		Protocol: layers.IPProtocolTCP,
		Id:       uint16(tcpt.calc_start_port(uint16(src_port))) + uint16(ttl),
	}

	// Create tcp layer
	tcp := layers.TCP{
		SrcPort: src_port,
		DstPort: layers.TCPPort(config.Cfg.Dst_port),
		ACK:     true,
		PSH:     true,
		Seq:     ack_num,
		Ack:     seq_num + 1,
		Window:  8192,
	}
	tcp.SetNetworkLayerForChecksum(&ip)

	// create dns layers
	qst := layers.DNSQuestion{
		Name:  []byte(config.Cfg.Dns_query),
		Type:  layers.DNSTypeA,
		Class: layers.DNSClassIN,
	}
	dns := layers.DNS{
		Questions: []layers.DNSQuestion{qst},
		RD:        true,
		QDCount:   1,
		OpCode:    layers.DNSOpCodeQuery,
		ID:        uint16(uint32(tcpt.calc_start_port(uint16(src_port))) + uint32(ttl)),
	}

	dns_buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(dns_buf, gopacket.SerializeOptions{}, &dns)
	// prepend dns payload with its size, as gopacket does not do this automatically
	dns_buf_bytes := dns_buf.Bytes()
	dns_corrected := make([]byte, len(dns_buf_bytes)+2)
	dns_corrected[0] = uint8(0)
	dns_corrected[1] = uint8(len(dns_buf_bytes))
	for i := 0; i < len(dns_buf_bytes); i++ {
		dns_corrected[i+2] = dns_buf_bytes[i]
	}
	return ip, tcp, dns_corrected
}

func (tcpt *Tcp_traceroute) send_ack_with_dns(dst_ip net.IP, src_port layers.TCPPort, seq_num uint32, ack_num uint32, ttl uint8) {
	logging.Println(6, tcpt.id_from_port(uint16(src_port)), "sending dns to", dst_ip.String(), "with ttl=", ttl)
	tcpt.Send_tcp_pkt_v4(tcpt.build_ack_with_dns(dst_ip, src_port, seq_num, ack_num, ttl))
}

func (tcpt *Tcp_traceroute) Handle_pkt(ip gopacket.NetworkLayer, pkt gopacket.Packet) {
	icmp_layer := pkt.Layer(layers.LayerTypeICMPv4)
	icmp, _ := icmp_layer.(*layers.ICMPv4)
	if icmp != nil && icmp.TypeCode == layers.ICMPv4TypeTimeExceeded {
		logging.Println(5, "", "received ICMP packet")
		//icmpPacket, _ := icmp_layer.(*layers.ICMPv4)

		// Print information about the ICMPv4 packet
		//log.Println("IPv4 Source: ", ip.SrcIP)
		//log.Println("IPv4 Destination: ", ip.DstIP)

		// Extract the encapsulated TCP layer
		// The TCP layer is truncated, however, we only need the src port which is encoded in the first 2 bytes of the ip payload

		// get icmp payload bytes
		payloadBytes := icmp.LayerPayload()
		if payloadBytes == nil {
			return
		}
		//handle icmp payload as new ipv4 packet (Time Exceeded Message returns IP header + 8 bytes of ip payload)
		packet := gopacket.NewPacket(payloadBytes, layers.LayerTypeIPv4, gopacket.Default)

		ip_layer := packet.Layer(layers.LayerTypeIPv4)
		if ip_layer == nil {
			// no tcp layer means not of interest to us!
			logging.Println(5, "", "No TCP layer found in the payload.")
			return
		}

		inner_ip, _ := ip_layer.(*layers.IPv4)
		// icmp has no correct IP header payload
		if len(inner_ip.Payload) < 20 {
			logging.Println(6, "ICMP-Payload ERR", pkt)
			return
		}
		// Decode source port (first 2 bytes)
		source_port := layers.TCPPort(binary.BigEndian.Uint16(inner_ip.Payload[:2]))
		start_port := tcpt.calc_start_port(uint16(source_port))
		logging.Println(6, tcpt.id_from_port(uint16(start_port)), "Source port: ", source_port)
		//log.Println("Destination Port:", tcp.DstPort)
		// Add more fields as needed

		params, exists := tracert_params[start_port]
		if !exists {
			// dont know where this packet came from but its not part of the scan
			logging.Println(5, tcpt.id_from_port(uint16(start_port)), "traceroute parameters do not exist for start port", start_port)
			return
		}
		// if we did not receive a syn ack and the source port is <= 65100 (which we use for all the syns we sent) add this to the
		if params.syn_ack_received == -1 && source_port >= layers.TCPPort(tcpt.lowest_port) && source_port < layers.TCPPort(tcpt.highest_port) {
			src_port_int := int(source_port)
			hop := src_port_int - start_port
			if params.initial_ip.Equal(net.IP(ip.NetworkFlow().Src().Raw())) {
				logging.Println(3, tcpt.id_from_port(uint16(start_port)), "\033[0;31m[*] \t Hop ", hop, " ", net.IP(ip.NetworkFlow().Src().Raw()), "\033[0m")
			} else {
				logging.Println(3, tcpt.id_from_port(uint16(start_port)), "[*] \t Hop ", hop, " ", net.IP(ip.NetworkFlow().Src().Raw()))
			}
			params.traceroute_mutex.Lock()
			params.syntr_hops = append(params.syntr_hops, tracert_hop{
				hop_count:   hop,
				ts:          time.Now().UTC(),
				response_ip: net.IP(ip.NetworkFlow().Src().Raw()),
			})
			params.traceroute_mutex.Unlock()

		} else if params.syn_ack_received != -1 && params.dns_traceroute_port == source_port {
			// we received an icmp packet and have already seen a syn ack and the sourcePort is equal to the dns traceroute port
			// put data into second list
			// to meet the TCP flow the TCP SrcPort remains unchanged when sending our DNS requesrt after receiving a Syn/Ack from a server
			// that means we cannot use the sourcePort extracted from the TCP header within the ICMP payload
			// to overcome this issue we use a custom IP.Id value when sending the DNS request
			// we set its value to 65000 + ttl (same as for tcp.SrcPort) and use it here as the hop value

			hop := inner_ip.Id - uint16(start_port)
			if params.initial_ip.Equal(net.IP(ip.NetworkFlow().Src().Raw())) {
				logging.Println(3, tcpt.id_from_port(uint16(start_port)), "\033[0;31m[*] \t DNSTR Hop ", hop, " ", net.IP(ip.NetworkFlow().Src().Raw()), "\033[0m")
			} else {
				logging.Println(3, tcpt.id_from_port(uint16(start_port)), "[*] \t DNSTR Hop ", hop, " ", net.IP(ip.NetworkFlow().Src().Raw()))
			}
			params.traceroute_mutex.Lock()
			params.dnstr_hops = append(params.dnstr_hops, tracert_hop{
				hop_count:   int(hop),
				ts:          time.Now().UTC(),
				response_ip: net.IP(ip.NetworkFlow().Src().Raw()),
			})
			params.traceroute_mutex.Unlock()
		}
	} else {
		tcp_layer := pkt.Layer(layers.LayerTypeTCP)
		if tcp_layer == nil {
			return
		}
		tcp, ok := tcp_layer.(*layers.TCP)
		if !ok { // skip wrong packets
			return
		}
		tcpflags := tcp_common.TCP_flags{
			PSH: tcp.PSH,
			FIN: tcp.FIN,
			SYN: tcp.SYN,
			RST: tcp.RST,
			ACK: tcp.ACK,
		}

		start_port := tcpt.calc_start_port(uint16(tcp.DstPort))
		params, exists := tracert_params[start_port]
		if !exists {
			// dont know where this packet came from but its not part of the scan
			return
		}

		if pkt.ApplicationLayer() == nil {
			if tcpflags.Is_SYN() {
				// received a SYN packet whysoever!?
				// we make sure to put it in our data queue
				// check if item in map and assign value
				logging.Println(3, tcpt.id_from_port(uint16(start_port)), "[*] Received unexpected SYN from ", net.IP(ip.NetworkFlow().Src().Raw()))
			} else
			// SYN-ACK
			if tcpflags.Is_SYN_ACK() {
				logging.Println(5, tcpt.id_from_port(uint16(start_port)), "received SYN-ACK from", net.IP(ip.NetworkFlow().Src().Raw()), "to port", tcp.DstPort)
				if params.syn_ack_received == -1 {
					// first syn ack -> put into icmp queue
					// we start dns traceroute only for the first packet!
					hop := int(tcp.DstPort) - start_port
					if params.initial_ip.Equal(net.IP(ip.NetworkFlow().Src().Raw())) {
						logging.Println(3, tcpt.id_from_port(uint16(start_port)), "\033[0;31m[*] \t Hop ", hop, " ", net.IP(ip.NetworkFlow().Src().Raw()), "\033[0m")
					} else {
						logging.Println(3, tcpt.id_from_port(uint16(start_port)), "[*] \t Hop ", hop, " ", net.IP(ip.NetworkFlow().Src().Raw()))
					}
					logging.Println(3, tcpt.id_from_port(uint16(start_port)), "[*] Received SYN/ACK from ", net.IP(ip.NetworkFlow().Src().Raw()))
					params.traceroute_mutex.Lock()
					params.syntr_hops = append(params.syntr_hops, tracert_hop{
						hop_count:   hop,
						ts:          time.Now().UTC(),
						response_ip: net.IP(ip.NetworkFlow().Src().Raw()),
					})
					params.syn_ack_received = time.Now().Unix()
					params.first_to_syn_ack = net.IP(ip.NetworkFlow().Src().Raw())
					// memorize the port we use for dns traceroute as it needs to stay constant to match the state
					if (uint16)(params.dns_traceroute_port) != 0 {
						logging.Println(3, nil, "[***] DNS Traceroute is already ongoing")
						params.traceroute_mutex.Unlock()
						return
					}
					params.dns_traceroute_port = tcp.DstPort
					params.traceroute_mutex.Unlock()
					logging.Println(3, tcpt.id_from_port(uint16(start_port)), "[*] Initializing DNS Traceroute to", net.IP(ip.NetworkFlow().Src().Raw()), "over", params.initial_ip, "on port", tcp.DstPort)

					for i := 1; i < 30; i++ {
						_ = tcpt.Send_limiter.Take()
						if params.dns_reply_received != -1 {
							break
						}
						tcpt.send_ack_with_dns(params.initial_ip, tcp.DstPort, tcp.Seq, tcp.Ack, uint8(i))
					}
					params.traceroute_mutex.Lock()
					params.all_dns_packets_sent = time.Now().Unix()
					params.traceroute_mutex.Unlock()
					logging.Println(6, tcpt.id_from_port(uint16(tcp.DstPort)), "all DNS packets sent")

				} else {
					if tcp.DstPort != params.dns_traceroute_port {
						// we might end up here if we receive another syn-ack after the initial, as we dont consider this -> finalize connection
						logging.Println(5, tcpt.id_from_port(uint16(start_port)), "responding with ack and fin-ack to", params.initial_ip, "and port", tcp.DstPort)
						tcpt.Send_ack_pos_fin(params.initial_ip, tcp.DstPort, tcp.Seq, tcp.Ack, false)
						tcpt.Send_ack_pos_fin(params.initial_ip, tcp.DstPort, tcp.Seq, tcp.Ack, true)
					} else {
						logging.Println(6, tcpt.id_from_port(uint16(start_port)), "duplicate SYN-ACK")
					}
					if !(params.initial_ip.Equal(net.IP(ip.NetworkFlow().Src().Raw()))) && !(params.first_to_syn_ack.Equal(net.IP(ip.NetworkFlow().Src().Raw()))) {
						// received SA from IP that is different to initialIP and the IP addr. that sent first SA
						//intValue := int(tcp.DstPort)
						//hop := intValue - 65000
						// we need to comment this out, otherwise we might see SynAcks from previous measurements
						//log.Println("[*] Hop ", hop, " ", ip.SrcIP)
						//log.Println("[*] Received another SYN/ACK from ", ip.SrcIP)
						return
					}
				}
			} else
			// FIN-ACK
			if tcpflags.Is_FIN_ACK() {
				logging.Println(5, tcpt.id_from_port(uint16(start_port)), "received FIN-ACK from", net.IP(ip.NetworkFlow().Src().Raw()), "to port", tcp.DstPort)
				tcpt.Send_ack_pos_fin(params.initial_ip, tcp.DstPort, tcp.Seq, tcp.Ack, false)
				if tcp.DstPort == params.dns_traceroute_port {
					logging.Println(6, tcpt.id_from_port(uint16(start_port)), "FIN-ACK was ACKed, this traceroute is done")
					params.traceroute_mutex.Lock()
					params.finished = time.Now().Unix()
					tcpt.write_chan <- params
					params.traceroute_mutex.Unlock()
				}
			}
		} else
		// PSH-ACK || FIN-PSH-ACK == DNS Response
		if tcpflags.Is_PSH_ACK() || tcpflags.Is_FIN_PSH_ACK() {
			logging.Println(5, tcpt.id_from_port(uint16(start_port)), "received PSH-ACK or FIN-PSH-ACK")
			// decode as DNS Packet
			dns := &layers.DNS{}
			// remove the first two bytes of the payload, i.e. size of the dns response
			// see build_ack_with_dns()
			if len(tcp.LayerPayload()) <= 2 {
				if params.finished == -1 {
					logging.Println(3, tcpt.id_from_port(uint16(start_port)), "[*] Received PSH-ACK or FIN-PSH-ACK but no DNS response from ", net.IP(ip.NetworkFlow().Src().Raw()))
					tcpt.Send_ack_pos_fin(params.initial_ip, tcp.DstPort, tcp.Seq, tcp.Ack, true)
				}
				return
			}
			// validate payload size
			pld_size := int(tcp.LayerPayload()[0]) + int(tcp.LayerPayload()[1])<<8
			if pld_size == len(tcp.LayerPayload())-2 {
				tcpt.Send_ack_pos_fin(params.initial_ip, tcp.DstPort, tcp.Seq, tcp.Ack, true)
				return
			}
			pld := make([]byte, len(tcp.LayerPayload())-2)
			for i := 0; i < len(pld); i++ {
				pld[i] = tcp.LayerPayload()[i+2]
			}
			err := dns.DecodeFromBytes(pld, gopacket.NilDecodeFeedback)
			if err != nil {
				// ignore sending a fin-ack if we are already finished, because then we must have done that already
				if params.finished == -1 {
					logging.Println(3, tcpt.id_from_port(uint16(start_port)), "[*] Received PSH-ACK or FIN-PSH-ACK but no DNS response from", net.IP(ip.NetworkFlow().Src().Raw()))
					tcpt.Send_ack_pos_fin(params.initial_ip, tcp.DstPort, tcp.Seq, tcp.Ack, true)
				}
				return
			}
			logging.Println(5, tcpt.id_from_port(uint16(start_port)), "got DNS response")
			// we can neither use the tcp.DstPort nor the IP.Id field when receiving a valid DNS response
			// therefore we use the dns.ID field which we set in the same manner as the IP.Id and tcp.SrcPort/DstPort field
			hop := dns.ID - uint16(start_port)
			if params.initial_ip.Equal(net.IP(ip.NetworkFlow().Src().Raw())) {
				logging.Println(3, tcpt.id_from_port(uint16(start_port)), "\033[0;31m[*] \t DNSTR Hop ", hop, " ", net.IP(ip.NetworkFlow().Src().Raw()), "\033[0m")
			} else {
				logging.Println(3, tcpt.id_from_port(uint16(start_port)), "[*] \t DNSTR Hop ", hop, " ", net.IP(ip.NetworkFlow().Src().Raw()))
			}
			params.traceroute_mutex.Lock()
			params.dnstr_hops = append(params.dnstr_hops, tracert_hop{
				hop_count:   int(hop),
				ts:          time.Now().UTC(),
				response_ip: net.IP(ip.NetworkFlow().Src().Raw()),
			})
			params.traceroute_mutex.Unlock()
			logging.Println(3, tcpt.id_from_port(uint16(start_port)), "[*] Received DNS response from ", net.IP(ip.NetworkFlow().Src().Raw()))
			// check for correct port
			if tcp.DstPort != params.dns_traceroute_port {
				logging.Println(5, tcpt.id_from_port(uint16(start_port)), "wrong port of PSH-ACK or missing SYN-ACK")
				tcpt.Send_ack_pos_fin(params.initial_ip, tcp.DstPort, tcp.Seq, tcp.Ack, true)
				return
			}
			if len(params.dns_answers) != 0 {
				logging.Println(5, tcpt.id_from_port(uint16(start_port)), "already received PSH-ACK")
				tcpt.Send_ack_pos_fin(params.initial_ip, tcp.DstPort, tcp.Seq, tcp.Ack, true)
				return
			}
			answers := dns.Answers
			var answers_ip []net.IP
			for _, answer := range answers {
				if answer.IP != nil {
					answers_ip = append(answers_ip, answer.IP)
					logging.Println(3, tcpt.id_from_port(uint16(start_port)), "[*] \t DNS answer: ", answer.IP)
				} else {
					logging.Println(5, tcpt.id_from_port(uint16(start_port)), "non IP type found in answer")
					//return
				}
			}
			params.traceroute_mutex.Lock()
			params.dns_answers = answers_ip
			params.dns_reply_received = time.Now().Unix()
			params.traceroute_mutex.Unlock()
			// send FIN-ACK to server
			tcpt.Send_ack_pos_fin(params.initial_ip, tcp.DstPort, tcp.Seq, tcp.Ack, true)
			params.traceroute_mutex.Lock()
			if tcpflags.Is_FIN_PSH_ACK() {
				logging.Println(6, tcpt.id_from_port(uint16(start_port)), "was FIN-PSH-ACK, this traceroute is done")
				params.finished = time.Now().Unix()
				tcpt.write_chan <- params
			}
			params.traceroute_mutex.Unlock()
		}
	}
}

// start_port must be a multiple of 32
func (tcpt *Tcp_traceroute) send_syn(id uint32, dst_ip net.IP, ttl uint8, start_port uint16) {
	// generate sequence number based on the first 21 bits of id
	seq := (id & 0x1FFFFF) * 2048
	port := layers.TCPPort(start_port + uint16(ttl))
	logging.Println(5, tcpt.id_from_port(start_port), "sending syn to", dst_ip, "with seq_num=", seq, "ttl=", ttl)

	_, ok := tracert_params[int(start_port)]
	if !ok {
		logging.Println(1, nil, "params object not present for start_port:", start_port)
		return
	}

	// === build packet ===
	// Create ip layer
	ip := layers.IPv4{
		Version:  4,
		TTL:      ttl,
		SrcIP:    net.ParseIP(config.Cfg.Iface_ip),
		DstIP:    dst_ip,
		Protocol: layers.IPProtocolTCP,
		Id:       start_port + uint16(ttl),
	}
	//log.Println(ip.Id)
	// Create tcp layer
	tcp := layers.TCP{
		SrcPort: port,
		DstPort: 53,
		SYN:     true,
		Seq:     seq,
		Ack:     0,
	}
	tcp.SetNetworkLayerForChecksum(&ip)

	tcpt.Send_tcp_pkt_v4(ip, tcp, nil)
}

func (tcpt *Tcp_traceroute) calc_start_port(port uint16) int {
	return (int)(port - port%32)
}

func (tcpt *Tcp_traceroute) id_from_port(port uint16) int {
	return (int)(port-tcpt.lowest_port) / 32
}

func (tcpt *Tcp_traceroute) init_traceroute(start_port uint16) {
	defer tcpt.Wg.Done()
	for {
		select {
		case netip := <-tcpt.Ip_chan:
			tcpt.init_finished[tcpt.id_from_port(start_port)] = false
			tracert_mutex.Lock()
			params, exists := tracert_params[(int)(start_port)]
			if !exists {
				params = &tracert_param{}
				tracert_params[(int)(start_port)] = params
				params.finished = -1
			}
			tracert_mutex.Unlock()
			for params.initial_ip != nil && (!params.written || params.finished == -1 || time.Now().Unix()-params.finished < int64(config.Cfg.Port_reuse_timeout)) {
				logging.Println(6, tcpt.id_from_port(start_port), "waiting until port is available again,", int64(config.Cfg.Port_reuse_timeout)-time.Now().Unix()+params.finished, "s remaining")
				logging.Println(6, tcpt.id_from_port(start_port), "time now:", time.Now().Unix(), "written:", params.written, ",finished:", params.finished, ",all_syns_sent:", params.all_syns_sent, ",all_dns_sent:", params.all_dns_packets_sent, ",syn_ack_received:", params.syn_ack_received, ",dns received:", params.dns_reply_received)
				time.Sleep(5 * time.Second)
			}
			params.traceroute_mutex.Lock()
			params.zero()
			params.initial_ip = netip
			params.traceroute_mutex.Unlock()
			logging.Println(3, tcpt.id_from_port(start_port), "[*] TCP Traceroute to ", netip)
			for i := 1; i <= 30; i++ {
				_ = tcpt.Send_limiter.Take()
				if params.syn_ack_received != -1 {
					break
				}
				tcpt.send_syn(uint32(i), netip, uint8(i), start_port)
			}
			params.traceroute_mutex.Lock()
			params.all_syns_sent = time.Now().Unix()
			params.traceroute_mutex.Unlock()
			logging.Println(6, tcpt.id_from_port(start_port), "all SYNs sent")
		case <-time.After(1 * time.Second):
			params, ok := tracert_params[(int)(start_port)]
			if ok && params.written {
				if !tcpt.init_finished[tcpt.id_from_port(start_port)] {
					logging.Println(6, tcpt.id_from_port(start_port), "written & no further ips found in channel")
				}
				tcpt.init_finished[tcpt.id_from_port(start_port)] = true
			} else if !ok && tcpt.Waiting_to_end {
				if !tcpt.init_finished[tcpt.id_from_port(start_port)] {
					logging.Println(6, tcpt.id_from_port(start_port), "routine never used")
				}
				tcpt.init_finished[tcpt.id_from_port(start_port)] = true
			}
		case <-tcpt.Stop_chan:
			return
		}
	}

}

// stop measurement if we've sent out all syn packets but still got no syn ack after 3 seconds
// 1 second should be sufficient in theory, but as we may route to targets that are geographically far away we do not want to miss their responses
// we also stop if we got a SYN ACK packet but no DNS response after three seconds of sending the last DNS packet
func (tcpt *Tcp_traceroute) timeout() {
	defer tcpt.Wg.Done()
	for {
		select {
		case <-time.After(1 * time.Second):
			for start_port, params := range tracert_params {
				if params.finished != -1 {
					continue
				}
				if params.all_syns_sent != -1 {
					if params.all_dns_packets_sent == -1 {
						if params.syn_ack_received == -1 && time.Now().Unix()-params.all_syns_sent > 3 {
							logging.Println(3, tcpt.id_from_port(uint16(start_port)), "[*] No target reached.")
							params.traceroute_mutex.Lock()
							params.finished = time.Now().Unix()
							tcpt.write_chan <- params
							params.traceroute_mutex.Unlock()
						}
					} else { // all dns packets sent
						if params.dns_reply_received == -1 && time.Now().Unix()-params.all_dns_packets_sent > 6 {
							logging.Println(3, tcpt.id_from_port(uint16(start_port)), "[*] No DNS reply received.")
							params.traceroute_mutex.Lock()
							params.finished = time.Now().Unix()
							tcpt.write_chan <- params
							params.traceroute_mutex.Unlock()
						} else if params.dns_reply_received != -1 && time.Now().Unix()-params.all_dns_packets_sent > 3 {
							logging.Println(3, tcpt.id_from_port(uint16(start_port)), "didnt receive a fin-ack, writeout triggered by timeout")
							params.traceroute_mutex.Lock()
							params.finished = time.Now().Unix()
							tcpt.write_chan <- params
							params.traceroute_mutex.Unlock()
						}
					}
				}
			}
		case <-tcpt.Stop_chan:
			return
		}
	}
}

func (tcpt *Tcp_traceroute) init_is_finished() bool {
	for i := 0; i < int(config.Cfg.Number_routines); i++ {
		if !tcpt.init_finished[i] {
			return false
		}
	}
	return true
}

func (tcpt *Tcp_traceroute) read_ips_file(fname string) {
	defer tcpt.Wg.Done()
	file, err := os.Open(fname)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		select {
		case <-tcpt.Stop_chan:
			return
		default:
			line := scanner.Text()
			if line == "" {
				continue
			}
			tcpt.Ip_chan <- net.ParseIP(line)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	// wait some time to send out SYNs & handle the responses
	// of the IPs just read before ending the program
	logging.Println(3, "READ-IPS", "read all ips")
	tcpt.Waiting_to_end = true
	for !tcpt.init_is_finished() {
		logging.Println(6, "READ-IPS", "waiting to end")
		time.Sleep(2 * time.Second)
	}
	logging.Println(6, "READ-IPS", "all init routines finished")
	time.Sleep(10 * time.Second)
	logging.Println(6, "READ-IPS", "stopping")
	close(tcpt.Stop_chan)
}

func (tcpt *Tcp_traceroute) Write_results() {
	defer tcpt.Wg.Done()
	data_folder := "traceroute/traceroute_data"
	formatted_ts := time.Now().UTC().Format("2006-01-02_15-04-05")
	save_path := filepath.Join(data_folder, formatted_ts)
	err := os.MkdirAll(save_path, os.ModePerm)
	if err != nil {
		logging.Println(1, nil, "could not create output directory")
	}
	for {
		select {
		case params := <-tcpt.write_chan:
			logging.Println(3, "writeout", "writing results for", params.initial_ip.String())
			if uint16(params.dns_traceroute_port) != 0 {
				logging.Println(6, "writeout", "id="+strconv.Itoa(tcpt.id_from_port(uint16(params.dns_traceroute_port))))
			}
			filepath := filepath.Join(save_path, params.initial_ip.String()+".csv")
			csvfile, err := os.Create(filepath)
			if err != nil {
				panic(err)
			}
			defer csvfile.Close()

			// format:
			// 1st field = tag: <SYNTR|DNSTR|DNSANS>
			// SYNTR;TS;HOP;RESPIP
			// DNSTR;TS;HOP;RESPIP
			// DNSANS;ANSWERIP1,ANSWERIP2
			//writer.Write(params_to_strarr(params))
			for _, syntrhop := range params.syntr_hops {
				csvfile.WriteString(common.To_csv_line([]string{"SYNTR", syntrhop.ts.Format("2006-01-02 15:04:05.000000"), strconv.Itoa(syntrhop.hop_count), syntrhop.response_ip.String()}))
			}
			for _, dnstrhop := range params.dnstr_hops {
				csvfile.WriteString(common.To_csv_line([]string{"DNSTR", dnstrhop.ts.Format("2006-01-02 15:04:05.000000"), strconv.Itoa(dnstrhop.hop_count), dnstrhop.response_ip.String()}))
			}
			dns_slice := params.str_dns_answers()
			csvfile.WriteString(common.To_csv_line(dns_slice))
			params.traceroute_mutex.Lock()
			params.written = true
			params.traceroute_mutex.Unlock()
		case <-tcpt.Stop_chan:
			return
		}
	}
}

func (tcpt *Tcp_traceroute) Start_traceroute(args []string) {
	tcpt.Traceroute_init()
	tcpt.Base_methods = tcpt
	tcpt.Set_iptable_rule()

	cur_usr, _ := user.Current()
	logging.Println(0, nil, "Current User UID:", cur_usr.Uid)
	tcpt.init_finished = make([]bool, config.Cfg.Number_routines)
	for i := 0; i < int(config.Cfg.Number_routines); i++ {
		tcpt.init_finished[i] = false
	}

	// command line args
	if len(args) < 1 {
		logging.Println(0, "", "ERR need IPv4 target address or filename")
		os.Exit(int(common.WRONG_INPUT_ARGS))
	}
	var netip net.IP = net.ParseIP(args[0])
	if netip != nil {
		logging.Println(3, "", "single ip mode")
		tcpt.Ip_chan <- netip
		go func() {
			tcpt.Waiting_to_end = true
			time.Sleep(10 * time.Second)
			close(tcpt.Stop_chan)
		}()
	} else {
		logging.Println(3, "", "filename mode")
		filename := args[0]
		tcpt.Wg.Add(1)
		go tcpt.read_ips_file(filename)
	}

	// set the DNS_PAYLOAD_SIZE once as it is static
	_, _, dns_payload := tcpt.build_ack_with_dns(net.ParseIP("0.0.0.0"), 0, 0, 0, 0)
	tcpt.DNS_PAYLOAD_SIZE = uint16(len(dns_payload))
	handle := common.Get_ether_handle()
	// start packet capture as goroutine
	tcpt.Wg.Add(4)
	go tcpt.Packet_capture(handle)
	time.Sleep(100 * time.Millisecond)
	go tcpt.timeout()
	go tcpt.Write_results()
	var i uint16 = 0
	tcpt.highest_port = tcpt.lowest_port + 32*config.Cfg.Number_routines
	logging.Println(3, nil, "lowest port:", tcpt.lowest_port)
	logging.Println(3, nil, "highest port:", tcpt.highest_port)
	for ; i < config.Cfg.Number_routines; i++ {
		tcpt.Wg.Add(1)
		go tcpt.init_traceroute(uint16(tcpt.lowest_port) + 32*i)
	}
	go tcpt.Close_handle(handle)
	tcpt.Wg.Wait()
	logging.Println(3, "Teardown", "all routines finished")
	tcpt.Remove_iptable_rule()
	logging.Println(3, "", "program done")
}
