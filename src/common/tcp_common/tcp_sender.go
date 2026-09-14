package tcp_common

import (
	"dns_tools/common"
	"dns_tools/config"
	"dns_tools/logging"
	"net"
	"os/exec"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type Tcp_sender struct {
	L2_sender     *common.RawL2
	L2_sender6    *common.RawL2
	L3_Raw_con    *ipv4.RawConn
	L3_Raw_con6   *ipv6.PacketConn
	Set_iptables  bool
	Set_ip6tables bool
}

func (sender *Tcp_sender) Sender_init() {
	// create raw l3 socket for ipv4
	var pkt_con net.PacketConn
	pkt_con, err := net.ListenPacket("ip4:tcp", config.Cfg.Iface_ip)
	if err != nil {
		panic(err)
	}
	sender.L3_Raw_con, err = ipv4.NewRawConn(pkt_con)
	if err != nil {
		panic(err)
	}
	// create raw l3 socket for ipv6
	var pkt_con6 net.PacketConn
	pkt_con6, err = net.ListenPacket("ip6:tcp", config.Cfg.Iface_ip6)
	if err != nil {
		panic(err)
	}
	sender.L3_Raw_con6 = ipv6.NewPacketConn(pkt_con6)
}

func (sender *Tcp_sender) Send_tcp_pkt_v6(ip layers.IPv6, tcp layers.TCP, payload []byte) {
	if config.Cfg.Craft_ethernet {
		tcp_buf := gopacket.NewSerializeBuffer()
		// ip still satisfies SerializableLayer here regardless of v4/v6
		err := gopacket.SerializeLayers(tcp_buf, common.Opts, &ip, &tcp, gopacket.Payload(payload))
		if err != nil {
			panic(err)
		}
		sender.L2_sender6.Send(tcp_buf.Bytes())
		return
	}

	tcp_buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(tcp_buf, common.Opts, &tcp, gopacket.Payload(payload)); err != nil {
		panic(err)
	}
	if _, err := sender.L3_Raw_con6.WriteTo(tcp_buf.Bytes(), nil, &net.IPAddr{IP: ip.DstIP}); err != nil {
		panic(err)
	}

}

func (sender *Tcp_sender) Send_tcp_pkt_v4(ip layers.IPv4, tcp layers.TCP, payload []byte) {
	if config.Cfg.Craft_ethernet {
		tcp_buf := gopacket.NewSerializeBuffer()
		err := gopacket.SerializeLayers(tcp_buf, common.Opts, &ip, &tcp, gopacket.Payload(payload))
		if err != nil {
			panic(err)
		}

		sender.L2_sender.Send(tcp_buf.Bytes())
	} else {
		ip_head_buf := gopacket.NewSerializeBuffer()
		err := ip.SerializeTo(ip_head_buf, common.Opts)
		if err != nil {
			panic(err)
		}
		ip_head, err := ipv4.ParseHeader(ip_head_buf.Bytes())
		if err != nil {
			panic(err)
		}
		tcp_buf := gopacket.NewSerializeBuffer()
		err = gopacket.SerializeLayers(tcp_buf, common.Opts, &tcp, gopacket.Payload(payload))
		if err != nil {
			panic(err)
		}
		if err = sender.L3_Raw_con.WriteTo(ip_head, tcp_buf.Bytes(), nil); err != nil {
			panic(err)
		}
	}
}

func (sender *Tcp_sender) Send_ack_pos_fin(dst_ip net.IP, src_port layers.TCPPort, seq_num uint32, ack_num uint32, fin bool) {
	// === build packet ===
	// Create ip layer
	ip_v4 := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.ParseIP(config.Cfg.Iface_ip),
		DstIP:    dst_ip,
		Protocol: layers.IPProtocolTCP,
		Id:       1,
	}
	ip_v6 := layers.IPv6{
		Version:    6,
		HopLimit:   64,
		SrcIP:      net.ParseIP(config.Cfg.Iface_ip6),
		DstIP:      dst_ip,
		NextHeader: layers.IPProtocolTCP,
	}

	// Create tcp layer
	tcp := layers.TCP{
		SrcPort: src_port,
		DstPort: layers.TCPPort(config.Cfg.Dst_port),
		ACK:     true,
		FIN:     fin,
		Seq:     ack_num,
		Ack:     seq_num + 1,
		Window:  8192,
	}
	if dst_ip.To4() == nil {
		tcp.SetNetworkLayerForChecksum(&ip_v6)
		sender.Send_tcp_pkt_v6(ip_v6, tcp, nil)
	} else {
		tcp.SetNetworkLayerForChecksum(&ip_v4)
		sender.Send_tcp_pkt_v4(ip_v4, tcp, nil)
	}
}

func (sender *Tcp_sender) Set_iptable_rule() {
	// ensure kernel doesn't send out RSTs
	cmd := exec.Command("sudo", "iptables", "-C", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP")
	err := cmd.Run()
	if err != nil {
		cmd := exec.Command("sudo", "iptables", "-A", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP")
		err = cmd.Run()
		if err == nil {
			sender.Set_iptables = true
			logging.Println(3, "Setup", "TCP RST rule set (ipv4)")
		} else {
			logging.Println(1, "Setup", "ERR could not set iptables rule, Ensure the kernel will drop TCP RST packets in the OUTPUT chain (ipv4)")
			return
		}
	} else {
		sender.Set_iptables = false
		logging.Println(3, "Setup", "TCP RST rule already set (ipv4)")
	}
	cmd = exec.Command("sudo", "ip6tables", "-C", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP")
	err = cmd.Run()
	if err != nil {
		cmd := exec.Command("sudo", "ip6tables", "-A", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP")
		err = cmd.Run()
		if err == nil {
			sender.Set_ip6tables = true
			logging.Println(3, "Setup", "TCP RST rule set (ipv6)")
		} else {
			logging.Println(1, "Setup", "ERR could not set iptables rule, Ensure the kernel will drop TCP RST packets in the OUTPUT chain (ipv6)")
			return
		}
	} else {
		sender.Set_ip6tables = false
		logging.Println(3, "Setup", "TCP RST rule already set (ipv6)")
	}
}

func (sender *Tcp_sender) Remove_iptable_rule() {
	if sender.Set_iptables {
		cmd := exec.Command("sudo", "iptables", "-D", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP")
		err := cmd.Run()
		if err == nil {
			logging.Println(3, "Teardown", "TCP RST rule removed (ipv4)")
		} else {
			logging.Println(1, "Teardown", "ERR Failed to remove TCP RST rule (ipv4)")
		}
	} else {
		logging.Println(3, "Teardown", "TCP RST rule not set by program, so not removed (ipv4)")
	}
	if sender.Set_ip6tables {
		cmd := exec.Command("sudo", "iptables", "-D", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP")
		err := cmd.Run()
		if err == nil {
			logging.Println(3, "Teardown", "TCP RST rule removed (ipv6)")
		} else {
			logging.Println(1, "Teardown", "ERR Failed to remove TCP RST rule (ipv6)")
		}
	} else {
		logging.Println(3, "Teardown", "TCP RST rule not set by program, so not removed (ipv6)")
	}
}
