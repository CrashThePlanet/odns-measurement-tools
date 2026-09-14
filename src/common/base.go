package common

import (
	"dns_tools/config"
	"dns_tools/logging"
	"encoding/csv"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	ratelimiter "go.uber.org/ratelimit"
)

type stop struct{}

type IBase_methods interface {
	Handle_pkt(ip gopacket.NetworkLayer, pkt gopacket.Packet)
}

type RawL2 struct {
	Eth_header []byte
	Fd         int
	Addr       syscall.SockaddrLinklayer
}

func get_def_gateway() (net.IP, error) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "via" && i+1 < len(fields) {
			return net.ParseIP(fields[i+1]), nil
		}
	}
	return nil, errors.New("default gateway not found")
}

func get_def_gateway_v6() (net.IP, error) {
	out, err := exec.Command("ip", "-6", "route", "show", "default").Output()
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "via" && i+1 < len(fields) {
			return net.ParseIP(fields[i+1]), nil
		}
	}
	return nil, errors.New("default gateway not found")
}

func get_mac_addr(ip net.IP) (net.HardwareAddr, error) {
	out, err := exec.Command("ip", "neigh", "show", ip.String()).Output()
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if net.ParseIP(f).Equal(ip) && i+4 < len(fields) {
			return net.ParseMAC(fields[i+4])
		}
	}
	return nil, errors.New("MAC address not found")
}

func (l2 *RawL2) Send(payload []byte) {
	p := append(l2.Eth_header, payload...)

	//err := syscall.Sendto(l2.Fd, p, 0, &l2.Addr)
	err := syscall.Sendmsg(l2.Fd, p, []byte{}, &l2.Addr, 0)
	if err != nil {
		panic(err)
	}
}

type fragment_buffer_s struct {
	fragmap map[uint16][]gopacket.Packet
	mu      sync.Mutex
}

type Base struct {
	Wg               sync.WaitGroup
	Base_methods     IBase_methods
	Stop_chan        chan stop
	DNS_PAYLOAD_SIZE uint16
	Ip_chan          chan net.IP
	Waiting_to_end   bool
	Send_limiter     ratelimiter.Limiter
	L2_v4            RawL2 // Layer 2 for IPv4
	L2_v6            RawL2 // Layer 2 for IPv6
	Writer           *csv.Writer
	fragbuf          fragment_buffer_s
}

func (st *Base) Base_init() {
	st.Stop_chan = make(chan stop) // (〃・ω・〃)
	st.Ip_chan = make(chan net.IP, 1024)
	st.Waiting_to_end = false
	st.Send_limiter = ratelimiter.New(config.Cfg.Pkts_per_sec)
	st.fragbuf.fragmap = make(map[uint16][]gopacket.Packet)

	logging.Println(6, "Init", "iface name:", config.Cfg.Iface_name)
	iface, err := net.InterfaceByName(config.Cfg.Iface_name)
	if err != nil {
		panic(err)
	}
	srcMac := iface.HardwareAddr
	if len(srcMac) == 0 {
		panic("no src MAC")
	}
	gwIp, err := get_def_gateway()
	if err != nil {
		panic(err)
	}
	dstMac, err := get_mac_addr(gwIp)
	if err != nil {
		panic(err)
	}

	fd, _ := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(Htons(syscall.ETH_P_ALL)))
	addr := syscall.SockaddrLinklayer{
		Ifindex: iface.Index,
		Halen:   6, // Ethernet address length is 6 bytes
		Addr: [8]uint8{
			dstMac[0],
			dstMac[1],
			dstMac[2],
			dstMac[3],
			dstMac[4],
			dstMac[5],
		},
	}
	eth_header_v4 := []byte{
		dstMac[0], dstMac[1], dstMac[2], dstMac[3], dstMac[4], dstMac[5],
		srcMac[0], srcMac[1], srcMac[2], srcMac[3], srcMac[4], srcMac[5],
		0x08, 0x00, // ipv4
	}
	eth_header_v6 := []byte{
		dstMac[0], dstMac[1], dstMac[2], dstMac[3], dstMac[4], dstMac[5],
		srcMac[0], srcMac[1], srcMac[2], srcMac[3], srcMac[4], srcMac[5],
		0x86, 0xDD, // ipv6
	}

	st.L2_v4 = RawL2{
		Eth_header: eth_header_v4,
		Addr:       addr,
		Fd:         fd,
	}
	st.L2_v6 = RawL2{
		Eth_header: eth_header_v6,
		Addr:       addr,
		Fd:         fd,
	}
}

func (st *Base) Process_pkt(pkt gopacket.Packet) {
	// ipv6 fragmentation reassbemly is skipped
	if ipv6_layer := pkt.Layer(layers.LayerTypeIPv6); ipv6_layer != nil {
		st.Base_methods.Handle_pkt(ipv6_layer.(*layers.IPv6), pkt)
		return
	}
	ipv4_layer := pkt.Layer(layers.LayerTypeIPv4)
	if ipv4_layer == nil {
		return
	}
	ip, ok := ipv4_layer.(*layers.IPv4)
	if !ok {
		return
	}

	// fragmentation
	// more fragments or last fragment
	// TODO timeout and remove
	if ip.Flags&0x1 == 1 || ip.FragOffset != 0 {
		logging.Println(7, "Process-Pkt", "fragmented pkt received, size:", len(pkt.Data()), ", appl layer size:", len(pkt.LinkLayer().LayerPayload()))

		st.fragbuf.mu.Lock()
		_, ok := st.fragbuf.fragmap[ip.Id]
		if !ok {
			st.fragbuf.fragmap[ip.Id] = make([]gopacket.Packet, 0)
		}
		st.fragbuf.fragmap[ip.Id] = append(st.fragbuf.fragmap[ip.Id], pkt)

		// check all received O(n^2)
		var transp_pkt []byte = make([]byte, 0)
		var last_seen bool
		for range st.fragbuf.fragmap[ip.Id] {
			frag_seen := false
			for _, fragpkt := range st.fragbuf.fragmap[ip.Id] {
				ip_layer_frag := fragpkt.Layer(layers.LayerTypeIPv4)
				ip_frag, _ := ip_layer_frag.(*layers.IPv4)
				if ip_frag.FragOffset != 0 && ip_frag.Flags&0x1 == 0 {
					last_seen = true
				}
				if int(ip_frag.FragOffset)<<3 == len(transp_pkt) {
					logging.Println(7, "Process-Pkt", "adding Layer Payload at offset", len(transp_pkt), ", layer payload size:", len(fragpkt.ApplicationLayer().Payload()))
					transp_pkt = append(transp_pkt, ip_frag.LayerPayload()...)
					frag_seen = true
					break
				}
			}
			if !frag_seen {
				logging.Println(7, "Process-Pkt", "fragment not seen, transp_size:", len(transp_pkt))
				st.fragbuf.mu.Unlock()
				return
			}
		}
		if !last_seen {
			// bail if not all fragments yet
			st.fragbuf.mu.Unlock()
			logging.Println(7, "Process-Pkt", "not all fragments seen yet")
			return
		}
		// remove from map
		delete(st.fragbuf.fragmap, ip.Id)
		st.fragbuf.mu.Unlock()

		logging.Println(6, "Process-Pkt", "all fragments seen")
		switch ip.Protocol {
		case layers.IPProtocolUDP:
			pkt = gopacket.NewPacket(transp_pkt, layers.LayerTypeUDP, gopacket.Default)
		case layers.IPProtocolTCP:
			pkt = gopacket.NewPacket(transp_pkt, layers.LayerTypeTCP, gopacket.Default)
		default:
			return
		}
	}

	st.Base_methods.Handle_pkt(ip, pkt)
}

func (st *Base) Packet_capture(handle *pcapgo.EthernetHandle) {
	defer st.Wg.Done()
	logging.Println(3, "Capture", "starting packet capture")
	pkt_src := gopacket.NewPacketSource(
		handle, layers.LinkTypeEthernet).Packets()
	for {
		select {
		case pkt := <-pkt_src:
			go st.Process_pkt(pkt)
		case <-st.Stop_chan:
			logging.Println(3, "Capture", "stopping packet capture")
			return
		}
	}
}

// handle ctrl+c SIGINT
func (st *Base) Handle_ctrl_c() {
	interrupt_chan := make(chan os.Signal, 1)
	signal.Notify(interrupt_chan, os.Interrupt)
	<-interrupt_chan
	if st.Waiting_to_end {
		logging.Println(3, nil, "already ending")
	} else {
		st.Waiting_to_end = true
		logging.Println(3, nil, "received SIGINT, ending")
		close(st.Stop_chan)
	}
}

func (st *Base) Close_handle(handle *pcapgo.EthernetHandle) {
	defer st.Wg.Done()
	<-st.Stop_chan
	logging.Println(3, "Handle", "closing handle")
	handle.Close()
	logging.Println(3, "Handle", "handle closed")
}

func Get_cidr_filename(cidr_filename string) (fname string, netip net.IP, hostsize int) {
	ip := net.ParseIP(cidr_filename)
	if ip != nil {
		netip = ip
		hostsize = 0
		fname = ""
		return
	}
	ip, ip_net, err := net.ParseCIDR(cidr_filename)
	if ip.To4() == nil {
		panic(fmt.Sprintf("Cannot scan IPv6 subnets: %s", cidr_filename))
	}
	_, file_err := os.Stat(cidr_filename)
	if err != nil && file_err == nil {
		// using filename
		fname = cidr_filename
	} else if err == nil {
		// using CIDR net
		netip = ip
		ones, _ := ip_net.Mask.Size()
		hostsize = 32 - ones
	} else {
		logging.Write_to_runlog("END " + time.Now().UTC().String() + " wrongly formatted input arg")
		logging.Println(1, "Input", "ERR check your input arg (filename or CIDR notation)")
		os.Exit(int(WRONG_INPUT_ARGS))
	}
	return
}
