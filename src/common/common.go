package common

import (
	"dns_tools/config"
	"dns_tools/logging"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"strings"

	"github.com/f10d0/bpfutils"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/pcapgo"
)

var Opts gopacket.SerializeOptions = gopacket.SerializeOptions{
	ComputeChecksums: true,
	FixLengths:       true,
}

func To_csv_line(str_slice []string) string {
	return strings.Join(str_slice[:], ";") + "\n"
}

func Htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func Ip42int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func Int2ip4(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

func Get_ether_handle() *pcapgo.EthernetHandle {
	handle, err := pcapgo.NewEthernetHandle(config.Cfg.Iface_name)
	if err != nil {
		panic(err)
	}

	iface, err := net.InterfaceByName(config.Cfg.Iface_name)
	if err != nil {
		panic(err)
	}
	// cannot filter for src port and protocol here, since the packets could be fragmented and would be dropped by the filter
	filter_string := fmt.Sprintf("(ip dst %s) or (ip6 dst %s)", config.Cfg.Iface_ip, config.Cfg.Iface_ip6)
	logging.Println(5, "Handle", "filter string:", filter_string)
	bpf_instr, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, iface.MTU+14, filter_string)
	if err != nil {
		panic(err)
	}
	bpf_raw := bpfutils.ToBpfRawInstructions(bpf_instr)
	if err := handle.SetBPF(bpf_raw); err != nil {
		panic(err)
	}
	return handle
}

func Max(a float64, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func Std_dev(data []float64) float64 {
	n := float64(len(data))
	if n == 0 {
		return 0
	}

	// mean
	var sum float64
	for _, value := range data {
		sum += value
	}
	mean := sum / n

	// variance
	var var_sum float64
	for _, value := range data {
		var_sum += (value - mean) * (value - mean)
	}
	variance := var_sum / n

	// standard deviation
	return math.Sqrt(variance)
}
