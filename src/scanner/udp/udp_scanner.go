package udpscanner

import (
	"dns_tools/common"
	"dns_tools/common/udp_common"
	"dns_tools/config"
	"dns_tools/generator"
	"dns_tools/logging"
	"dns_tools/scanner"
	"encoding/base64"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	ratelimiter "go.uber.org/ratelimit"
)

type Udp_scanner struct {
	scanner.Base_scanner
	udp_common.Udp_sender
	udp_common.Udp_binder
	// slice for sockets that will be bound on program start
	Bound_sockets []*net.UDPConn
	Ip_loop_id    Synced_init
}

// lockable datastructure for the init phase
type Synced_init struct {
	Mu    sync.Mutex
	Id    uint32
	Port  uint16
	Dnsid uint16
}

func (udps *Udp_scanner) Update_sync_init() (uint32, uint16, uint16) {
	udps.Ip_loop_id.Mu.Lock()
	defer udps.Ip_loop_id.Mu.Unlock()
	udps.Ip_loop_id.Id += 1
	if (uint32)(udps.Ip_loop_id.Dnsid)+1 > 0xFFFF {
		udps.Ip_loop_id.Dnsid = 0
		// restart at the beginning of the port range
		if (uint32)(udps.Ip_loop_id.Port)+1 > (uint32)(config.Cfg.Port_max) {
			udps.Ip_loop_id.Port = config.Cfg.Port_min
		} else {
			udps.Ip_loop_id.Port += 1
		}
	} else {
		udps.Ip_loop_id.Dnsid += 1
	}
	return udps.Ip_loop_id.Id, udps.Ip_loop_id.Port, udps.Ip_loop_id.Dnsid
}

// this struct contains all relevant data to track the dns query & response
type Udp_scan_data_item struct {
	Id               uint32
	Ts_req           time.Time
	Ts_resp          time.Time
	Ip               net.IP
	Answerip         net.IP
	Port             layers.UDPPort
	Dnsid            uint16
	Dns_recs         []layers.DNSResourceRecord
	Raw_dns          []byte
	Dns_payload_size int
	Dns_flags        uint16
	Ttl              int
	Done             chan *Udp_scan_data_item
}

func (u *Udp_scan_data_item) Get_timestamp() time.Time {
	return u.Ts_req
}

func (u *Udp_scan_data_item) String() string {
	var dns_rec string = ""
	for _, rec := range u.Dns_recs {
		dns_rec += rec.String() + " "
	}
	return fmt.Sprintf("Item %d: Request-IP %s, Answer-IP %s, DNS-Recs %s", u.Id, u.Ip.String(), u.Answerip.String(), dns_rec)
}

// key for the map below
type udp_scan_item_key struct {
	port  layers.UDPPort
	dnsid uint16
}

func (udps *Udp_scanner) Write_item(scan_item *scanner.Scan_data_item) {
	udp_scan_item, ok := (*scan_item).(*Udp_scan_data_item)
	if !ok {
		return
	}
	udps.Writer.Write(scan_item_to_strarr(udp_scan_item))
}

func scan_item_to_strarr(scan_item *Udp_scan_data_item) []string {
	// csv format: id;target_ip;response_ip;arecords;timestamp_request;timestamp_response;port;dnsid;dns_pkt_size,<<record-type>-<base64-data>,...>;dnsflags;dns-ttl
	// transform scan_item into string array for csv writer
	var record []string
	record = append(record, strconv.Itoa(int(scan_item.Id)))
	record = append(record, scan_item.Ip.String())
	record = append(record, scan_item.Answerip.String())
	dns_answers := ""
	if config.Cfg.Dns_query_type == "A" {
		for i, rr := range scan_item.Dns_recs {
			if rr.Type == layers.DNSTypeA {
				dns_answers += rr.String()
				if i != len(scan_item.Dns_recs)-1 {
					dns_answers += ","
				}
			}
		}
	}
	record = append(record, dns_answers)
	record = append(record, scan_item.Ts_req.UTC().Format("2006-01-02 15:04:05.000000"))
	record = append(record, scan_item.Ts_resp.UTC().Format("2006-01-02 15:04:05.000000"))
	record = append(record, scan_item.Port.String())
	record = append(record, strconv.Itoa((int)(scan_item.Dnsid)))
	// dns packet size
	record = append(record, strconv.Itoa(scan_item.Dns_payload_size))
	dns_recs_str := ""
	if config.Cfg.Log_dnsrecs {
		for i, rr := range scan_item.Dns_recs {
			logging.Println(6, "DNS-Response", "rec:"+rr.String())
			if rr.Data == nil {
				continue
			}
			dns_recs_str += fmt.Sprintf("%s-%s", rr.Type, base64.StdEncoding.EncodeToString(rr.Data))
			if i != len(scan_item.Dns_recs)-1 {
				dns_recs_str += ","
			}
		}
	}
	record = append(record, dns_recs_str)
	record = append(record, strconv.Itoa((int)(scan_item.Dns_flags)))
	record = append(record, strconv.Itoa((int)(scan_item.Ttl)))

	return record
}

func (udps *Udp_scanner) Send_dns(id uint32, dst_ip net.IP, src_port layers.UDPPort, dnsid uint16, domain string, done chan *Udp_scan_data_item) {
	// generate sequence number based on the first 21 bits of the hash
	logging.Println(6, "Send", dst_ip, "port=", src_port, "dnsid=", dnsid)
	// check for sequence number collisions
	udps.Scan_data.Mu.Lock()
	s_d_item := Udp_scan_data_item{
		Id:       id,
		Ts_req:   time.Now(),
		Ip:       dst_ip,
		Port:     src_port,
		Dns_recs: []layers.DNSResourceRecord{},
		Dnsid:    dnsid,
		Done:     done,
	}
	logging.Println(6, "Send", "scan_data=", s_d_item)
	udps.Scan_data.Items[udp_scan_item_key{src_port, dnsid}] = &s_d_item
	udps.Scan_data.Mu.Unlock()

	l3, l4, payload := udps.Build_dns(dst_ip, src_port, dnsid, domain)

	if ipv4, ok := l3.(*layers.IPv4); ok {
		udps.Send_udp_pkt(*ipv4, l4, payload)
		return
	}
	if ipv6, ok := l3.(*layers.IPv6); ok {
		udps.Send_udp_pkt6(*ipv6, l4, payload)
	}
}

func (udps *Udp_scanner) deliver(item *Udp_scan_data_item) {
	if item.Done != nil {
		item.Done <- item
		return
	}
	var boxed scanner.Scan_data_item = item
	udps.Write_chan <- &boxed
}

func (udps *Udp_scanner) Handle_pkt(ip gopacket.NetworkLayer, pkt gopacket.Packet) {
	udp_layer := pkt.Layer(layers.LayerTypeUDP)
	if udp_layer == nil {
		return
	}
	udp, ok := udp_layer.(*layers.UDP)
	if !ok { // skip wrong packets
		return
	}
	if udp.SrcPort != layers.UDPPort(config.Cfg.Dst_port) { //skip wrong source port
		return
	}
	// pkts w/o content will be dropped
	if pkt.ApplicationLayer() != nil {
		logging.Println(5, "Handle-Pkt", "received data")
		// decode as DNS Packet
		dns := &layers.DNS{}
		pld := udp.LayerPayload()
		err := dns.DecodeFromBytes(pld, gopacket.NilDecodeFeedback)
		if err != nil {
			logging.Println(5, "Handle-Pkt", "DNS not found")
			return
		}
		logging.Println(5, "Handle-Pkt", "got DNS response from", net.IP(ip.NetworkFlow().Src().Raw()).String(), "port", udp.DstPort, "id", dns.ID)
		// check if item in map and assign value
		udps.Scan_data.Mu.Lock()
		scan_item, ok := udps.Scan_data.Items[udp_scan_item_key{udp.DstPort, dns.ID}]
		if !ok {
			udps.Scan_data.Mu.Unlock()
			return
		}
		delete(udps.Scan_data.Items, udp_scan_item_key{udp.DstPort, dns.ID})
		logging.Println(5, "Handle-Pkt", "found related scan item")
		udp_scan_item, ok := scan_item.(*Udp_scan_data_item)
		if !ok {
			log.Fatal("cast failed, wrong type")
		}
		udp_scan_item.Answerip = net.IP(ip.NetworkFlow().Dst().Raw())
		udp_scan_item.Ts_resp = time.Now()
		udp_scan_item.Raw_dns = pld
		if len(dns.Answers) != 0 {
			udp_scan_item.Dns_recs = append(udp_scan_item.Dns_recs, dns.Answers...)
			udp_scan_item.Ttl = (int)(dns.Answers[0].TTL)
		}
		udp_scan_item.Dns_flags = (uint16)(udp.LayerPayload()[2])<<8 | (uint16)(udp.LayerPayload()[3])
		udp_scan_item.Dns_payload_size = len(udp.LayerPayload())
		udps.Scan_data.Mu.Unlock()
		// queue for writeout
		udps.deliver(udp_scan_item)
	} else {
		logging.Println(6, "Handle-Pkt", "missing application data")
	}
}

func (udps *Udp_scanner) init_udp() {
	defer udps.Wg.Done()
	for {
		select {
		case dst_ip := <-udps.Ip_chan:
			// check if ip is excluded in the blocklist
			should_exclude := false
			for _, blocked_net := range udps.Blocked_nets {
				if blocked_net.Contains(dst_ip) {
					should_exclude = true
					break
				}
			}
			if should_exclude {
				logging.Println(4, nil, "excluding ip:", dst_ip)
				continue
			}
			id, src_port, dns_id := udps.Update_sync_init()
			logging.Println(5, "Send", "ip:", dst_ip, "id=", id, "port=", src_port, "dns_id=", dns_id)
			if config.Cfg.Pkts_per_sec > 0 {
				_ = udps.Send_limiter.Take()
			}
			udps.Send_dns(id, dst_ip, layers.UDPPort(src_port), dns_id, config.Cfg.Dns_query, nil)
		case <-udps.Stop_chan:
			return
		}
	}
}

func (udps *Udp_scanner) gen_ips(netip net.IP, hostsize int) bool {
	// bypass generator for ipv6 address
	if netip.To4() == nil {
		select {
		case udps.Ip_chan <- netip:
			return true
		case <-udps.Stop_chan:
			return false
		}
	}
	netip_int := generator.Ip42uint32(netip)
	var lcg_ipv4 generator.Lcg
	lcg_ipv4.Init(int(math.Pow(2, float64(hostsize))))
	for lcg_ipv4.Has_next() {
		select {
		case <-udps.Stop_chan:
			return false
		default:
			val := lcg_ipv4.Next()
			udps.Ip_chan <- generator.Uint322ip(netip_int + uint32(val))
		}
	}
	return true
}

func (udps *Udp_scanner) gen_ips_nets(nets []net.IP, hostsize int) {
	defer udps.Wg.Done()
	rand.Shuffle(len(nets), func(i, j int) { nets[i], nets[j] = nets[j], nets[i] })
	// generate ips for all the given nets
	for _, ip := range nets {
		if !udps.gen_ips(ip, hostsize) {
			return
		}
	}
	var wait_time int = len(udps.Ip_chan)/config.Cfg.Pkts_per_sec + 10
	logging.Println(3, "Generator", "all ips generated, waiting", wait_time, "seconds to end")
	udps.Waiting_to_end = true
	// time to wait until end based on packet rate + channel size
	time.Sleep(time.Duration(wait_time) * time.Second)
	close(udps.Stop_chan)
}

func (udps *Udp_scanner) gen_ips_wait(netip net.IP, hostsize int) {
	defer udps.Wg.Done()
	udps.gen_ips(netip, hostsize)
	// wait some time to send out SYNs & handle the responses
	// of the IPs just generated before ending the program
	var wait_time int = len(udps.Ip_chan)/config.Cfg.Pkts_per_sec + 10
	logging.Println(3, "Generator", "all ips generated, waiting", wait_time, "seconds to end")
	udps.Waiting_to_end = true
	// time to wait until end based on packet rate + channel size
	time.Sleep(time.Duration(wait_time) * time.Second)
	close(udps.Stop_chan)
}

func (udps *Udp_scanner) Start_scan(args []string, outpath string) {
	udps.Scanner_init()
	udps.Sender_init()
	udps.L2_sender = &udps.L2_v4
	udps.L2_sender6 = &udps.L2_v6
	udps.Scanner_methods = udps
	udps.Base_methods = udps
	udps.Bound_sockets = []*net.UDPConn{}
	// synced between multiple init_udp()
	udps.Ip_loop_id = Synced_init{
		Id:    0,
		Port:  config.Cfg.Port_min,
		Dnsid: 0,
	}

	// write start ts to log
	logging.Write_to_runlog("START " + time.Now().UTC().String())
	// command line args
	if len(os.Args) < 2 {
		logging.Write_to_runlog("END " + time.Now().UTC().String() + " arg not given")
		logging.Println(1, "Start", "ERR need filename or net in CIDR notation")
		return
	}
	var fname string
	var netip net.IP
	var hostsize int
	fname, netip, hostsize = common.Get_cidr_filename(args[0])

	udps.Bind_ports()
	// set the DNS_PAYLOAD_SIZE once as it is static
	_, _, dns_payload := udps.Build_dns(net.ParseIP("0.0.0.0"), 0, 0, config.Cfg.Dns_query)
	udps.DNS_PAYLOAD_SIZE = uint16(len(dns_payload))
	handle := common.Get_ether_handle()
	// start packet capture as goroutine
	udps.Wg.Add(5)
	go udps.Packet_capture(handle)
	go udps.Write_results(outpath)
	go udps.Timeout()
	if fname != "" {
		logging.Println(3, "Start", "running in filename mode")
		go udps.Read_ips_file(fname)
	} else {
		logging.Println(3, "Start", "running in CIDR mode")
		go udps.gen_ips_wait(netip, hostsize)
	}
	for i := 0; i < int(config.Cfg.Number_routines); i++ {
		udps.Wg.Add(1)
		go udps.init_udp()
	}
	go udps.Close_handle(handle)
	udps.Wg.Wait()
	udps.Unbind_ports()
	logging.Println(3, "Start", "all routines finished")
	logging.Write_to_runlog("END " + time.Now().UTC().String())
	logging.Println(3, "Start", "program done")
}

func (udps *Udp_scanner) Start_internal(nets []net.IP, hostsize int) []scanner.Scan_data_item {
	udps.Scanner_init_internal()
	udps.Sender_init()
	udps.L2_sender = &udps.L2_v4
	udps.L2_sender6 = &udps.L2_v6
	udps.Scanner_methods = udps
	udps.Base_methods = udps
	//udps.bound_sockets = []*net.UDPConn{}
	// synced between multiple init_udp()
	udps.Ip_loop_id = Synced_init{
		Id:    0,
		Port:  config.Cfg.Port_min,
		Dnsid: 0,
	}
	udps.Send_limiter = ratelimiter.New(config.Cfg.Pkts_per_sec)

	//udps.Bind_ports()
	// set the DNS_PAYLOAD_SIZE once as it is static
	_, _, dns_payload := udps.Build_dns(net.ParseIP("0.0.0.0"), 0, 0, config.Cfg.Dns_query)
	udps.DNS_PAYLOAD_SIZE = uint16(len(dns_payload))
	handle := common.Get_ether_handle()
	// start packet capture as goroutine
	udps.Wg.Add(6)
	go udps.Packet_capture(handle)
	go udps.Store_internal()
	go udps.Timeout()
	go udps.gen_ips_nets(nets, hostsize)
	go udps.init_udp()
	go udps.Close_handle(handle)
	udps.Wg.Wait()
	//udps.Unbind_ports()
	logging.Println(3, "Start", "internal scan done")
	return udps.Result_data_internal
}
