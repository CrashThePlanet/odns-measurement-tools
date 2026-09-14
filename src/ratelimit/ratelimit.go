package ratelimit

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"dns_tools/common"
	"dns_tools/common/udp_common"
	"dns_tools/config"
	"dns_tools/generator"
	"dns_tools/logging"
	udpscanner "dns_tools/scanner/udp"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	ratelimiter "go.uber.org/ratelimit"
)

type csv_pos_struct struct {
	target_ip     int
	response_ip   int
	response_type int
}

var csv_pos csv_pos_struct = csv_pos_struct{
	target_ip:     -1,
	response_ip:   -1,
	response_type: -1,
}

type Answer_entry struct {
	ts               int64
	dns_payload_size int
}

type rate_curve_pair_s struct {
	target_tx_rate float64
	duration       int
	tx_rate        float64
	rx_rate        float64
	loss           float64
}

type rate_data_s struct {
	answer_data         []Answer_entry // us, answer timestamps, log timestamp of every incoming packet
	answer_mu           sync.Mutex
	rate_limiter        ratelimiter.Limiter // current rate limiter
	rate_curve_pair     []rate_curve_pair_s
	moving_sent_packets int
	first_response_ts   int64
}

type Resolver_entry struct {
	resolver_ip   net.IP
	tfwd_ips      []net.IP // ip pool
	tfwd_pool_pos int
	rate_pos      int // the current pos in the rate slice aka the current send rate
	outport       uint16
	rate_data     []rate_data_s
	acc_max_rate  rate_curve_pair_s
	acc_rate_data []rate_curve_pair_s
}

type Resolver_key struct {
	resolver_ip string
}

type Active_key struct {
	port uint16
}

type Rate_tester struct {
	common.Base
	udp_common.Udp_binder
	udp_common.Udp_sender
	resolver_data      map[Resolver_key]*Resolver_entry
	resolver_mu        sync.Mutex
	active_resolvers   map[Active_key]*Resolver_entry
	finished_resolvers chan *Resolver_entry
	sender_wg          sync.WaitGroup
	open_writer        sync.Mutex
	rate_curve         []int
	current_port       uint32
	resolver_counter   int
	domains            []string
	singleip           bool
}

func (entry *rate_data_s) calc_last_second_rate(target_rate float64, duration_send int, duration_timeout int) {
	now := time.Now().UnixMicro()
	//                                  tx_start+rx_timeout(2)
	//              |<--- rx_timeout-------->|                        |<--- rx_timeout-------->|
	// .............|.............|...................................|.............|..........|...............> time
	//            tx_start(1)  first_resp                           tx_end       last_resp   rx_end(~now)
	//                            |<--------- rx_time ----------------------------->|
	//              |<----------------- tx_time --------------------->|
	//              |<----------------rx_recording-------------------------------------------->|
	//
	// if first response happens between (1) and (2), then rx_start_ts should be moved
	//                            |<---------|
	//                     rx_start_ts'    rx_start_ts     rx_end_ts=rx_start_ts+duration_send
	//
	var no_rx_pkts int
	if entry.first_response_ts != -1 {
		var rx_start_ts int64 = now - int64(duration_send)*1000
		if entry.first_response_ts > now-int64(duration_send+duration_timeout)*1000 &&
			entry.first_response_ts < now-int64(duration_send)*1000 {
			rx_start_ts = entry.first_response_ts
		}
		var rx_end_ts int64 = rx_start_ts + int64(duration_send)*1000

		// count received packets
		for i := len(entry.answer_data) - 1; i >= 0; i-- {
			if entry.answer_data[i].ts < rx_start_ts {
				break
			}
			if entry.answer_data[i].ts < rx_end_ts {
				no_rx_pkts++
			}
		}
	} else {
		no_rx_pkts = 0
	}

	entry.rate_curve_pair = append(entry.rate_curve_pair, rate_curve_pair_s{
		target_tx_rate: target_rate,
		duration:       duration_send,
		rx_rate:        float64(no_rx_pkts) / float64(duration_send) * 1000,
		tx_rate:        float64(entry.moving_sent_packets) / float64(duration_send) * 1000,
		loss:           float64(entry.moving_sent_packets-no_rx_pkts) / float64(duration_send) * 1000,
	})
	logging.Println(6, "Calc-Last-Rate", "# of tx:", entry.moving_sent_packets, "| # of rx:", no_rx_pkts)
	entry.moving_sent_packets = 0
	entry.first_response_ts = -1
}

func (tester *Rate_tester) write_results(out_path string) {
	formatted_ts := time.Now().UTC().Format("2006-01-02_15-04-05")
	out_path = path.Join(out_path, fmt.Sprintf("%s_rm-%s_dm-%s_incr-%sms_wait%sms_max-rate-%spps-port%s",
		formatted_ts,
		config.Cfg.Rate_mode,
		config.Cfg.Domain_mode,
		strconv.Itoa(config.Cfg.Rate_increase_interval),
		strconv.Itoa(config.Cfg.Rate_wait_interval),
		strconv.Itoa(tester.rate_curve[len(tester.rate_curve)-1]),
		strconv.Itoa((int)(config.Cfg.Dst_port))),
	)
	// TODO output config as txt file in folder
	os.MkdirAll(out_path, os.ModePerm)
	for {
		select {
		case entry := <-tester.finished_resolvers:
			tester.open_writer.Lock()
			logging.Println(5, nil, "writing entry for resolver", entry.resolver_ip)
			var record []string
			// write timestamps
			// format: fwd-ip, ts, dns-payload-size
			os.MkdirAll(path.Join(out_path, "timestamps"), os.ModePerm)
			csvfile, err := os.Create(path.Join(out_path, "timestamps", entry.resolver_ip.String()+".csv.gz"))
			if err != nil {
				panic(err)
			}
			zip_writer := gzip.NewWriter(csvfile)
			csv_writer := csv.NewWriter(zip_writer)
			csv_writer.Comma = ';'

			for idx, data := range entry.rate_data {
				if !config.Cfg.Rate_concurrent_pool {
					idx = 0
				}
				for _, ans_entry := range data.answer_data {
					record = make([]string, 0)
					record = append(record, entry.tfwd_ips[idx].String())
					record = append(record, strconv.FormatInt(ans_entry.ts, 10))
					record = append(record, strconv.Itoa(ans_entry.dns_payload_size))
					csv_writer.Write(record)
				}
			}
			csv_writer.Flush()
			zip_writer.Close()
			csvfile.Close()

			// write rate data
			// format: target-tx-rate, tx-rate, rx-rate, loss
			csvfile, err = os.Create(path.Join(out_path, "ratelimit_record_"+entry.resolver_ip.String()+".csv"))
			if err != nil {
				panic(err)
			}
			csv_writer = csv.NewWriter(csvfile)
			csv_writer.Comma = ';'

			for _, data_pair := range entry.acc_rate_data {
				record = make([]string, 0)
				record = append(record, strconv.Itoa((int)(math.Round(data_pair.target_tx_rate))))
				record = append(record, strconv.Itoa((int)(math.Round(data_pair.tx_rate))))
				record = append(record, strconv.Itoa((int)(math.Round(data_pair.rx_rate))))
				record = append(record, strconv.Itoa((int)(math.Round(data_pair.loss))))
				csv_writer.Write(record)
			}
			csv_writer.Flush()
			csvfile.Close()

			//TODO output subroutine raw data
			tester.open_writer.Unlock()
		case <-tester.Stop_chan:
			return
		}
	}
}

func (tester *Rate_tester) print_resolver_data() {
	for _, v := range tester.resolver_data {
		var fwd_strs []string
		for _, fwd := range v.tfwd_ips {
			fwd_strs = append(fwd_strs, fwd.String())
		}
		logging.Println(5, "Resolver Data", "Resolver-IP:", v.resolver_ip, "Fwds:", fwd_strs)
	}
}

func iparr_contains(s []net.IP, e net.IP) bool {
	for _, a := range s {
		if generator.Ip42uint32(a) == generator.Ip42uint32(e) {
			return true
		}
	}
	return false
}
func intarr_contains(a []int, b int) bool {
	for _, c := range a {
		if c == b {
			return true
		}
	}
	return false
}

func (tester *Rate_tester) find_active_fwds() {
	logging.Println(3, "Probing", "Probing for active forwarders")
	var mask uint32 = 0xffffff00
	var config_backup config.Cfg_db = config.Cfg
	config.Cfg.Verbosity = 4
	config.Cfg.Pkts_per_sec = 20000

	// Find all the nets to scan
	var nets map[uint32]struct{} = make(map[uint32]struct{}, 0)
	for _, entry := range tester.resolver_data {
		for _, fwd_ip := range entry.tfwd_ips {
			var cur_net uint32 = generator.Ip42uint32(fwd_ip) & mask
			if _, ok := nets[cur_net]; !ok {
				nets[cur_net] = struct{}{}
			}
		}
		// Zero fwds from resolver_data
		entry.tfwd_ips = make([]net.IP, 0)
	}
	pass_on_nets := make([]net.IP, 0)
	for k := range nets {
		pass_on_nets = append(pass_on_nets, generator.Uint322ip(k))
		logging.Println(4, "Probing", "net:", generator.Uint322ip(k).String())
	}
	// Scan these nets with the UDP scanner
	var udp_scanner udpscanner.Udp_scanner
	var data_items = udp_scanner.Start_internal(pass_on_nets, 8)
	var udp_data_items []udpscanner.Udp_scan_data_item = make([]udpscanner.Udp_scan_data_item, 0)
	for _, item := range data_items {
		udp_item, ok := item.(*udpscanner.Udp_scan_data_item)
		if !ok {
			log.Fatal("error in converting data item to udp data item")
		}
		udp_data_items = append(udp_data_items, *udp_item)
		logging.Println(5, "Probing", udp_item.String())
	}
	config.Cfg = config_backup
	// Add detected fwds
	temp_resolver_data := tester.resolver_data
	for res_key, res_val := range temp_resolver_data {
		for _, udp_item := range udp_data_items {
			if len(udp_item.Dns_recs) == 0 || udp_item.Answerip == nil {
				continue
			}
			if generator.Ip42uint32(udp_item.Answerip) == generator.Ip42uint32(res_val.resolver_ip) {
				// check if ip already in list
				if !iparr_contains(res_val.tfwd_ips, udp_item.Ip) {
					res_val.tfwd_ips = append(res_val.tfwd_ips, udp_item.Ip)
				} else {
					logging.Println(5, nil, "ip already contained in array of resolver", res_val.resolver_ip.String(), "data item:", udp_item.String())
				}
			}
		}
		// no fwds found -> remove from map
		if len(res_val.tfwd_ips) == 0 {
			delete(tester.resolver_data, res_key)
		}
	}
	logging.Println(3, "Probing", "Probing done")
}

func (tester *Rate_tester) read_domain_list(max int) {
	logging.Println(3, nil, "reading domain list from", config.Cfg.Domain_list)
	file, err := os.Open(config.Cfg.Domain_list)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			logging.Println(6, nil, "line empty")
			continue
		}
		// split csv columns
		// domain file format: id,domain
		split := strings.Split(line, ",")
		tester.domains = append(tester.domains, split[1])
		if max != 0 && len(tester.domains)+1 > max {
			break
		}
	}
}

func (tester *Rate_tester) read_forwarders(fname string) bool {
	logging.Println(3, nil, "reading forwarders from", fname)
	file, err := os.Open(fname)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	gzip_reader, err := gzip.NewReader(file)
	if err != nil {
		log.Fatal(err)
	}
	defer gzip_reader.Close()

	scanner := bufio.NewScanner(gzip_reader)
	// read column headers
	if scanner.Scan() {
		line := scanner.Text()
		split := strings.Split(line, ";")
		for i, col := range split {
			switch col {
			case "ip_request":
				csv_pos.target_ip = i
			case "ip_response":
				csv_pos.response_ip = i
			case "response_type":
				csv_pos.response_type = i
			}
		}
		if csv_pos.response_ip == -1 || (!config.Cfg.Rate_response_ip_only && csv_pos.target_ip == -1) {
			log.Fatal("missing header of the csv file")
		}
	}
	if config.Cfg.Rate_response_ip_only {
		logging.Println(5, nil, "Rate limit testing response ip directly")
	} else {
		logging.Println(5, nil, "Rate limit testing via target ip")
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			logging.Println(6, nil, "line empty")
			continue
		}
		// split csv columns
		split := strings.Split(line, ";")
		//if split[csv_pos.response_type] != "Transparent Forwarder" {
		//	continue
		//}
		// add to resolver map
		key := Resolver_key{resolver_ip: split[csv_pos.response_ip]}
		resolver_entry, ok := tester.resolver_data[key]
		if !ok {
			tester.resolver_data[key] = &Resolver_entry{
				resolver_ip: net.ParseIP(split[csv_pos.response_ip]),
				tfwd_ips:    make([]net.IP, 0),
				rate_pos:    0,
				rate_data:   make([]rate_data_s, 1),
			}
			tester.resolver_data[key].rate_data[0].first_response_ts = -1
			resolver_entry = tester.resolver_data[key]
		}
		if config.Cfg.Rate_response_ip_only {
			if !iparr_contains(resolver_entry.tfwd_ips, net.ParseIP(split[csv_pos.response_ip])) {
				resolver_entry.tfwd_ips = append(resolver_entry.tfwd_ips, net.ParseIP(split[csv_pos.response_ip]))
			} else {
				logging.Println(6, "Reading Forwarder File", "ip already in list")
			}
		} else {
			if !iparr_contains(resolver_entry.tfwd_ips, net.ParseIP(split[csv_pos.target_ip])) {
				resolver_entry.tfwd_ips = append(resolver_entry.tfwd_ips, net.ParseIP(split[csv_pos.target_ip]))
			} else {
				logging.Println(6, "Reading Forwarder File", "ip already in list")
			}
		}
	}

	if config.Cfg.Rate_mode == "probe" {
		logging.Println(3, nil, "probe rate mode")
		tester.find_active_fwds()
		tester.print_resolver_data()
	} else if config.Cfg.Rate_mode == "direct" || config.Cfg.Rate_mode == "" {
		logging.Println(3, nil, "direct rate mode")
		tester.print_resolver_data()
	} else {
		logging.Println(1, nil, "the rate_mode", config.Cfg.Rate_mode, "does not exist")
		return false
	}

	logging.Println(6, nil, "read all lines")
	logging.Println(3, nil, "there are", len(tester.resolver_data), "resolvers")
	return true
}

func (tester *Rate_tester) rate_test_target_sub(id int, entry *Resolver_entry, subid int, wg *sync.WaitGroup, dnsid *uint16, ret_chan chan int, finished_subs int) { //TODO maybe make this dnsid random
	defer wg.Done()
	t_start := time.Now().UnixMicro()
	// send for increase_interval ms
	port := (int(entry.outport)-int(config.Cfg.Port_min)+subid)%int(config.Cfg.Port_max-config.Cfg.Port_min) + int(config.Cfg.Port_min)
	for time.Now().UnixMicro()-t_start < int64(config.Cfg.Rate_increase_interval)*1000 {
		var query_domain string
		if config.Cfg.Domain_mode == "hash" {
			hash := sha256.New()
			time_bytes := make([]byte, 8)
			binary.LittleEndian.PutUint64(time_bytes, (uint64)(time.Now().UnixMicro()))
			hash.Write(time_bytes)
			domain_prefix := hex.EncodeToString(hash.Sum(nil)[0:4])
			query_domain = domain_prefix + "." + config.Cfg.Dns_query
			logging.Println(6, "Sender "+strconv.Itoa(id)+"-"+strconv.Itoa(subid), "using query domain:", query_domain)
		} else if config.Cfg.Domain_mode == "constant" {
			query_domain = config.Cfg.Dns_query
		} else if config.Cfg.Domain_mode == "list" || config.Cfg.Domain_mode == "inject" {
			query_domain = tester.domains[rand.Intn(len(tester.domains))]
		} else {
			log.Fatal("wrong domain mode")
		}
		//TODO check if ip on blocklist
		// entry.tfwd_ips[entry.tfwd_pool_pos]
		if config.Cfg.Rate_concurrent_pool {
			logging.Println(6, "Sender "+strconv.Itoa(id)+"-"+strconv.Itoa(subid), "sending dns to", entry.tfwd_ips[subid].String(), ",resolver", entry.resolver_ip.String())
			l3, l4, payload := tester.Build_dns(entry.tfwd_ips[subid], layers.UDPPort(port), *dnsid, query_domain)
			if ipv4, ok := l3.(*layers.IPv4); ok {
				tester.Send_udp_pkt(*ipv4, l4, payload)
			}

			if ipv6, ok := l3.(*layers.IPv6); ok {
				tester.Send_udp_pkt6(*ipv6, l4, payload)
			}
		} else {
			logging.Println(6, "Sender "+strconv.Itoa(id)+"-"+strconv.Itoa(subid), "sending dns to", entry.tfwd_ips[entry.tfwd_pool_pos].String(), ",resolver", entry.resolver_ip.String())
			l3, l4, payload := tester.Build_dns(entry.tfwd_ips[entry.tfwd_pool_pos], layers.UDPPort(port), *dnsid, query_domain)
			if ipv4, ok := l3.(*layers.IPv4); ok {
				tester.Send_udp_pkt(*ipv4, l4, payload)
			}

			if ipv6, ok := l3.(*layers.IPv6); ok {
				tester.Send_udp_pkt6(*ipv6, l4, payload)
			}
			entry.tfwd_pool_pos = (entry.tfwd_pool_pos + 1) % len(entry.tfwd_ips)
		}
		entry.rate_data[subid].moving_sent_packets += 1
		(*dnsid)++
		_ = entry.rate_data[subid].rate_limiter.Take()
	}
	time.Sleep(time.Duration(config.Cfg.Rate_wait_interval) * time.Millisecond)
	entry.rate_data[subid].calc_last_second_rate(float64(tester.rate_curve[entry.rate_pos]), config.Cfg.Rate_increase_interval, config.Cfg.Rate_wait_interval)
	logging.Println(6, "Sender "+strconv.Itoa(id)+"-"+strconv.Itoa(subid), "last calculated rate is", entry.rate_data[subid].rate_curve_pair[len(entry.rate_data[subid].rate_curve_pair)-1].rx_rate)
	// set rate limiter to next value
	if entry.rate_pos == len(tester.rate_curve)-1 {
		logging.Println(6, "Sender "+strconv.Itoa(id)+"-"+strconv.Itoa(subid), "rate curve exhausted")
		ret_chan <- subid
		return
	}
	// TODO remove threshold and instead just check if increasing the tx rate gives a certain increase in rx rate
	if config.Cfg.Rate_ignore_threshold {
		ret_chan <- -1
		return
	}
	rate_divisor := 1
	if !config.Cfg.Rate_concurrent_pool {
		rate_divisor = int(config.Cfg.Rate_subroutines) - finished_subs
	}
	rate_is := entry.rate_data[subid].rate_curve_pair[len(entry.rate_data[subid].rate_curve_pair)-1].rx_rate
	rate_should := config.Cfg.Rate_receive_threshold * float64(tester.rate_curve[entry.rate_pos]/rate_divisor)
	if rate_is < rate_should {
		logging.Println(5, fmt.Sprintf("Sender %d-%d", id, subid), fmt.Sprintf("receiving rate too small (is:%.1fpps, should:%.1fpps), quitting", rate_is, rate_should))
		ret_chan <- subid
		return
	}
	ret_chan <- -1
}

func (tester *Rate_tester) rate_test_target(id int, entry *Resolver_entry) {
	var wg sync.WaitGroup
	ret_chan := make(chan int, 32)
	var length_n int
	if config.Cfg.Rate_concurrent_pool {
		length_n = len(entry.tfwd_ips)
	} else {
		length_n = int(config.Cfg.Rate_subroutines)
	}
	dnsids := make([]uint16, length_n)
	subid_pool := make([]int, 0)
	for {
		for i := 0; i < length_n; i++ {
			if intarr_contains(subid_pool, i) {
				continue
			}
			wg.Add(1)
			go tester.rate_test_target_sub(id, entry, i, &wg, &dnsids[i], ret_chan, len(subid_pool))
		}
		chan_count := 0
		for {
			subid := <-ret_chan
			logging.Println(6, "Sender "+strconv.Itoa(id), "subid", subid, "returned")
			if subid != -1 {
				if !intarr_contains(subid_pool, subid) {
					subid_pool = append(subid_pool, subid)
				}
			} else {
				chan_count += 1
			}
			if chan_count == length_n-len(subid_pool) {
				logging.Println(5, "Sender "+strconv.Itoa(id), "all subroutines finished")
				break
			}
		}

		// calculate rate data
		// TODO method
		var curve_pair rate_curve_pair_s
		curve_pair.target_tx_rate = -1
		curve_pair.duration = -1
		curve_pair.rx_rate = 0
		curve_pair.tx_rate = 0
		curve_pair.loss = 0
		for _, rate_data := range entry.rate_data {
			if len(rate_data.rate_curve_pair) <= entry.rate_pos {
				continue
			}
			sub_curve_pair := rate_data.rate_curve_pair[entry.rate_pos]
			if curve_pair.target_tx_rate == float64(-1) {
				curve_pair.target_tx_rate = sub_curve_pair.target_tx_rate
				curve_pair.duration = sub_curve_pair.duration
			}
			curve_pair.rx_rate += sub_curve_pair.rx_rate
			curve_pair.tx_rate += sub_curve_pair.tx_rate
			curve_pair.loss += sub_curve_pair.loss
		}
		if entry.acc_max_rate.rx_rate < curve_pair.rx_rate {
			entry.acc_max_rate = curve_pair
		}
		entry.acc_rate_data = append(entry.acc_rate_data, curve_pair)
		logging.Println(4, "Sender "+strconv.Itoa(id), "current rx-rate:", math.Round(curve_pair.rx_rate), "Pkts/s")

		if len(subid_pool) == length_n {
			break
		}
		entry.rate_pos++
		logging.Println(4, "Sender "+strconv.Itoa(id), "rate up", tester.rate_curve[entry.rate_pos], "Pkts/s")
		rlimiter := ratelimiter.New(tester.rate_curve[entry.rate_pos])
		for i := 0; i < len(entry.rate_data); i++ {
			if config.Cfg.Rate_concurrent_pool {
				entry.rate_data[i].rate_limiter = ratelimiter.New(tester.rate_curve[entry.rate_pos])
			} else {
				entry.rate_data[i].rate_limiter = rlimiter
			}
		}
	}
	// calculate tx/rx rates
	for _, curve_pair := range entry.acc_rate_data {
		logging.Println(3, "Sender "+strconv.Itoa(id),
			"\n    === Resolver", entry.resolver_ip, "[accumulated]",
			"\n    target-tx-rate:", math.Round(curve_pair.target_tx_rate),
			"Pkts/s\n    tx-rate:", math.Round(curve_pair.tx_rate),
			"Pkts/s\n    rx-rate:", math.Round(curve_pair.rx_rate),
			"Pkts/s\n    loss (tx-rx):", math.Round(curve_pair.loss), "Pkts/s", "rel:", math.Round(curve_pair.loss/curve_pair.tx_rate*100), "%")
	}
	logging.Println(3, "Sender "+strconv.Itoa(id),
		"\n    === Resolver", entry.resolver_ip, "[overall]",
		"Pkts/s\n    tx-rate @max-rx-rate:", math.Round(entry.acc_max_rate.tx_rate),
		"Pkts/s\n    max-rx-rate:", math.Round(entry.acc_max_rate.rx_rate),
		"Pkts/s\n    loss (tx-rx) @max-rx-rate:", math.Round(entry.acc_max_rate.loss), "Pkts/s", "rel:", math.Round(entry.acc_max_rate.loss/entry.acc_max_rate.tx_rate*100), "%")
	// TODO test stability at max rate, add config variable
}

func (tester *Rate_tester) send_packets(id int) {
	defer tester.sender_wg.Done()
	for {
		tester.resolver_mu.Lock()
		if len(tester.resolver_data) == 0 {
			tester.resolver_mu.Unlock()
			logging.Println(4, "Sender "+strconv.Itoa(id), "list exhausted, returning")
			return
		}
		// retrieve the next resolver from the map
		var key Resolver_key
		for key = range tester.resolver_data { // pseudo-random key, TODO how random is this?
			break
		}
		entry := tester.resolver_data[key]
		delete(tester.resolver_data, key)
		outport := tester.current_port
		entry.outport = (uint16)(outport)
		//TODO send mode: one tfwd ip after another, break in between
		if config.Cfg.Rate_concurrent_pool {
			tester.current_port += uint32(len(entry.tfwd_ips))
		} else {
			tester.current_port++
		}
		if tester.current_port > uint32(config.Cfg.Port_max) {
			tester.current_port -= uint32(config.Cfg.Port_max-config.Cfg.Port_min) + 1
		}
		if config.Cfg.Rate_concurrent_pool {
			entry.rate_data = make([]rate_data_s, len(entry.tfwd_ips))
			for i := 0; i < len(entry.tfwd_ips); i++ {
				entry.rate_data[i].rate_limiter = ratelimiter.New(tester.rate_curve[0])
				entry.rate_data[i].first_response_ts = -1
				act_key := Active_key{port: uint16(int(outport) + i)}
				tester.active_resolvers[act_key] = entry
			}
		} else {
			entry.rate_data = make([]rate_data_s, int(config.Cfg.Rate_subroutines))
			rlimiter := ratelimiter.New(tester.rate_curve[0])
			for i := 0; i < int(config.Cfg.Rate_subroutines); i++ {
				entry.rate_data[i].rate_limiter = rlimiter
				entry.rate_data[i].first_response_ts = -1
				act_key := Active_key{port: uint16(int(outport) + i)}
				tester.active_resolvers[act_key] = entry
			}
		}
		tester.resolver_counter++
		tester.resolver_mu.Unlock()
		logging.Println(4, "Sender "+strconv.Itoa(id), "rate limit testing resolver", tester.resolver_counter, entry.resolver_ip, "on port", outport)
		// === start the rate limit testing to that target ===
		tester.rate_test_target(id, entry)
		tester.finished_resolvers <- entry
		tester.resolver_mu.Lock()
		if config.Cfg.Rate_concurrent_pool {
			for i := 0; i < len(entry.tfwd_ips); i++ {
				act_key := Active_key{port: uint16(int(outport) + i)}
				delete(tester.active_resolvers, act_key)
			}
		} else {
			act_key := Active_key{port: uint16(outport)}
			delete(tester.active_resolvers, act_key)
		}
		tester.resolver_mu.Unlock()
		time.Sleep(50 * time.Millisecond)
	}
}

func (tester *Rate_tester) Handle_pkt(ip gopacket.NetworkLayer, pkt gopacket.Packet) {
	rec_time := time.Now().UnixMicro()

	udp_layer := pkt.Layer(layers.LayerTypeUDP)
	if udp_layer == nil {
		logging.Println(6, "Handle-Pkt", "wrong udp layer")
		return
	}
	udp, ok := udp_layer.(*layers.UDP)
	if !ok { // skip wrong packets
		logging.Println(6, "Handle-Pkt", "wrong udp")
		return
	}

	logging.Println(6, "Handle-Pkt", "received data")
	// decode as DNS Packet
	dns := &layers.DNS{}
	pld := udp.LayerPayload()
	err := dns.DecodeFromBytes(pld, gopacket.NilDecodeFeedback)
	if err != nil {
		logging.Println(5, "Handle-Pkt", "error decoding DNS:", err)
		return
	}
	//logging.Println(6, nil, "got DNS response", count)
	if dns.ResponseCode == layers.DNSResponseCodeNotImp {
		logging.Println(5, "Handle-Pkt", "DNS response code: not implemented")
		return
	}
	if len(dns.Answers) == 0 {
		//ignore empty replies
		logging.Println(5, "Handle-Pkt", "DNS empty answers")
		return
	}
	if len(dns.Answers) == 1 {
		if dns.Answers[0].Type == layers.DNSTypeHINFO {
			logging.Println(6, "Handle-Pkt", "DNS reply is HINFO")
			return
		}
	}
	// check if item in map and assign value
	tester.resolver_mu.Lock()
	rate_entry, ok := tester.active_resolvers[Active_key{port: uint16(udp.DstPort)}]
	if !ok {
		tester.resolver_mu.Unlock()
		logging.Println(5, "Handle-Pkt", "got DNS but cant find related resolver")
		return
	}
	subid := uint16(udp.DstPort) - rate_entry.outport
	tester.resolver_mu.Unlock()
	rate_entry.rate_data[subid].answer_mu.Lock()
	ans_entry := Answer_entry{
		ts:               rec_time,
		dns_payload_size: len(pld),
	}
	rate_entry.rate_data[subid].answer_data = append(rate_entry.rate_data[subid].answer_data, ans_entry)
	if rate_entry.rate_data[subid].first_response_ts == -1 {
		rate_entry.rate_data[subid].first_response_ts = rec_time
	}
	rate_entry.rate_data[subid].answer_mu.Unlock()
}

func (tester *Rate_tester) inject_cache() {
	logging.Println(3, "cache injection", "starting")
	var resolver_data map[Resolver_key]*Resolver_entry = make(map[Resolver_key]*Resolver_entry)
	for k, v := range tester.resolver_data {
		resolver_data[k] = v
	}
	// summon go routines
	for i := 0; i < int(config.Cfg.Rate_inject_routines); i++ {
		tester.sender_wg.Add(1)
		// iterate all resolvers
		go func(id int) {
			defer tester.sender_wg.Done()
			var dnsid uint16 = 0
			var rate_limiter ratelimiter.Limiter = ratelimiter.New(tester.rate_curve[0])
			outport := tester.current_port
			for { // iterate resolvers
				tester.resolver_mu.Lock()
				if len(resolver_data) == 0 {
					tester.resolver_mu.Unlock()
					logging.Println(5, "Cache-Injector "+strconv.Itoa(id), "list exhausted, returning")
					return
				}
				var key Resolver_key
				for key = range resolver_data {
					break
				}
				entry := (resolver_data)[key] // next resolver
				delete(resolver_data, key)
				tester.resolver_mu.Unlock()
				logging.Println(5, "Cache-Injector "+strconv.Itoa(id), "resolver", entry.resolver_ip.String())
				for idx, tfwd := range entry.tfwd_ips { // iterate over all twfds of this resolver
					if idx > config.Cfg.Rate_inject_max_fwds {
						break
					}
					logging.Println(5, "Cache-Injector "+strconv.Itoa(id), "injecting fwd", tfwd.String(), "to resolver", entry.resolver_ip.String())
					for _, query_domain := range tester.domains {
						// per resolver iterate all 1k domains
						logging.Println(6, "Cache-Injector "+strconv.Itoa(id), "sending dns to", tfwd, ",resolver", entry.resolver_ip.String())

						l3, l4, payload := tester.Build_dns(tfwd, layers.UDPPort(outport), dnsid, query_domain)
						if ipv4, ok := l3.(*layers.IPv4); ok {
							tester.Send_udp_pkt(*ipv4, l4, payload)
						}

						if ipv6, ok := l3.(*layers.IPv6); ok {
							tester.Send_udp_pkt6(*ipv6, l4, payload)
						}
						dnsid++
						_ = rate_limiter.Take()
					}
				}
			}
		}(i)
	}
	tester.sender_wg.Wait()
	logging.Println(3, "cache injection", "done")
}

func (tester *Rate_tester) Start_ratetest(args []string, outpath string) {
	tester.resolver_data = make(map[Resolver_key]*Resolver_entry)
	tester.active_resolvers = make(map[Active_key]*Resolver_entry)
	// load rate curve from config
	// the rate will increase over time up to a maximum value
	var rate_values []string = strings.Split(config.Cfg.Rate_curve, ",")
	tester.rate_curve = make([]int, 0)
	for _, rate_value := range rate_values {
		rate_val_int, err := strconv.Atoi(strings.Trim(rate_value, " "))
		if err != nil {
			logging.Println(1, nil, "cannot convert value in rate curve to int")
			return
		}
		tester.rate_curve = append(tester.rate_curve, rate_val_int)
	}
	logging.Println(4, nil, "rate curve:", tester.rate_curve)
	tester.current_port = uint32(config.Cfg.Port_min)
	tester.L2_sender = &tester.L2_v4
	tester.Base_methods = tester
	tester.finished_resolvers = make(chan *Resolver_entry, 128)
	tester.Sender_init()
	tester.Base_init()
	tester.Bind_ports()

	if len(args) < 1 {
		logging.Println(1, nil, "missing intersect input file or ip")
		return
	}
	fname, netip, hostsize := common.Get_cidr_filename(args[0])
	if hostsize != 0 {
		logging.Println(1, nil, "cannot test entire net")
	}

	logging.Write_to_runlog("START " + time.Now().UTC().String())

	if fname != "" {
		if !tester.read_forwarders(fname) {
			logging.Println(3, nil, "exiting with error")
			return
		}
		tester.singleip = false
	} else {
		key := Resolver_key{resolver_ip: netip.String()}
		resolver_entry, ok := tester.resolver_data[key]
		if !ok {
			tester.resolver_data[key] = &Resolver_entry{
				resolver_ip: netip,
				tfwd_ips:    make([]net.IP, 0),
				rate_pos:    0,
				rate_data:   make([]rate_data_s, 1),
			}
			resolver_entry = tester.resolver_data[key]
		}
		resolver_entry.tfwd_ips = append(resolver_entry.tfwd_ips, netip)
		tester.singleip = true
	}

	if config.Cfg.Domain_mode == "list" {
		logging.Println(3, nil, "using domain list")
		tester.read_domain_list(0)
	} else if config.Cfg.Domain_mode == "inject" {
		logging.Println(3, nil, "using domain list, inject mode")
		tester.read_domain_list(config.Cfg.Rate_inject_count)
		tester.inject_cache()
	}

	// packet capture will call Handle_pkt
	handle := common.Get_ether_handle()
	tester.Wg.Add(1)
	go tester.Packet_capture(handle)

	// path to an output directory, each resolver will be written to its own file
	go tester.write_results(outpath)
	// start ratelimit senders
	for i := 0; i < int(config.Cfg.Number_routines); i++ {
		tester.sender_wg.Add(1)
		go tester.send_packets(i)
	}
	tester.sender_wg.Wait()
	logging.Println(3, nil, "Sending completed")

	tester.open_writer.Lock()
	close(tester.Stop_chan)
	handle.Close()

	tester.Wg.Wait()
	tester.Unbind_ports()
	logging.Println(3, nil, "all routines finished")
	logging.Write_to_runlog("END " + time.Now().UTC().String())
	logging.Println(3, nil, "program done")
}
