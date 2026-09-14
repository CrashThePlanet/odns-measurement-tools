package scanner

import (
	"bufio"
	"compress/gzip"
	"dns_tools/common"
	"dns_tools/config"
	"dns_tools/logging"
	"encoding/csv"
	"errors"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
)

type Scan_data_item interface {
	Get_timestamp() time.Time
}

type scan_item_key interface{}

// map to track tcp connections, key is a tuple of (port, seq)
type root_scan_data struct {
	Mu    sync.Mutex
	Items map[scan_item_key]Scan_data_item
}

type IScanner_Methods interface {
	Write_item(scan_item *Scan_data_item)
	Handle_pkt(ip gopacket.NetworkLayer, pkt gopacket.Packet)
}

type Base_scanner struct {
	common.Base
	Blocked_nets         []*net.IPNet
	Write_chan           chan *Scan_data_item
	Scan_data            root_scan_data
	Result_data_internal []Scan_data_item
	Scanner_methods      IScanner_Methods
}

func (bs *Base_scanner) Scanner_init() {
	bs.Scanner_init_internal()

	go bs.Handle_ctrl_c()
}

func (bs *Base_scanner) Scanner_init_internal() {
	bs.Base_init()
	bs.Blocked_nets = []*net.IPNet{}
	bs.Write_chan = make(chan *Scan_data_item, 4096)
	bs.Scan_data = root_scan_data{
		Items: make(map[scan_item_key]Scan_data_item),
	}
	bs.Result_data_internal = make([]Scan_data_item, 0)
	bs.Exclude_ips()
}

func (bs *Base_scanner) Write_results(out_path string) {
	defer bs.Wg.Done()
	csvfile, err := os.Create(out_path)
	if err != nil {
		panic(err)
	}
	defer csvfile.Close()

	zip_writer := gzip.NewWriter(csvfile)
	defer zip_writer.Close()

	bs.Writer = csv.NewWriter(zip_writer)
	bs.Writer.Comma = ';'
	defer bs.Writer.Flush()

	for {
		select {
		case scan_item := <-bs.Write_chan:
			bs.Scanner_methods.Write_item(scan_item)
		case <-bs.Stop_chan:
			return
		}
	}
}

func (bs *Base_scanner) Store_internal() {
	defer bs.Wg.Done()
	for {
		select {
		case scan_item := <-bs.Write_chan:
			bs.Result_data_internal = append(bs.Result_data_internal, *scan_item)
		case <-bs.Stop_chan:
			return
		}
	}
}

// periodically remove keys (=connections) that get no response from map
func (bs *Base_scanner) Timeout() {
	defer bs.Wg.Done()
	for {
		select {
		case <-time.After(10 * time.Second):
			//go through map's keyset
			bs.Scan_data.Mu.Lock()
			for k, v := range bs.Scan_data.Items {
				//remove each key where its timestamp is older than x seconds
				if time.Now().Unix()-v.Get_timestamp().Unix() > 10 {
					delete(bs.Scan_data.Items, k)
				}
			}
			bs.Scan_data.Mu.Unlock()
		case <-bs.Stop_chan:
			return
		}
	}
}

func (bs *Base_scanner) Exclude_ips() {
	if _, err := os.Stat(config.Cfg.Excl_ips_fname); errors.Is(err, os.ErrNotExist) {
		logging.Println(2, "Exclude", "ip exclusion list [", config.Cfg.Excl_ips_fname, "] not found, skipping")
		return
	}
	file, err := os.Open(config.Cfg.Excl_ips_fname)
	if err != nil {
		panic(err)
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if bs.Waiting_to_end {
			return
		}
		line := scanner.Text()
		if line == "" {
			continue
		}
		comment_pos := strings.IndexByte(line, '#')
		if comment_pos == -1 {
			comment_pos = len(line)
		}
		pos_net := line[:comment_pos]
		pos_net = strings.TrimSpace(pos_net)
		if pos_net == "" {
			continue
		}
		_, new_net, err := net.ParseCIDR(pos_net)
		if err != nil { // if there are errors try if the string maybe is a single ip
			toblock_ip := net.ParseIP(pos_net)
			if toblock_ip == nil {
				logging.Println(3, "Exclude", "could not interpret line, skipping")
				continue
			}
			mask := net.CIDRMask(32, 32) // 32 bits for IPv4
			new_net = &net.IPNet{IP: toblock_ip, Mask: mask}
		}

		bs.Blocked_nets = append(bs.Blocked_nets, new_net)
		logging.Println(3, "Exclude", "added blocked net:", new_net.String())
	}

	if err := scanner.Err(); err != nil {
		panic(err)
	}
}

func (bs *Base_scanner) Read_ips_file(fname string) {
	defer bs.Wg.Done()
	file, err := os.Open(fname)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if bs.Waiting_to_end {
			return
		}
		line := scanner.Text()
		if line == "" {
			continue
		}
		bs.Ip_chan <- net.ParseIP(line)
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	// wait some time to send out SYNs & handle the responses
	// of the IPs just read before ending the program
	var wait_time int = len(bs.Ip_chan)/config.Cfg.Pkts_per_sec + 10
	logging.Println(3, "Generator", "read all ips, waiting", wait_time, "seconds to end")
	bs.Waiting_to_end = true
	// time to wait until end based on packet rate + channel size
	time.Sleep(time.Duration(wait_time) * time.Second)
	close(bs.Stop_chan)
}
