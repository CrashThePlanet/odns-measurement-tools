package qmin_scanner

import (
	"bufio"
	"dns_tools/common"
	"dns_tools/config"
	tcpscanner "dns_tools/scanner/tcp"
	udpscanner "dns_tools/scanner/udp"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/gopacket/gopacket/layers"
	"github.com/parquet-go/parquet-go"
)

var baseDomain string
var randMax int

// we want the resolver inside the target domain (for identification and to further avoid collisions). For IPv4 and IPv6 we can simply encode to hex, as both have a fixed length.
// But DoH DOmain are full domains and have an arbitrary length. If we encode to Hex to Base64 we run into the max character limit of domains name pretty fast.
// Therefore we create a custom Hashfunction with hashmap and store said hashmap into a file anlongside the result
var dohResolverHashMap map[string]string

type ScanStat struct {
	Start        time.Time
	Fin          time.Time
	Runtime      string
	Input        string
	NumResolver  int
	Timeout      int
	RetryTimeout int
	Protocol     string
	LabelDepth   int
	Rounds       int
	BaseURL      string
}

type QueryResult struct {
	resolverIP         string
	status             int // -1: undefined error,  0: no error, 1: refused, 2: Servfail, 3: timeout, 4: NXDomain, 5: No Route to host, 6: no recursion available, 7: no answer from resolver, 8: answer contains no TXT response
	Res                string
	requestingIP       string // ip of the Server that actually sent the request to the Server, see "Forwarder"
	induction          bool
	inductionPattern   string
	inductionRequester string
	qmin_mode          bool
	nxopti             int
	nxcheck            bool
	ResolverType       string
	FileName           string
}

type ParquetQueryResult struct {
	ResolverIP       string `parquet:"resolver_ip,zstd"`
	ResolverType     string `parquet:"resolver_type,dict,zstd"`
	RequestingIP     string `parquet:"requesting_ip,zstd"`
	Response         string `parquet:"response,zstd"`
	InductionIP      string `parquet:"ind_requesting_ip,zstd"`
	InducedRes       string `parquet:"induced_res,zstd"`
	InducedQMINCheck bool   `parquet:"induced_qmin_check"`
	ModeCheck        bool   `parquet:"qmin_mode_check"`
	NXCheck          bool   `parquet:"nx_check"`
	NxOptimization   int    `parquet:"nxOptimization"`
	FileName         string `parquet:"filename,dict,zstd"`
}

type QMinScanner struct {
	baseDomain   string
	randMax      int
	tokenDepth   int
	batchSize    int
	rounds       int
	timeout      time.Duration
	retryTimeout time.Duration
}

type InputFileFormat struct {
	// protocol                 string
	Queried_ip string `parquet:"queried_ip"`
	//replying_ip              string
	//backend_resolver         string
	//timestamp_request        string
	Resolver_type string `parquet:"resolver_type"`
	//queried_ip_country       string
	//replying_ip_country      string
	//queried_ip_asn           int64
	//replying_ip_asn          int64
	//queried_ip_prefix        string
	//replying_ip_prefix       string
	//queried_ip_org           string
	//replying_ip_org          string
	//backend_resolver_country string
	//backend_resolver_asn     int64
	//backend_resolver_prefix  string
	//backend_resolver_org     string
	//scan_date                string
	//queried_ip_uint32        uint32
	//replying_ip_uint32       uint32
	// backend_resolver_uint32  uint32
}

type TcpScanner struct {
	tcps tcpscanner.Tcp_scanner
}

func (s *TcpScanner) Setup() *TcpScanner {
	tcps := &s.tcps

	config.Cfg.Pkts_per_sec = 10
	config.Cfg.Iface_name = "enp7s0"
	config.Cfg.Iface_ip = "192.168.188.85"
	config.Cfg.Iface_ip6 = "2a00:fda0:2bf:1000:79dc:dc36:f753:9c93"
	config.Cfg.Dst_port = 53
	config.Cfg.Dnssec_enabled = false
	config.Cfg.Log_dnsrecs = false
	config.Cfg.EDNS0_enabled = true
	tcps.Scanner_init()
	tcps.Sender_init()
	tcps.L2_sender = &tcps.L2_v4
	tcps.L2_sender6 = &tcps.L2_v6
	tcps.Scanner_methods = tcps
	tcps.Base_methods = tcps
	tcps.Set_iptable_rule()

	handle := common.Get_ether_handle()

	tcps.Wg.Add(3)

	go tcps.Packet_capture(handle)
	go tcps.Timeout()
	go tcps.Close_handle(handle)

	return s
}

func (s *TcpScanner) Teardown() {

	close(s.tcps.Stop_chan)
	s.tcps.Wg.Wait()
	s.tcps.Remove_iptable_rule()
}

func (s *TcpScanner) Resolve(domain string, target net.IP, qType uint16, timeout time.Duration) (*dns.Msg, error) {
	// need to remove root-zone indicator dot (".") as the dns payload will be packed wrongly with it present
	domain = strings.TrimSuffix(domain, ".")
	_, _, dns_payload := s.tcps.Build_ack_with_dns(net.ParseIP("0.0.0.0"), 0, 0, 0, domain, dns.TypeToString[qType])
	s.tcps.DNS_PAYLOAD_SIZE = uint16(len(dns_payload))

	id := s.tcps.Get_next_id()
	if config.Cfg.Pkts_per_sec > 0 {
		_ = s.tcps.Send_limiter.Take()
	}

	s.tcps.Send_syn(id, target, domain, dns.TypeToString[qType])

	select {
	case item := <-s.tcps.Write_chan:
		if scan_item, ok := (*item).(*tcpscanner.Tcp_scan_data_item); ok {
			msg := new(dns.Msg)
			msg.Data = scan_item.Next.Next.Raw_dns
			err := msg.Unpack()
			return msg, err
		}
	case <-time.After(timeout):
		return nil, fmt.Errorf("timout")
	}
	panic("Houston, we have a problem. This should be impossible. \n No but really you should not me able to reach this point.")
}

type UdpScanner struct {
	udps udpscanner.Udp_scanner
}

func (s *UdpScanner) Setup() *UdpScanner {

	udps := &s.udps
	config.Cfg.Pkts_per_sec = 10
	config.Cfg.Iface_name = "enp7s0"
	config.Cfg.Iface_ip = "192.168.188.85"
	config.Cfg.Iface_ip6 = "2a00:fda0:2bf:1000:79dc:dc36:f753:9c93"
	config.Cfg.Dst_port = 53
	config.Cfg.Dnssec_enabled = false
	config.Cfg.Log_dnsrecs = false
	config.Cfg.EDNS0_enabled = true
	config.Cfg.Port_min = 61440
	config.Cfg.Port_max = 65535
	config.Cfg.EDNS0_buffer_size = 4096
	config.Cfg.Dns_query_type = "TXT"

	udps.Scanner_init_internal()
	udps.Sender_init()
	udps.L2_sender = &udps.L2_v4
	udps.L2_sender6 = &udps.L2_v6
	udps.Scanner_methods = udps
	udps.Base_methods = udps
	udps.Bound_sockets = []*net.UDPConn{}
	// synced between multiple init_udp()
	udps.Ip_loop_id = udpscanner.Synced_init{
		Id:    0,
		Port:  config.Cfg.Port_min,
		Dnsid: 0,
	}

	handle := common.Get_ether_handle()
	udps.Wg.Add(3)

	go udps.Packet_capture(handle)
	go udps.Timeout()
	go udps.Close_handle(handle)

	return s
}

func (s *UdpScanner) Resolve(domain string, target net.IP, qType uint16, timeout time.Duration) (*dns.Msg, error) {
	domain = strings.TrimSuffix(domain, ".")
	id, src_port, dns_id := s.udps.Update_sync_init()
	// fmt.Println(5, "Send", "ip:", net.ParseIP(server), "id=", id, "port=", src_port, "dns_id=", dns_id)

	if config.Cfg.Pkts_per_sec > 0 {
		_ = s.udps.Send_limiter.Take()
	}
	s.udps.Send_dns(id, target, layers.UDPPort(src_port), dns_id, domain)

	select {
	case item := <-s.udps.Write_chan:
		if i, ok := (*item).(*udpscanner.Udp_scan_data_item); ok {
			msg := new(dns.Msg)
			msg.Data = i.Raw_dns
			err := msg.Unpack()
			return msg, err
		}
	case <-time.After(timeout):
		return nil, fmt.Errorf("timeout") // no reply in time
	}
	panic("Houston, we have a problem. This should be impossible. \n No but really you should not me able to reach this point.")

}

func (s *UdpScanner) Teardown() {
	close(s.udps.Stop_chan)
	s.udps.Wg.Wait()
}

var responsePattern = `^(?:[0-9]+(?:\.[0-9]+)*_[A-Za-z0-9]+\|)*[0-9]+(?:\.[0-9]+)*\.[0-9A-Fa-f]{8}-[0-9]+-[^-|_]+(?:-(?:inducation|qmin_mode|nxopti))?_[A-Za-z0-9]+$`
var reg = regexp.MustCompile(responsePattern)

func targetToHex(target string) string {
	parsedIp, err := netip.ParseAddr(target)
	if err != nil {
		if Cfg.Protocol != "doh" {
			log.Fatalln("Looks like you tried to used an IP but the scanner is configured for DoH scanning.")
		}
		return fmt.Sprintf("%X", crc32.ChecksumIEEE([]byte(target)))
	}

	if parsedIp.Is4() {
		return fmt.Sprintf("%x", parsedIp.As4())
	}
	return fmt.Sprintf("%X", crc32.ChecksumIEEE([]byte(target)))
}

func domainAssembly(dnsServer string, tokenDepth int, induction bool, qmin_mode bool, nxopti bool) string {
	if induction && qmin_mode {
		log.Fatalln("Only test for induced queries OR NX behaviour in one query!")
	}

	var idToken = targetToHex(dnsServer)

	idToken += "-" + strconv.Itoa(tokenDepth) + "-"
	idToken += strconv.Itoa(rand.Intn(randMax))

	var domain = ""

	for i := tokenDepth - 1; i > 0; i-- {
		domain += strconv.Itoa(i) + "."
	}
	domain += idToken

	if induction {
		domain += "-induction"
	}
	if qmin_mode {
		domain += "-qminMode"
	}
	if nxopti {
		domain += "-nxopti"
	}
	return domain + "." + baseDomain
}

func evalCommError(err error, server string) QueryResult {
	if strings.Contains(err.Error(), "i/o timeout") {
		return QueryResult{resolverIP: server, requestingIP: "NONE", status: 3, Res: "timeout"}
	}
	if strings.Contains(err.Error(), "connection refused") {
		return QueryResult{resolverIP: server, requestingIP: "NONE", status: 1, Res: "refused"}
	}
	if strings.Contains(err.Error(), "no route to host") {
		return QueryResult{resolverIP: server, requestingIP: "NONE", status: 5, Res: "noRoute"}
	}
	fmt.Println(server, ": unhandled error: ", err)
	return QueryResult{resolverIP: server, requestingIP: "NONE", status: -1, Res: "unhandledError"}
}

func dnsQuery(domain string, server string, qType uint16, timeout time.Duration) QueryResult {

	var res *dns.Msg
	var err error

	switch Cfg.Protocol {
	case "udp":
		udpscan := &UdpScanner{}
		udpscan.Setup()

		res, err := udpscan.Resolve(domain, net.ParseIP(server), qType, timeout)
		fmt.Println(res)
		fmt.Println(err)

		udpscan.Teardown()
		panic("stop")

	case "tcp":
		tcpscan := &TcpScanner{}
		tcpscan.Setup()

		res, err := tcpscan.Resolve(domain, net.ParseIP(server), qType, timeout)
		fmt.Println(res)
		fmt.Println(err)

		tcpscan.Teardown()
		panic("stop")

	case "doh":
		/*
			if !strings.HasPrefix(server, "https://") && !strings.HasPrefix(server, "http://") {
				server = "https://" + server
			}
			var req *http.Request
			req, err = dnshttp.NewRequest(http.MethodPost, server, m)
			if err != nil {
				log.Fatalln("Request build error:", err)
			}
			var resp *http.Response
			resp, err = http.DefaultClient.Do(req)
			if err != nil {
				return evalCommError(err, server)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return QueryResult{resolverIP: server, requestingIP: "NONE", status: 9, Res: "http status: " + strconv.Itoa(resp.StatusCode)}
			}

			res, err = dnshttp.Response(resp)
			if err != nil {
				fmt.Println("Failed to parse HTTP response:", err)
				return QueryResult{resolverIP: server, requestingIP: "NONE", status: -1, Res: "unhandledError"}
			}
		*/
	default:
		log.Fatalln("Wrong or unsupported protocol:", Cfg.Protocol)
	}

	if err != nil {
		return evalCommError(err, server)
	}
	if res.Rcode != dns.RcodeSuccess {
		switch res.Rcode {
		case dns.RcodeServerFailure:
			return QueryResult{resolverIP: server, requestingIP: "NONE", status: 2, Res: "servfail"}
		case dns.RcodeNameError:
			return QueryResult{resolverIP: server, requestingIP: "NONE", status: 4, Res: "nxdomain"}
		case dns.RcodeRefused:
			return QueryResult{resolverIP: server, requestingIP: "NONE", status: 1, Res: "refused"}
		default:
			fmt.Println(server, ": unhandled error: rcode:", res.Rcode)
			return QueryResult{resolverIP: server, requestingIP: "NONE", status: -1, Res: "unhandledError"}
		}
	}
	if len(res.Answer) == 0 {
		if !res.RecursionAvailable {
			return QueryResult{resolverIP: server, requestingIP: "NONE", status: 6, Res: "noRecursion"}
		}
		return QueryResult{resolverIP: server, requestingIP: "NONE", status: 7, Res: "noAnswer"}
	}
	for _, a := range res.Answer {
		if t, ok := a.(*dns.TXT); ok {
			if !strings.Contains(t.Txt[0], ",") {
				return QueryResult{resolverIP: server, requestingIP: "NONE", status: -1, Res: "unhandledError"}
			}
			split := strings.Split(t.Txt[0], ",")
			if t.Txt[0] == "false,,," {
				return QueryResult{resolverIP: server, requestingIP: "NONE", status: 0, Res: split[0], inductionRequester: "", inductionPattern: ""}
			}
			if len(split) > 3 {
				return QueryResult{resolverIP: server, requestingIP: split[0], status: 0, Res: split[1], inductionRequester: split[2], inductionPattern: split[3]}
			} else {
				fmt.Println(server, ": unhandled response error: ", t.Txt[0])
				return QueryResult{resolverIP: server, requestingIP: "NONE", status: -1, Res: "unhandledError"}
			}
		}
	}
	return QueryResult{resolverIP: server, requestingIP: "NONE", status: 9, Res: "noTXTResponse"}
}

func dnsQueryRoutine(tokenDepth int, resolver InputFileFormat, timeout time.Duration, retryTimeout time.Duration, qType uint16, ch chan<- QueryResult, wg *sync.WaitGroup, induction bool, qmin_mode bool) {
	server := resolver.Queried_ip
	defer wg.Done()
	requestedDomain := domainAssembly(server, tokenDepth, induction, qmin_mode, false)
	res := dnsQuery(requestedDomain, server, qType, timeout)
	// if timeout retry wiht longer timeout
	if res.status == 3 {
		requestedDomain = domainAssembly(server, tokenDepth, induction, qmin_mode, false)
		res = dnsQuery(requestedDomain, server, qType, retryTimeout)
	}
	res.ResolverType = resolver.Resolver_type
	res.qmin_mode = qmin_mode
	res.induction = induction
	res.nxcheck = false
	res.nxopti = -1
	ch <- res
}

func nxOptiRoutine(resolver InputFileFormat, timeout time.Duration, retryTimeout time.Duration, qType uint16, ch chan<- QueryResult, wg *sync.WaitGroup) {
	defer wg.Done()
	server := resolver.Queried_ip

	domain := domainAssembly(server, 1, false, false, true)
	d1 := "a." + domain
	d2 := "b." + domain

	res := dnsQuery(d1, server, qType, timeout)

	if res.status == 3 {
		res = dnsQuery(d1, server, qType, retryTimeout)
	}
	res.qmin_mode = false
	res.induction = false
	res.nxcheck = true
	res.ResolverType = resolver.Resolver_type
	if res.status != 4 {
		res.nxopti = -1
		ch <- res
		return
	}

	res2 := dnsQuery(d2, server, qType, timeout)
	if res2.status == 3 {
		res2 = dnsQuery(d2, server, qType, retryTimeout)
	}
	res2.qmin_mode = false
	res2.induction = false
	res2.nxcheck = true
	res2.ResolverType = resolver.Resolver_type
	if res2.status != 4 && res2.status != 0 {
		res.nxopti = -1
		ch <- res
		return
	}
	if res2.status == 4 {
		res2.nxopti = 1
		ch <- res2
		return
	}
	if res2.Res == "false" {
		res2.nxopti = 0
	}
	ch <- res2
}

func scanResolvers(resolver []InputFileFormat, tempFile *TempStore, tokenDepth int, rounds int, timeout time.Duration, retryTrimeout time.Duration, fileName string) {

	for i := 0; i < rounds; i++ {
		fmt.Println("round", i+1, "/", rounds)
		ch := make(chan QueryResult)
		var wg sync.WaitGroup

		for _, res := range resolver {
			if res.Queried_ip == "" || res.Resolver_type == "" {
				log.Println("nil value type (skipped): %w", res)
				continue
			}
			wg.Add(1)
			go dnsQueryRoutine(tokenDepth, res, timeout, retryTrimeout, dns.TypeTXT, ch, &wg, false, false) /*
				wg.Add(1)
				go dnsQueryRoutine(tokenDepth, res, timeout, retryTrimeout, dns.TypeTXT, ch, &wg, true, false)
				wg.Add(1)
				go dnsQueryRoutine(tokenDepth, res, timeout, retryTrimeout, dns.TypeTXT, ch, &wg, false, true)
				wg.Add(1)
				go nxOptiRoutine(res, timeout, retryTrimeout, dns.TypeTXT, ch, &wg)*/
		}
		go func() {
			wg.Wait()
			close(ch)
		}()

		for v := range ch {
			resLine := ParquetQueryResult{
				ResolverIP:       v.resolverIP,
				RequestingIP:     v.requestingIP,
				Response:         v.Res,
				InducedQMINCheck: v.induction,
				InducedRes:       v.inductionPattern,
				InductionIP:      v.inductionRequester,
				ModeCheck:        v.qmin_mode,
				NxOptimization:   v.nxopti,
				NXCheck:          v.nxcheck,
				ResolverType:     v.ResolverType,
				FileName:         fileName,
			}
			tempFile.WriteSingle(resLine)
		}
	}
}

func readInputAndScan(inputPath string, batchSize int, fileName string) (*TempStore, error) {
	tempDataFile, err := NewTempStore()
	if err != nil {
		return nil, fmt.Errorf("Could not create Temporary file: %w", err)
	}

	inputFile, err := os.Open(inputPath)
	if err != nil {
		return nil, fmt.Errorf("Could not Open input file: %w", err)
	}
	defer inputFile.Close()

	reader := parquet.NewGenericReader[InputFileFormat](inputFile)
	defer reader.Close()

	partIndex := 1
	numParts := math.Ceil(float64(reader.NumRows()) / float64(batchSize))

	rows := make([]InputFileFormat, batchSize)
	for {
		log.Println("Part", partIndex, "of", numParts)
		partIndex++

		n, err := reader.Read(rows)
		if n > 0 {
			scanResolvers(rows[:n], tempDataFile, Cfg.LabelDepth, Cfg.Rounds, time.Duration(Cfg.Timeout*int(time.Millisecond)), time.Duration(Cfg.RetryTimeout*int(time.Millisecond)), fileName)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return tempDataFile, fmt.Errorf("error while reading data: %w", err)
		}
	}

	if err := tempDataFile.Close(); err != nil {
		return tempDataFile, fmt.Errorf("Error while trying to close temporary file: %w", err)
	}

	return tempDataFile, nil
}

func readInputTXTAndScan(inputPath string, batchSize int, fileName string) (*TempStore, error) {
	tempDataFile, err := NewTempStore()
	if err != nil {
		return nil, fmt.Errorf("Could not create Temporary file: %w", err)
	}
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return nil, fmt.Errorf("Could not Open input file: %w", err)
	}
	defer inputFile.Close()

	scanner := bufio.NewScanner(inputFile)
	batch := make([]InputFileFormat, 0, batchSize)

	for scanner.Scan() {
		t := scanner.Text()
		ty := "unset"
		batch = append(batch, InputFileFormat{Queried_ip: t, Resolver_type: ty})

		if len(batch) == batchSize {
			scanResolvers(batch, tempDataFile, Cfg.LabelDepth, Cfg.Rounds, time.Duration(Cfg.Timeout*int(time.Millisecond)), time.Duration(Cfg.RetryTimeout*int(time.Millisecond)), fileName)
			batch = batch[:0]
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}
	if len(batch) > 0 {
		scanResolvers(batch, tempDataFile, Cfg.LabelDepth, Cfg.Rounds, time.Duration(Cfg.Timeout*int(time.Millisecond)), time.Duration(Cfg.RetryTimeout*int(time.Millisecond)), fileName)
	}

	if err := tempDataFile.Close(); err != nil {
		return tempDataFile, fmt.Errorf("Error while trying to close temporary file: %w", err)
	}

	return tempDataFile, nil
}

func scanFile(path string, outputPath string) {
	tempDataFile, err := NewTempStore()
	if err != nil {
		log.Fatalln("Could not create Temporary file: %w", err)
	}

	defer func() {
		tempDataFile.Delete()
	}()

	fileStat, err := os.Stat(path)

	if os.IsNotExist(err) {
		log.Fatalln("File not Found")
	}
	switch filepath.Ext(path) {
	case ".txt":
		tempDataFile, err = readInputTXTAndScan(path, Cfg.BatchSize, fileStat.Name())
	case ".pq", ".parquet":
		tempDataFile, err = readInputAndScan(path, Cfg.BatchSize, fileStat.Name())
	default:
		log.Println("Unsupported file extension: ", path)
		return
	}
	if err != nil {
		if tempDataFile != nil {
			log.Println("Temporary file path: %w", tempDataFile.Path())
		}
		log.Fatal(err)
	}
	log.Println("Temporary file path: %w", tempDataFile.Path())
	WriteOutputParquet(tempDataFile.Path(), outputPath+"/result.parquet")
}

func (scan *QMinScanner) Start_scan(inArg []string, inputIsResolver bool) {
	stats := ScanStat{
		Timeout:      Cfg.Timeout,
		RetryTimeout: Cfg.RetryTimeout,
		Protocol:     Cfg.Protocol,
		LabelDepth:   Cfg.LabelDepth,
		Rounds:       Cfg.Rounds,
		BaseURL:      Cfg.BaseURL,
	}

	start := time.Now()
	stats.Start = start

	baseDomain = Cfg.BaseURL
	randMax = Cfg.RandMax

	// get permission of output directory to pass them down
	dirStat, err := os.Stat(Cfg.OutputDir)
	if os.IsNotExist(err) {
		log.Fatalln("Output directory does not exist")
	}
	if err != nil {
		log.Fatalln("Couldn't access output directory")
	}

	workingDir := Cfg.OutputDir + start.Local().Format("2006-01-02_15-04")
	err = os.Mkdir(workingDir, dirStat.Mode().Perm())
	if err != nil {
		log.Fatalln("Failed to create output directory: ", err)
	}
	// user can input ether one single ip or a csv file containing multiple
	// default is the csv file
	if inputIsResolver {
		tempDataFile, err := NewTempStore()
		if err != nil {
			log.Fatalln("Could not create Temporary file: %w", err)
		}
		res_type := "Unset"
		scanResolvers([]InputFileFormat{{Queried_ip: inArg[0], Resolver_type: res_type}}, tempDataFile, Cfg.LabelDepth, Cfg.Rounds, time.Duration(Cfg.Timeout*int(time.Millisecond)), time.Duration(Cfg.RetryTimeout*int(time.Millisecond)), "programArgument")

		if err := tempDataFile.Close(); err != nil {
			log.Println("Temporary file path: %w", tempDataFile.Path())
			log.Fatalln("Error while trying to close temporary file: %w", err)
		}
		log.Println("Temporary file path: %w", tempDataFile.Path())
		WriteOutputParquet(tempDataFile.Path(), workingDir+"/result.parquet")
		tempDataFile.Delete()
	} else {
		for _, arg := range inArg {
			argStat, err := os.Stat(arg)
			if err != nil {
				log.Println("Failed to get OS Stat of passed argument: ", err)
				continue
			}
			if !argStat.IsDir() {
				fileNameNoExt := strings.Split(argStat.Name(), ".")[0]
				os.Mkdir(workingDir+"/"+fileNameNoExt, dirStat.Mode().Perm())
				scanFile(arg, workingDir+"/"+fileNameNoExt)
				continue
			}

			dirEntris, err := os.ReadDir(arg)
			if err != nil {
				log.Println("Failed to read files in given directory: ", err)
				continue
			}

			for _, dirEntry := range dirEntris {
				if !dirEntry.IsDir() {
					fileNameNoExt := strings.Split(dirEntry.Name(), ".")[0]
					os.Mkdir(workingDir+"/"+fileNameNoExt, dirStat.Mode().Perm())
					scanFile(filepath.Join(arg, dirEntry.Name()), workingDir+"/"+fileNameNoExt)
				}
			}

		}
	}

	fmt.Println("runtime: ", time.Since(start))

	stats.Fin = time.Now()
	stats.Runtime = time.Since(start).String()

	data, err := json.MarshalIndent(stats, "", "	")
	if err != nil {
		log.Fatalln("couldn't convert stats to json")
	}

	err = os.WriteFile(workingDir+"/metadata.json", data, dirStat.Mode().Perm())
	if err != nil {
		log.Fatalln("Couldn't write Metadata.json file")
	}
}
