package qmin_scanner

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnshttp"
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

var dohClient = &http.Client{
	Transport: &http.Transport{
		ForceAttemptHTTP2:   true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
	},
}

func doDoHQuery(ctx context.Context, method, target string, m *dns.Msg) (*dns.Msg, int, error) {
	req, err := dnshttp.NewRequest(method, target, m)
	if err != nil {
		return nil, 0, fmt.Errorf("build request: %w", err)
	}
	req = req.WithContext(ctx)
	req.Header.Set("Accept", "application/dns-message")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/dns-message")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("http status %d", resp.StatusCode)
	}

	res, err := dnshttp.Response(resp) // body is still open here
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("parse response: %w", err)
	}
	return res, resp.StatusCode, nil
}

func dnsQuery(domain string, server string, qType uint16, timeout time.Duration) QueryResult {
	m := dns.NewMsg(domain, qType)
	m.RecursionDesired = true

	var res *dns.Msg
	var err error

	switch Cfg.Protocol {
	case "udp", "tcp":
		// increase UDP Buffer size
		// some Resolver send too large packages
		if Cfg.Protocol == "udp" {
			m.UDPSize, m.Security = 4096, false
		}
		c := dns.NewClient()
		c.ReadTimeout = timeout
		c.WriteTimeout = timeout

		targetServer := net.JoinHostPort(server, strconv.Itoa(Cfg.Port))
		res, _, err = c.Exchange(context.TODO(), m, Cfg.Protocol, targetServer)
	case "doh":
		if !strings.HasPrefix(server, "https://") && !strings.HasPrefix(server, "http://") {
			server = "https://" + server
		}

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		res2, status, err2 := doDoHQuery(ctx, http.MethodPost, server, m)
		switch status {
		case http.StatusBadRequest, http.StatusMethodNotAllowed,
			http.StatusUnsupportedMediaType, http.StatusNotImplemented:
			res2, status, err2 = doDoHQuery(ctx, http.MethodGet, server, m)
		}

		if err2 != nil {
			if status != 0 {
				return QueryResult{resolverIP: server, requestingIP: "NONE", status: 9, Res: err2.Error()}
			}
			return evalCommError(err2, server)
		}
		res = res2
		err = err2
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
			go dnsQueryRoutine(tokenDepth, res, timeout, retryTrimeout, dns.TypeTXT, ch, &wg, false, false)
			wg.Add(1)
			go dnsQueryRoutine(tokenDepth, res, timeout, retryTrimeout, dns.TypeTXT, ch, &wg, true, false)
			wg.Add(1)
			go dnsQueryRoutine(tokenDepth, res, timeout, retryTrimeout, dns.TypeTXT, ch, &wg, false, true)
			wg.Add(1)
			go nxOptiRoutine(res, timeout, retryTrimeout, dns.TypeTXT, ch, &wg)
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
