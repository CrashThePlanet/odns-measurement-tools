package qmin_scanner

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var baseDomain string
var randMax int

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
	Ip     string
	status int // -1: undefined error,  0: no error, 1: refused, 2: Servfail, 3: timeout, 4: NXDomain, 5: No Route to host, 6: no recursion available, 7: no answer from resolver, 8: answer contains no TXT response
	Res    string
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

func partitionStringSlice(list []string, partitionSize int) [][]string {
	if len(list) < partitionSize {
		return [][]string{list}
	}

	var partitions = [][]string{}

	for i := 0; i <= len(list); i += partitionSize {
		if i+partitionSize > len(list) {
			partitions = append(partitions, list[i:])
		} else {
			partitions = append(partitions, list[i:i+partitionSize])
		}
	}
	return partitions
}

func domainAssembly(dnsServer string, tokenDepth int) string {
	octets := strings.Split(dnsServer, ".")
	if len(octets) != 4 {
		log.Fatalln("Please provide an correct IPv4 Adress: ", dnsServer)
	}

	var idToken = ""

	for _, oc := range octets {
		ocInt, err := strconv.Atoi(oc)
		if err != nil {
			log.Fatalln("Please provide an correct IPv4 Adress: ", dnsServer)
		}
		if ocInt < 16 {
			idToken += "0"
		}
		idToken += strconv.FormatInt(int64(ocInt), 16)
	}

	idToken += strconv.Itoa(tokenDepth)
	idToken += strconv.Itoa(rand.Intn(randMax))

	var domain = ""

	for i := tokenDepth - 1; i > 0; i-- {
		domain += strconv.Itoa(i) + "."
	}

	domain += idToken + "." + baseDomain
	return domain
}

func dnsQuery(domain string, server string, qType uint16, timeout time.Duration) QueryResult {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qType)
	m.RecursionDesired = true

	c := new(dns.Client)
	c.Net = Cfg.Protocol
	c.Timeout = timeout
	res, _, err := c.Exchange(m, server+":"+strconv.Itoa(Cfg.Port))

	if err != nil {
		if strings.Contains(err.Error(), "i/o timeout") {
			return QueryResult{Ip: server, status: 3, Res: "timeout"}
		}
		if strings.Contains(err.Error(), "connection refused") {
			return QueryResult{Ip: server, status: 1, Res: "refused"}
		}
		if strings.Contains(err.Error(), "no route to host") {
			return QueryResult{Ip: server, status: 5, Res: "noRoute"}
		}
		fmt.Println("unhandled error: ", err)
		return QueryResult{Ip: server, status: -1, Res: "unhandledError"}
	}

	if res.Rcode != dns.RcodeSuccess {
		switch res.Rcode {
		case dns.RcodeServerFailure:
			return QueryResult{Ip: server, status: 2, Res: "servfail"}
		case dns.RcodeNameError:
			return QueryResult{Ip: server, status: 4, Res: "nxdomain"}
		case dns.RcodeRefused:
			return QueryResult{Ip: server, status: 1, Res: "refused"}
		default:
			return QueryResult{Ip: server, status: -1, Res: "unhandledError"}
		}
	}
	if len(res.Answer) == 0 {
		if !res.RecursionAvailable {
			return QueryResult{Ip: server, status: 6, Res: "noRecursion"}
		}
		return QueryResult{Ip: server, status: 7, Res: "noAnswer"}
	}
	if t, ok := res.Answer[0].(*dns.TXT); ok {
		return QueryResult{Ip: server, status: 0, Res: t.Txt[0]}
	}
	return QueryResult{Ip: server, status: 9, Res: "noTXTResponse"}
}

func dnsQueryRoutine(tokenDepth int, server string, timeout time.Duration, retryTimeout time.Duration, qType uint16, ch chan<- QueryResult, wg *sync.WaitGroup) {
	defer wg.Done()
	requestedDomain := domainAssembly(server, tokenDepth)
	res := dnsQuery(requestedDomain, server, qType, timeout)
	if res.status == 3 {
		res = dnsQuery(requestedDomain, server, qType, retryTimeout)
	}
	ch <- res
}

func scanResolvers(resolver []string, tokenDepth int, rounds int, batchSize int, timeout time.Duration, retryTrimeout time.Duration) map[string][]QueryResult {
	var out = make(map[string][]QueryResult)

	parts := partitionStringSlice(resolver, batchSize)

	for i, part := range parts {
		fmt.Println("part", i+1, "/", len(parts))
		for i := 0; i < rounds; i++ {
			fmt.Println("round", i+1, "/", rounds)
			ch := make(chan QueryResult)
			var wg sync.WaitGroup

			for _, ip := range part {
				wg.Add(1)
				go dnsQueryRoutine(tokenDepth, ip, timeout, retryTrimeout, dns.TypeTXT, ch, &wg)
			}
			go func() {
				wg.Wait()
				close(ch)
			}()

			for v := range ch {
				val, ok := out[v.Ip]
				if ok {
					out[v.Ip] = append(val, v)
				} else {
					out[v.Ip] = []QueryResult{v}
				}
			}
		}
	}
	return out
}

type kvPair struct {
	Key   QueryResult
	value int
}

func evalRsults(raw map[string][]QueryResult) map[string][3]string {
	var out = make(map[string][3]string)
	for k, v := range raw {
		qmin := -1
		var counter = make(map[QueryResult]int)
		mostFreq := kvPair{QueryResult{"", 0, ""}, 0}

		for _, seq := range v {
			if seq.status == 0 {
				if strings.Contains(seq.Res, "|") {
					switch qmin {
					case 0:
						qmin = 2
					case -1:
						qmin = 1
					}
					seq.Res = seq.Res[:strings.LastIndex(seq.Res, "|")+1]
				} else if strings.Contains(seq.Res, ".") {
					switch qmin {
					case 1:
						qmin = 2
					case -1:
						qmin = 0
					}
					seq.Res = seq.Res[:strings.LastIndex(seq.Res, ".")+1]
				}
				seq.Res += "*idToken*"
			}

			if val, ok := counter[seq]; ok {
				counter[seq] = val + 1
			} else {
				counter[seq] = 1
			}
			if counter[seq] > mostFreq.value {
				mostFreq = kvPair{seq, counter[seq]}
			}
		}
		var tmp = make(map[string]int)
		for k, v := range counter {
			tmp[k.Res] = v
		}
		out[k] = [3]string{
			strconv.Itoa(qmin),
			fmt.Sprint(tmp),
			strconv.Itoa(mostFreq.value),
		}
	}
	return out
}

func writeOutputCSV(data map[string][3]string, outPath string) {
	var csvData = [][]string{}

	for k, v := range data {
		csvData = append(csvData, []string{k, v[0], v[1]})
	}

	file, err := os.Create(outPath)
	if err != nil {
		log.Fatalln("Couldn't create output file: ", err.Error())
	}
	writer := csv.NewWriter(file)
	err = writer.WriteAll(csvData)

	if err != nil {
		log.Fatalln("Couldn't write to Output File: ", err.Error())
	}
}

func readCSV(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalln("Couldn't open CSV file: ", err.Error())
	}
	reader := csv.NewReader(file)
	records, _ := reader.ReadAll()

	var ips = []string{}
	for _, record := range records[1:] {
		ips = append(ips, record[1])
	}
	return ips
}

func (scan *QMinScanner) Start_scan(inArg string, inputIsResolver bool) {
	stats := ScanStat{
		Input:        inArg,
		Timeout:      Cfg.Timeout,
		RetryTimeout: Cfg.RetryTimeout,
		Protocol:     Cfg.Protocol,
		LabelDepth:   Cfg.LabelDepth,
		Rounds:       Cfg.Rounds,
		BaseURL:      Cfg.BaseURL,
	}

	start := time.Now()
	stats.Start = start

	var server []string

	// user can input ether one single ip or a csv file containing multiple
	// default is the csv file
	if inputIsResolver {
		// TODO: check for valid ip address
		server = []string{inArg}
	} else {
		if _, err := os.Stat(inArg); os.IsNotExist(err) {
			log.Fatalln("File not Found")
		}
		server = readCSV(inArg)
	}
	stats.NumResolver = len(server)

	// get permission of output directory to pass them down
	dirStat, err := os.Stat(Cfg.OutputDir)
	if os.IsNotExist(err) {
		log.Fatalln("Output directory does not exist")
	}
	if err != nil {
		log.Fatalln("Couldn't access output directory")
	}

	workingDir := Cfg.OutputDir + start.Local().Format("2006-01-02_15-04")
	os.Mkdir(workingDir, dirStat.Mode().Perm())

	baseDomain = Cfg.BaseURL
	randMax = Cfg.RandMax

	fmt.Println("estimated maximum runtime:", time.Duration(Cfg.Rounds*Cfg.RetryTimeout*int(time.Millisecond)).String())

	responses := scanResolvers(server, Cfg.LabelDepth, Cfg.Rounds, Cfg.BatchSize, time.Duration(Cfg.Timeout*int(time.Millisecond)), time.Duration(Cfg.RetryTimeout*int(time.Millisecond)))
	results := evalRsults(responses)

	writeOutputCSV(results, workingDir+"/result.csv")
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
