package qmin_scanner

import (
	"encoding/csv"
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

type QueryResult struct {
	Ip     string
	status int // -1: undefined error,  0: no error, 1: refused, 2: Servfail, 3: timeout, 4: NXDomain
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
	c.Net = "udp"
	c.Timeout = timeout
	res, _, err := c.Exchange(m, server+":53")

	if err != nil {
		if strings.Contains(err.Error(), "i/o timeout") {
			return QueryResult{Ip: server, status: 3, Res: "timeout"}
		}
		if strings.Contains(err.Error(), "connection refused") {
			return QueryResult{Ip: server, status: 1, Res: "refused"}
		}
		fmt.Println("unhandled error: ", err)
		return QueryResult{Ip: server, status: -1, Res: "unhandled error"}
	}

	if res.Rcode != dns.RcodeSuccess {
		switch res.Rcode {
		case dns.RcodeServerFailure:
			return QueryResult{Ip: server, status: 2, Res: "Server failed to complete request"}
		case dns.RcodeNameError:
			return QueryResult{Ip: server, status: 4, Res: "Domain does not exists on Server"}
		case dns.RcodeRefused:
			return QueryResult{Ip: server, status: 1, Res: "refused"}
		default:
			return QueryResult{Ip: server, status: -1, Res: "unhandled error"}
		}
	}
	if len(res.Answer) == 0 {
		if !res.RecursionAvailable {
			return QueryResult{Ip: server, status: -1, Res: "no recursion available"}
		}
		return QueryResult{Ip: server, status: -1, Res: "no Awnser from Resolver"}
	}
	if t, ok := res.Answer[0].(*dns.TXT); ok {
		return QueryResult{Ip: server, status: 0, Res: t.Txt[0]}
	}
	// fmt.Println(res.Answer[0])
	// fmt.Println(res.Extra)
	return QueryResult{Ip: server, status: -1, Res: "Answer doesn't contain TXT response"}
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

func (scan *QMinScanner) Start_scan(inCSV string) {
	start := time.Now()
	server := readCSV("/home/Til/Downloads/apidownload/data/resolver.csv")
	// server = server[7000:7050]
	// server := []string{"9.9.9.9", "1.1.1.1", "8.8.8.8", "46.226.143.86", "34.28.223.99"}
	// server := []string{"190.181.4.204"}

	baseDomain = Cfg.BaseURL
	randMax = Cfg.RandMax

	fmt.Println("ETA:", time.Duration(Cfg.Rounds*Cfg.RetryTimeout*int(time.Millisecond)).String())

	responses := scanResolvers(server, Cfg.LabelDepth, Cfg.Rounds, Cfg.BatchSize, time.Duration(Cfg.Timeout*int(time.Millisecond)), time.Duration(Cfg.RetryTimeout*int(time.Millisecond)))
	results := evalRsults(responses)
	writeOutputCSV(results, Cfg.OutputDir)
	fmt.Println("runtime: ", time.Since(start))

}
