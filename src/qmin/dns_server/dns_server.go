package qmin_dnsserver

import (
	"fmt"
	"log"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var lastClean time.Time

type IP struct {
	Query string
}
type probeData struct {
	tokenLength      int
	incomingResolver string
	lastSeen         time.Time
	tokenSequence    []string
	currTokenNum     int
	induction        bool
	inductionProbe   inducedProbe
}

type inducedProbe struct {
	tokenSequence []string
	currTokenNum  int
	resolver      string
}

type ResourceRecord struct {
	name  string
	qtype string
	value string
}

type QminDnsServer struct {
	baseURL          string
	addr             string
	port             int
	timeout          int
	sleepCycle       int
	ip               string
	resource_records map[string]ResourceRecord
}

var (
	probes      = make(map[string]probeData)
	probesMutex = sync.RWMutex{}
)

func (s *QminDnsServer) cleanProbes() {
	for true {
		probesMutex.Lock()
		for k, v := range probes {
			if time.Since(v.lastSeen).Milliseconds() > int64(s.timeout) {
				// fmt.Println("delete old probe entry. New length:", len(probes))
				delete(probes, k)
			}
		}
		probesMutex.Unlock()
		time.Sleep(time.Duration(s.sleepCycle) * time.Millisecond)
	}
}

// handle incoming dns request
func (s *QminDnsServer) requestResponse(w dns.ResponseWriter, r *dns.Msg) (dns.ResponseWriter, *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	requestedDomain := strings.ToLower(r.Question[0].Name)

	// catch requests that target predefined records
	if slices.Contains(slices.Collect(maps.Keys(s.resource_records)), requestedDomain) {
		record := s.resource_records[requestedDomain]
		if r.Question[0].Qtype == dns.StringToType[record.qtype] {
			rr, _ := dns.NewRR(fmt.Sprintf("%s 3600 IN %s %s", r.Question[0].Name, record.qtype, record.value))
			m.Answer = append(m.Answer, rr)
			return w, m
		}
	}

	// some resolver prepend "_." to each request (except the fqdn with all tokens)
	// it can be removed as this carries no information or significance
	if len(requestedDomain) > 2 && requestedDomain[:2] == "_." {
		requestedDomain = requestedDomain[2:]
	}

	// check if requested Domain is longer than base domain and ends in the base domain
	if len(requestedDomain) <= len(s.baseURL) || requestedDomain[len(requestedDomain)-len(s.baseURL):] != s.baseURL {
		m.SetRcode(r, dns.RcodeNameError)
		return w, m
	}

	tokenSeq := requestedDomain[:len(requestedDomain)-len(s.baseURL)-1]
	tokens := strings.Split(tokenSeq, ".")
	idToken := tokens[len(tokens)-1]

	// TODO: check for valid id token
	if len(idToken) < 10 {
		m.SetRcode(r, dns.RcodeRefused)
		return w, m
	}
	probeMetaData := strings.Split(idToken, "-")

	probesMutex.Lock()
	probe, ok := probes[idToken]

	// check if this probe (identified by id Token) has sent a request before
	if ok {
		// probeDomain := strings.Join(probe.tokenSequence, ".")
		probeDomain := ""
		for i, pToken := range probe.tokenSequence {
			tmp := strings.Split(pToken, "_")[0]
			if i == 0 {
				probeDomain = tmp
			} else {
				probeDomain += "." + tmp
			}
		}

		// new request is longer than the longest recorded one and contains said longest requested domain --> more information
		// should occur if qmin is used
		// some RR are sending shorter domains inbetween longer ones
		// i've seen one that even does qmin inverse (so send fqdn first und remove one label with each successive request) -> idk why?!
		if len(probeDomain) < len(tokenSeq) && strings.Contains(tokenSeq, probeDomain) {
			newSeq := tokenSeq[:len(tokenSeq)-len(probeDomain)-1]

			probe.currTokenNum = len(tokens)
			// force copy of tokenSequence slice
			// some Resolver send the last request (the entiry requested sequence) twice (or more)
			// for some reason the last label/token (the idToken) disappears inbetween these 2 requests
			// the forced copy solves this
			// it should not be a concurrency problem, as the entire block is inside a mutex ?!
			// do not touch
			s := append([]string(nil), probe.tokenSequence...)
			s = slices.Insert(s, 0, newSeq+"_"+dns.TypeToString[r.Question[0].Qtype])
			probe.tokenSequence = s
			// end
		}
		recentTok := probe.tokenSequence[len(probe.tokenSequence)-1]

		if len(probeDomain) == len(tokenSeq) && strings.Contains(tokenSeq, probeDomain) && r.Question[0].Qtype == dns.TypeTXT && recentTok[len(recentTok)-3:] != "_TXT" {
			s := append([]string(nil), probe.tokenSequence...)
			s = slices.Insert(s, 0, strconv.Itoa(probe.tokenLength)+"_"+dns.TypeToString[r.Question[0].Qtype])
			probe.tokenSequence = s
		}

		probe.lastSeen = time.Now()
	} else if p, ok := probes[idToken+"-induction"]; ok {
		//inductionDomain := strings.Join(p.inductionProbe.tokenSequence, ".")
		inductionDomain := ""
		for i, pToken := range p.inductionProbe.tokenSequence {
			tmp := strings.Split(pToken, "_")[0]
			if i == 0 {
				inductionDomain = tmp
			} else {
				inductionDomain += "." + tmp
			}
		}
		if len(inductionDomain) < len(tokenSeq) && strings.Contains(tokenSeq, inductionDomain) {
			var newSeq string
			if len(inductionDomain) == 0 {
				newSeq = tokenSeq
			} else {
				newSeq = tokenSeq[:len(tokenSeq)-len(inductionDomain)-1]
			}

			p.inductionProbe.currTokenNum = len(tokens)
			s := append([]string(nil), p.inductionProbe.tokenSequence...)
			s = slices.Insert(s, 0, newSeq+"_"+dns.TypeToString[r.Question[0].Qtype])
			p.inductionProbe.resolver = strings.Split(w.RemoteAddr().String(), ":")[0]
			p.inductionProbe.tokenSequence = s
		}

		recentTok := p.inductionProbe.tokenSequence[len(p.inductionProbe.tokenSequence)-1]

		if len(inductionDomain) == len(tokenSeq) && strings.Contains(tokenSeq, inductionDomain) && r.Question[0].Qtype == dns.TypeTXT && recentTok[len(recentTok)-3:] != "_TXT" {
			s := append([]string(nil), p.inductionProbe.tokenSequence...)
			s = slices.Insert(s, 0, strconv.Itoa(p.tokenLength)+"_"+dns.TypeToString[r.Question[0].Qtype])
			p.inductionProbe.tokenSequence = s
		}

		p.lastSeen = time.Now()
		probe = p
		idToken += "-induction"
	} else {
		// first time this domain is requested
		// create entry in probes map

		// Label to identify the probe run:
		// XXXXXXXX | XX | XXXX... (pipes just for visualisation)
		// IPv4 of Resolver (Hex) | max token depth (int) | randomized numbers to circumvent caches (length loosly dependent on number of runs per resolver)

		tokenLen, err := strconv.ParseInt(probeMetaData[1], 10, 64)
		if err != nil {
			fmt.Errorf("Couldn't parse token length: %v", err.Error())
		}
		probe = probeData{
			tokenLength:      int(tokenLen),
			lastSeen:         time.Now(),
			tokenSequence:    []string{tokenSeq + "_" + dns.TypeToString[r.Question[0].Qtype]},
			currTokenNum:     len(tokens),
			incomingResolver: strings.Split(w.RemoteAddr().String(), ":")[0], // RemoteAddr() contains IP and Port --> remove port
			induction:        len(probeMetaData) > 3 && probeMetaData[3] == "induction",
			inductionProbe: inducedProbe{
				tokenSequence: []string{},
				currTokenNum:  0,
			},
		}
	}
	probes[idToken] = probe
	probesMutex.Unlock()

	// if this request was the last (determained by the provied depth inside the ID label) we return a TXT response containing the pattern and the ip of requesting server
	// (ip of requested and requesting server can differ -> forwarder)
	if probe.induction && probe.inductionProbe.currTokenNum == probe.tokenLength && r.Question[0].Qtype == dns.TypeTXT {
		rr, _ := dns.NewRR(fmt.Sprintf("%s 3600 IN TXT \"%s\"", r.Question[0].Name, probe.incomingResolver+","+strings.Join(probe.tokenSequence, "|")+","+probe.inductionProbe.resolver+","+strings.Join(probe.inductionProbe.tokenSequence, "|")))
		m.Answer = append(m.Answer, rr)
		return w, m
	} else if len(probeMetaData) > 3 && probeMetaData[3] == "nxopti" {
		if r.Question[0].Name[0] == 'b' {
			rr, _ := dns.NewRR(fmt.Sprintf("%s 3600 IN TXT \"%s\"", r.Question[0].Name, "false,,,"))
			m.Answer = append(m.Answer, rr)
		} else {
			m.SetRcode(r, dns.RcodeNameError)
		}
		return w, m
	} else if probe.currTokenNum == probe.tokenLength {
		if len(probeMetaData) > 3 && probeMetaData[3] == "induction" {
			rr := new(dns.CNAME)
			rr.Hdr = dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 3600}

			var domain string
			for i := probe.tokenLength - 1; i > 0; i-- {
				domain += strconv.Itoa(i) + "."
			}
			rr.Target = domain + strings.Join(probeMetaData[:3], "-") + "." + s.baseURL
			m.Answer = append(m.Answer, rr)
		} else if r.Question[0].Qtype == dns.TypeTXT {
			rr, _ := dns.NewRR(fmt.Sprintf("%s 3600 IN TXT \"%s\"", r.Question[0].Name, probe.incomingResolver+","+strings.Join(probe.tokenSequence, "|")+",NULL,NULL"))
			m.Answer = append(m.Answer, rr)
		}
	} else {
		if len(probeMetaData) > 3 && probeMetaData[3] == "qmin_mode" {
			m.SetRcode(r, dns.RcodeNameError)
			return w, m
		} else {
			// if there are still new reuqests expected we return an NS record pointing to this server
			// rr, _ := dns.NewRR(fmt.Sprintf("%s 3600 IN A %s", r.Question[0].Name, s.ip))
			rr, _ := dns.NewRR(fmt.Sprintf("%s 3600 IN NS %s", r.Question[0].Name, "ns1.tilhempel.info."))
			m.Answer = append(m.Answer, rr)
		}

	}
	return w, m
}

func (s *QminDnsServer) responder(w dns.ResponseWriter, r *dns.Msg) {
	var m *dns.Msg
	w, m = s.requestResponse(w, r)

	if err := w.WriteMsg(m); err != nil {
		log.Fatalf("Write error: %v", err.Error())
	}
	w.Close()
}

func (s *QminDnsServer) Start_server() {

	s.addr = Cfg.ListenIp
	s.port = Cfg.Port
	s.baseURL = Cfg.BaseURL
	s.ip = Cfg.IPAddr
	s.sleepCycle = Cfg.SleepCycle
	s.timeout = Cfg.Timeout
	s.resource_records = make(map[string]ResourceRecord)

	for _, rec := range Cfg.ResourceRecords {
		s.resource_records[rec["name"]] = ResourceRecord{
			name:  rec["name"],
			qtype: rec["qtype"],
			value: rec["value"],
		}
	}

	dns.HandleFunc(".", s.responder)
	go s.cleanProbes()
	server := &dns.Server{Addr: s.addr + ":" + strconv.Itoa(s.port), Net: Cfg.Protocol}
	fmt.Println("DNS server listining on:", s.addr, ":", s.port, ";Protocol:", Cfg.Protocol)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
