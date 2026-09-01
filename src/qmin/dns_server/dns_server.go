package qmin_dnsserver

import (
	"context"
	"fmt"
	"log"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
	// dnsv1 "github.com/miekg/dns"
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
		for k, v := range probes {
			if time.Since(v.lastSeen).Milliseconds() > int64(s.timeout) {
				// fmt.Println("delete old probe entry. New length:", len(probes))
				probesMutex.Lock()
				delete(probes, k)
				probesMutex.Unlock()
			}
		}
		time.Sleep(time.Duration(s.sleepCycle) * time.Millisecond)
	}
}

// the labels sequence also stores the RTYPE of each label-batch
// this function removes them and sends the labels back as one string
// this is basicly the last seend dns request minus the base url
func stripRTypes(seq []string) (res string) {
	for i, pToken := range seq {
		tmp := strings.Split(pToken, "_")[0]
		if i == 0 {
			res = tmp
		} else {
			res += "." + tmp
		}
	}
	return res
}

// check if a given seqence of tokens contains more information (either more tokens or same amout but different qtype) then the other given
// if so update and return the new one
func updateProbeEntry(tokenLength int, probeSeq []string, tokenSeq string, tokens []string, requestQtype uint16) (updatedSeq []string, tokenNum int, extended bool) {
	// remove rtypes
	domain := stripRTypes(probeSeq)
	updatedSeq = probeSeq
	// new request is longer than the longest recorded one and contains said longest requested domain --> more information
	// should occur if qmin is used
	// some RR are sending shorter domains inbetween longer ones
	// i've seen one that even does qmin inverse (so send fqdn first und remove one label with each successive request) -> idk why?!
	if len(domain) < len(tokenSeq) && strings.Contains(tokenSeq, domain) {
		extended = true
		var newSeq string
		if len(domain) == 0 {
			newSeq = tokenSeq
		} else {
			newSeq = tokenSeq[:len(tokenSeq)-len(domain)-1]
		}

		tokenNum = len(tokens)
		// force copy of tokenSequence slice
		// some Resolver send the last request (the entiry requested sequence) twice (or more)
		// for some reason the last label/token (the idToken) disappears inbetween these 2 requests
		// the forced copy solves this
		// it should not be a concurrency problem, as the entire block is inside a mutex ?!
		// do not touch
		updatedSeq = append([]string(nil), probeSeq...)
		updatedSeq = slices.Insert(updatedSeq, 0, newSeq+"_"+dns.TypeToString[requestQtype])
		// end
	}
	recentTok := updatedSeq[0]

	if len(domain) == len(tokenSeq) && strings.Contains(tokenSeq, domain) && requestQtype == dns.TypeTXT && !strings.HasSuffix(recentTok, "_TXT") {
		updatedSeq = append([]string(nil), updatedSeq...)
		updatedSeq = slices.Insert(updatedSeq, 0, strconv.Itoa(tokenLength-1)+"_"+dns.TypeToString[requestQtype])
	}
	return
}

// handle incoming dns request
func (s *QminDnsServer) requestResponse(w dns.ResponseWriter, r *dns.Msg) (dns.ResponseWriter, *dns.Msg) {
	m := &dns.Msg{
		MsgHeader: dns.MsgHeader{
			ID:                 r.ID,
			Response:           true,
			Authoritative:      true,
			RecursionDesired:   r.RecursionDesired,
			RecursionAvailable: false,
		},
		Question: r.Question,
	}
	dnsutil.SetReply(m, r)
	m.Authoritative = true
	m.UDPSize = r.UDPSize
	m.Security = r.Security

	requestedDomain := strings.ToLower(r.Question[0].Header().Name)

	// catch requests that target predefined records
	if slices.Contains(slices.Collect(maps.Keys(s.resource_records)), requestedDomain) {
		record := s.resource_records[requestedDomain]
		if dns.RRToType(r.Question[0]) == dns.StringToType[record.qtype] {
			rr, err := dns.New(fmt.Sprintf("%s 3600 IN %s %s", r.Question[0].Header().Name, record.qtype, record.value))
			if err != nil {
				fmt.Println("Error while creating RR %w", err)
				m.Rcode = dns.RcodeServerFailure
				return w, m
			}
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
		m.Rcode = dns.RcodeNameError
		return w, m
	}

	tokenSeq := requestedDomain[:len(requestedDomain)-len(s.baseURL)-1]
	// get every label in domain minus the base domain
	tokens := strings.Split(tokenSeq, ".")
	// the id token holds the metadata for this requests run
	idToken := tokens[len(tokens)-1]

	// TODO: check for valid id token
	if len(idToken) < 10 {
		m.Rcode = dns.RcodeRefused
		return w, m
	}

	probeMetaData := strings.Split(idToken, "-")
	//  every valid id token hast at least 3 parts (IP in hex, token depth, nonce)
	if len(probeMetaData) < 3 {
		m.Rcode = dns.RcodeNameError
		return w, m
	}

	probesMutex.Lock()
	probe, ok := probes[idToken]

	// check if this probe (identified by id Token) has sent a request before
	if ok {
		// later on each sequence of tokens (requested by the probe) will also contain the RTYPE
		// the seperator is the underscore "_"
		// the scanner should not create domains with an underscore in them

		updatedSeq, tokenNum, extended := updateProbeEntry(probe.tokenLength, probe.tokenSequence, tokenSeq, tokens, dns.RRToType(r.Question[0]))
		probe.tokenSequence = updatedSeq
		if extended {
			probe.currTokenNum = tokenNum
		}
		probe.lastSeen = time.Now()

	} else if p, ok := probes[idToken+"-induction"]; ok {

		updatedInductionSeq, tokenNum, extended := updateProbeEntry(p.tokenLength, p.inductionProbe.tokenSequence, tokenSeq, tokens, dns.RRToType(r.Question[0]))
		p.inductionProbe.tokenSequence = updatedInductionSeq
		if extended {
			p.inductionProbe.currTokenNum = tokenNum
			p.inductionProbe.resolver = strings.Split(w.RemoteAddr().String(), ":")[0]
		}

		p.lastSeen = time.Now()
		probe = p
		idToken += "-induction"
	} else {
		// first time this domain is requested
		// create entry in probes map

		tokenLen, err := strconv.ParseInt(probeMetaData[1], 10, 64)
		if err != nil {
			fmt.Errorf("Couldn't parse token length: %v", err.Error())
		}
		probe = probeData{
			tokenLength:      int(tokenLen),
			lastSeen:         time.Now(),
			tokenSequence:    []string{tokenSeq + "_" + dns.TypeToString[dns.RRToType(r.Question[0])]},
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
	if probe.induction && probe.inductionProbe.currTokenNum == probe.tokenLength && dns.RRToType(r.Question[0]) == dns.TypeTXT {
		rr, err := dns.New(fmt.Sprintf("%s 3600 IN TXT \"%s\"", r.Question[0].Header().Name, probe.incomingResolver+","+strings.Join(probe.tokenSequence, "|")+","+probe.inductionProbe.resolver+","+strings.Join(probe.inductionProbe.tokenSequence, "|")))
		if err != nil {
			fmt.Println("Error while creating RR %w", err)
			m.Rcode = dns.RcodeServerFailure
			return w, m
		}
		m.Answer = append(m.Answer, rr)
		return w, m
	} else if len(probeMetaData) > 3 && probeMetaData[3] == "nxopti" {
		if r.Question[0].Header().Name[0] == 'b' {
			rr, err := dns.New(fmt.Sprintf("%s 3600 IN TXT \"%s\"", r.Question[0].Header().Name, "false,,,"))
			if err != nil {
				fmt.Println("Error while creating RR %w", err)
				m.Rcode = dns.RcodeServerFailure
				return w, m
			}
			m.Answer = append(m.Answer, rr)
		} else {
			m.Rcode = dns.RcodeNameError
		}
		return w, m
	} else if probe.currTokenNum == probe.tokenLength {
		if len(probeMetaData) > 3 && probeMetaData[3] == "induction" {

			var domain string
			for i := probe.tokenLength - 1; i > 0; i-- {
				domain += strconv.Itoa(i) + "."
			}
			rr := &dns.CNAME{
				Hdr:   dns.Header{Name: r.Question[0].Header().Name, Class: dns.ClassINET, TTL: 3600},
				CNAME: rdata.CNAME{Target: domain + strings.Join(probeMetaData[:3], "-") + "." + s.baseURL},
			}
			m.Authoritative = false
			m.Answer = append(m.Answer, rr)
		} else if dns.RRToType(r.Question[0]) == dns.TypeTXT {
			rr, err := dns.New(fmt.Sprintf("%s 3600 IN TXT \"%s\"", r.Question[0].Header().Name, probe.incomingResolver+","+strings.Join(probe.tokenSequence, "|")+",NULL,NULL"))
			if err != nil {
				fmt.Println("Error while creating RR %w", err)
				m.Rcode = dns.RcodeServerFailure
				return w, m
			}
			m.Answer = append(m.Answer, rr)
		}
	} else {
		if len(probeMetaData) > 3 && probeMetaData[3] == "qminmode" {
			m.Rcode = dns.RcodeNameError
			return w, m
		} else {
			// if there are still new reuqests expected we return an NS record pointing to this server
			// rr, _ := dnsv1.NewRR(fmt.Sprintf("%s 3600 IN A %s", r.Question[0].Name, s.ip))
			rr, err := dns.New(fmt.Sprintf("%s 3600 IN NS %s", r.Question[0].Header().Name, "ns1.tilhempel.info."))
			if err != nil {
				fmt.Println("Error while creating RR %w", err)
				m.Rcode = dns.RcodeServerFailure
				return w, m
			}
			m.Answer = append(m.Answer, rr)
		}

	}
	return w, m
}

func (s *QminDnsServer) responder(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	var m *dns.Msg
	w, m = s.requestResponse(w, r)

	if _, err := m.WriteTo(w); err != nil {
		log.Println("Write error: ", err.Error())
	}
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
	udpServer := &dns.Server{Addr: s.addr + ":" + strconv.Itoa(s.port), Net: "udp"}
	tcpServer := &dns.Server{Addr: s.addr + ":" + strconv.Itoa(s.port), Net: "tcp"}
	go func() {
		fmt.Println("DNS server listining on:", s.addr, ":", s.port, ";Protocol: udp")
		if err := udpServer.ListenAndServe(); err != nil {
			log.Fatalf("udp server failed: %v", err)
		}
	}()
	go func() {
		fmt.Println("DNS server listining on:", s.addr, ":", s.port, ";Protocol: tcp")
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Fatalf("tcp server failed: %v", err)
		}
	}()
	select {}
}
