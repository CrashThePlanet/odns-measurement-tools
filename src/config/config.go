package config

import (
	"github.com/ilyakaznacheev/cleanenv"
)

// config
type Cfg_db struct {
	// ===== General Settings =====
	// the interface name of the interface used for scanning
	Iface_name string `yaml:"iface_name"`
	// the interface's IP address
	Iface_ip string `yaml:"iface_ip"`
	// the interface's IPv& address
	Iface_ip6 string `yaml:"iface_ip6"`
	// the scan's destination port, typically 53 for DNS
	Dst_port uint16 `yaml:"dst_port" env-default:"53"`
	// the dns query name to use during scanning
	Dns_query string `yaml:"dns_query"`
	// dns query type (only UDP)
	Dns_query_type string `yaml:"dns_query_type" env-default:"A"`
	// enable dnssec (only udp)
	Dnssec_enabled bool `yaml:"dnssec_enabled" env-default:"false"`
	// enable edns0 (only UDP)
	EDNS0_enabled bool `yaml:"edns0_enabled" env-default:"false"`
	// ENDS0 buffer size
	EDNS0_buffer_size int `yaml:"edns0_buffer_size" env-default:"4096"`
	// Log all dns resource records
	Log_dnsrecs bool `yaml:"log_dnsrecs" env-default:"false"`
	// list of ips or subnets in CIDR notation to exclude from the scan
	Excl_ips_fname string `yaml:"exclude_ips_fname"`
	// maximum pps to *send*
	Pkts_per_sec int `yaml:"pkts_per_sec"`
	// verbosity -> 0: OFF, 1: ERR, 2: WARN, 3: INFO, 4: DEBUG, 5: VERBOSE, 6: ALL
	Verbosity int    `yaml:"verbosity" env-default:"3"`
	Port_min  uint16 `yaml:"port_min"`
	Port_max  uint16 `yaml:"port_max"`
	// used in traceroute to specify how long to wait between traceroutes on the same port
	Port_reuse_timeout int `yaml:"port_reuse_timeout"`
	// Number of go routines to use for each scan/test
	// for udp/tcp: number of concurrent senders
	// traceroute:  number of concurrent traceroutes
	// rate limit:  number of concurrent rate limit targets to test
	Number_routines uint16 `yaml:"no_of_routines" env-default:"1"`
	// boolean value to specify whether craft the ethernet header of each outgoing packet inside this program
	// effectively changing between sending from layer 2 or layer 3
	// ===== Rate limit testing settings =====
	Craft_ethernet bool `yaml:"craft_ethernet" env-default:"false"`
	// domain mode may be: < constant | hash | list | inject >
	// provide domain_list path if list or inject
	// constant: static query domain
	// hash:     add a random subdomain string to the front of the defined query name (Dns_query)
	// list:     read a list of domains to use, randomly chosen for each send query
	// inject:   only reads a subset of the domain list and inject (=request) these domains on each of the resolvers
	//           before running the actual ratelimit test
	Domain_mode string `yaml:"domain_mode" env-default:"constant"`
	// path to a domain list
	//       format: id,domain
	//         e.g.: 1,google.com
	//               2,yahoo.com
	Domain_list string `yaml:"domain_list"`
	// comma separated list of send rates to test one after another
	// e.g.: 50, 100, 150, 200
	// this will start testing with 50pps slowly ramping up the send rate to 200pps if the target manages to serve this rate
	Rate_curve string `yaml:"rate_curve" env-default:"50,100,200,400,600,800,1000"`
	// rate modes may be: < probe | direct >
	//  - probe will check the entire /24 net of the transparent fwds from the intersect file for (further) active fwds
	//  - direct will only use the specified addresses
	Rate_mode string `yaml:"rate_mode" env-default:"direct"`
	// in ms, how long to test each send rate of the rate curve for
	Rate_increase_interval int `yaml:"rate_increase_interval" env-default:"2000"`
	// in ms, how long to wait for incoming packets
	Rate_wait_interval int `yaml:"rate_wait_interval" env-default:"150"`
	// use the below defined receive threshold to prematurely end the test
	Rate_ignore_threshold bool `yaml:"rate_ignore_threshold" env-default:"false"`
	// receive threshold: between 0 and 1, defines what percentage of the outgoing packet rate must be received again to
	//                    to be counted as successfully serving the target packet rate
	//                    e.g.: current send rate is 1000pps, threshold value is 0.75
	//                          -> if the incoming packet rate on average over the time of the test interval is below
	//                             750pps the target failed to serve the send rate of 1000ps and the test will stop at
	//                             this send rate of 1000pps and not try higher values
	Rate_receive_threshold float64 `yaml:"rate_receive_threshold" env-default:"0.75"`
	// ===== Rate limit cache injection =====
	// sending rate to use in pps during cache injection
	Rate_inject_speed int `yaml:"rate_inject_speed" env-default:"100"`
	// the number of domains to read from the domains list and use for injection and rate testing
	Rate_inject_count int `yaml:"rate_inject_count" env-default:"1000"`
	// the number of go routines to use during the cache injection phase
	// example: approx 60000 resolvers, with 1000 routines at 100pps (=10s per resolver with 1k domains) -> 10min injection time
	Rate_inject_routines int `yaml:"rate_inject_routines" env-default:"1000"`
	Rate_inject_max_fwds int `yaml:"rate_inject_max_fwds" env-default:"50"`
	// ignore the target-ips of the input file and test the response-ips directly
	Rate_response_ip_only bool `yaml:"rate_response_ip_only" env-default:"false"`
	// will summon a routine for each ip of the tfwd_pool to test concurrently at the same rate
	Rate_concurrent_pool bool `yaml:"rate_concurrent_pool" env-default:"false"`
	// number of subroutines to use for rate testing (== different source ports per forwarder/resolver)
	Rate_subroutines int `yaml:"rate_subroutines" env-default:"5"`
}

var Cfg Cfg_db

func Load_config(config_path string) {
	err := cleanenv.ReadConfig(config_path, &Cfg)
	if err != nil {
		panic(err)
	}
}
