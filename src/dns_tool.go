package main

import (
	"dns_tools/common"
	scanner_config "dns_tools/config"
	"dns_tools/logging"
	qmin_dnsserver "dns_tools/qmin/dns_server"
	qmin_scanner "dns_tools/qmin/scanner"
	"dns_tools/ratelimit"
	tcpscanner "dns_tools/scanner/tcp"
	udpscanner "dns_tools/scanner/udp"
	traceroute_tcp "dns_tools/traceroute"
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
)

var cpu_file *os.File

func start_profiling() {
	var err error
	cpu_file, err = os.Create("cpu.prof")
	if err != nil {
		panic(err)
	}
	runtime.SetCPUProfileRate(200)
	if err := pprof.StartCPUProfile(cpu_file); err != nil {
		panic(err)
	}
}

func stop_profiling() {
	pprof.StopCPUProfile()
	cpu_file.Close()
}

type SubCommand struct {
	fs *flag.FlagSet

	name        string
	description string
}

func (sc *SubCommand) Name() string {
	return sc.fs.Name()
}
func (sc *SubCommand) Init(args []string) error {
	return sc.fs.Parse(args)
}
func (sc *SubCommand) Description() string {
	return sc.description
}

type Runner interface {
	Run() (error, int)
	Name() string
	Init([]string) error
	Description() string
}

type ScannerCommand struct {
	SubCommand
	help_flag       bool
	mode_flag       string
	mode_alias      string
	prot_flag       string
	prot_alias      string
	config_path     string
	config_alias    string
	pktrate         int
	pktrate_alias   int
	outpath         string
	outpath_alias   string
	profile         bool
	debug_level     int
	debug_alias     int
	ethernet_header bool
	ethernet_alias  bool
	qname           string
	qname_alias     string
	port            int
}

func NewScannerCommand() *ScannerCommand {
	sc := &ScannerCommand{
		SubCommand: SubCommand{
			fs:          flag.NewFlagSet("scanner", flag.ContinueOnError),
			description: "Measure the open DNS infrastructure over IPv4 using TCP/UDP",
		},
	}
	sc.fs.BoolVar(&sc.help_flag, "help", false, "Display help")
	sc.fs.StringVar(&sc.mode_flag, "mode", "", "available modes: (s)scan, (t)trace,traceroute")
	sc.fs.StringVar(&sc.mode_alias, "m", "", "alias for -mode")
	sc.fs.StringVar(&sc.prot_flag, "protocol", "", "available protocols: tcp, udp")
	sc.fs.StringVar(&sc.prot_alias, "p", "", "alias for -protocol")
	sc.fs.StringVar(&sc.config_path, "config", "", "Path to configuration file")
	sc.fs.StringVar(&sc.config_alias, "c", "", "alias for -config")
	sc.fs.IntVar(&sc.pktrate, "rate", -2, "packet rate in pkt/s, -1 for unlimited")
	sc.fs.IntVar(&sc.pktrate_alias, "r", -2, "alias for -rate")
	sc.fs.StringVar(&sc.outpath, "out", "", "output file path")
	sc.fs.StringVar(&sc.outpath_alias, "o", "", "alias for -out")
	sc.fs.BoolVar(&sc.profile, "profile", false, "enable cpu profiling (output file: cpu.prof")
	sc.fs.IntVar(&sc.debug_level, "verbose", -1, "overwrites the debug level set in the config")
	sc.fs.IntVar(&sc.debug_alias, "v", -1, "alias for -verbose")
	sc.fs.BoolVar(&sc.ethernet_header, "ethernet", false, "dns_tool will manually craft the ethernet header")
	sc.fs.BoolVar(&sc.ethernet_alias, "e", false, "alias for -ethernet")
	sc.fs.StringVar(&sc.qname, "qname", "", "overwrites config dns query name")
	sc.fs.StringVar(&sc.qname_alias, "q", "", "alias for -qname")
	sc.fs.IntVar(&sc.port, "port", -1, "overwrites the port set in config file")

	return sc
}

func (sc *ScannerCommand) Run() (error, int) {
	if sc.help_flag {
		sc.fs.Usage()
		return nil, 0
	}
	if sc.mode_alias != "" {
		sc.mode_flag = sc.mode_alias
	}
	if sc.prot_alias != "" {
		sc.prot_flag = sc.prot_alias
	}
	if sc.config_alias != "" {
		sc.config_path = sc.config_alias
	}
	if sc.debug_alias > -1 {
		sc.debug_level = sc.debug_alias
	}
	if sc.pktrate_alias > -2 {
		sc.pktrate = sc.pktrate_alias
	}
	if sc.outpath_alias != "" {
		sc.outpath = sc.outpath_alias
	}
	if sc.qname_alias != "" {
		sc.qname = sc.qname_alias
	}
	scanner_config.Cfg.Craft_ethernet = sc.ethernet_alias || sc.ethernet_header

	if sc.config_path != "" {
		fmt.Println("using config", sc.config_path)
		scanner_config.Load_config(sc.config_path)
	} else {
		return fmt.Errorf("missing config path"), int(common.WRONG_INPUT_ARGS)
	}

	if sc.pktrate > -2 {
		scanner_config.Cfg.Pkts_per_sec = sc.pktrate
	}

	if sc.qname != "" {
		scanner_config.Cfg.Dns_query = sc.qname
	}

	if sc.debug_level > -1 {
		fmt.Println("verbosity level set to", sc.debug_level)
		scanner_config.Cfg.Verbosity = sc.debug_level
	}

	if sc.port != -1 {
		scanner_config.Cfg.Dst_port = uint16(sc.port)
	}

	fmt.Println("config:", scanner_config.Cfg)

	if sc.profile {
		// go tool pprof -http=:8080 cpu.prof
		start_profiling()
	}

	if sc.mode_flag != "" {
		switch sc.mode_flag {
		case "s":
			fallthrough
		case "scan":
			if sc.prot_flag == "" {
				return fmt.Errorf("missing protocol"), int(common.WRONG_INPUT_ARGS)
			}
			switch sc.prot_flag {
			case "tcp":
				fmt.Println("starting tcp scan")
				logging.Runlog_prefix = "TCP-SCAN"
				var tcp_scanner tcpscanner.Tcp_scanner
				if sc.outpath == "" {
					sc.outpath = "tcp_results.csv.gz"
				}
				tcp_scanner.Start_scan(sc.fs.Args(), sc.outpath)
			case "udp":
				fmt.Println("starting udp scan")
				logging.Runlog_prefix = "UDP-SCAN"
				var udp_scanner udpscanner.Udp_scanner
				if sc.outpath == "" {
					sc.outpath = "udp_results.csv.gz"
				}
				udp_scanner.Start_scan(sc.fs.Args(), sc.outpath)
			default:
				return fmt.Errorf("wrong protocol"), int(common.WRONG_INPUT_ARGS)
			}
		case "t":
			fallthrough
		case "trace":
			fallthrough
		case "traceroute":
			if sc.prot_flag == "" {
				return fmt.Errorf("missing protocol"), int(common.WRONG_INPUT_ARGS)
			}
			switch sc.prot_flag {
			case "tcp":
				fmt.Println("starting tcp traceroute")
				logging.Runlog_prefix = "TCP-Traceroute"
				var tcp_traceroute traceroute_tcp.Tcp_traceroute
				tcp_traceroute.Start_traceroute(sc.fs.Args())
			default:
				return fmt.Errorf("wrong protocol"), int(common.WRONG_INPUT_ARGS)
			}
		case "r":
			fallthrough
		case "rate":
			fallthrough
		case "ratelimit":
			var rate_tester ratelimit.Rate_tester
			if sc.outpath == "" {
				sc.outpath = "ratelimit_results"
			}
			fmt.Println("starting ratelimit testing")
			logging.Runlog_prefix = "Ratelimit"
			rate_tester.Start_ratetest(sc.fs.Args(), sc.outpath)
		default:
			return fmt.Errorf("%s", fmt.Sprint("wrong mode:", sc.mode_flag)), int(common.WRONG_INPUT_ARGS)
		}
	} else {
		return fmt.Errorf("missing mode (--mode)"), int(common.WRONG_INPUT_ARGS)
	}

	if sc.profile {
		stop_profiling()
	}
	return nil, 0
}

type QMinServerCommand struct {
	SubCommand
	help_flag    bool
	config_path  string
	config_alias string
}

func NewQMinServerCommand() *QMinServerCommand {
	sc := &QMinServerCommand{
		SubCommand: SubCommand{
			fs:          flag.NewFlagSet("qmin_server", flag.ContinueOnError),
			description: "Starts up a DNS Server for Qmin testing of DNS Resolver",
		},
	}
	sc.fs.BoolVar(&sc.help_flag, "help", false, "Display help")
	sc.fs.StringVar(&sc.config_path, "config", "qmin/dns_server/config.yml", "Path to config File")
	sc.fs.StringVar(&sc.config_alias, "c", "", "alias for --config")

	return sc
}

func (qc *QMinServerCommand) Run() (error, int) {
	if qc.help_flag {
		qc.fs.Usage()
		return nil, 0
	}
	if qc.config_alias != "" {
		qc.config_path = qc.config_alias
	}
	if qc.config_path != "" {
		fmt.Println("using config", qc.config_path)
		qmin_dnsserver.Load_config(qc.config_path)
	} else {
		return fmt.Errorf("missing config path"), int(common.WRONG_INPUT_ARGS)
	}

	var server qmin_dnsserver.QminDnsServer
	server.Start_server()

	return nil, 0
}

type QMinScannerCommand struct {
	SubCommand
	help_flag      bool
	resolver_flag  bool
	resolver_alias bool
	config_path    string
	config_alias   string
}

func NewQMinScannerCommand() *QMinScannerCommand {
	sc := &QMinScannerCommand{
		SubCommand: SubCommand{
			fs:          flag.NewFlagSet("qmin_scanner", flag.ContinueOnError),
			description: "Starts the QMin Scanner to test Resolvers",
		},
	}
	sc.fs.BoolVar(&sc.help_flag, "help", false, "Display help")
	sc.fs.BoolVar(&sc.resolver_flag, "resolver", false, "allows you to pass ONE resolver (ip) instead of file")
	sc.fs.BoolVar(&sc.resolver_alias, "r", false, "alias for --resolver")
	sc.fs.StringVar(&sc.config_path, "config", "./qmin/scanner/config.yml", "Path to config file")
	sc.fs.StringVar(&sc.config_alias, "c", "", "alais for --conmfig")

	return sc
}

func (qsc *QMinScannerCommand) Run() (error, int) {
	if qsc.help_flag {
		qsc.fs.Usage()
		return nil, 0
	}
	if qsc.config_alias != "" {
		qsc.config_path = qsc.config_alias
	}
	if qsc.resolver_alias {
		qsc.resolver_flag = qsc.resolver_alias
	}
	if qsc.config_path != "" {
		fmt.Println("using config", qsc.config_path)
		qmin_scanner.Load_config(qsc.config_path)
	} else {
		return fmt.Errorf("missing config path"), int(common.WRONG_INPUT_ARGS)
	}

	var scanner qmin_scanner.QMinScanner
	scanner.Start_scan(qsc.fs.Args()[0], qsc.resolver_flag)

	return nil, 0
}

type QMINScannerParquetWriterCommand struct {
	SubCommand
	temp_path string
}

func NewQMINScannerParquetWriterCommand() *QMINScannerParquetWriterCommand {
	wc := &QMINScannerParquetWriterCommand{
		SubCommand: SubCommand{
			fs:          flag.NewFlagSet("temp_file_parquet_writer", flag.ContinueOnError),
			description: "Write temp scan results file to parquet file",
		},
	}
	wc.fs.StringVar(&wc.temp_path, "path", "", "Path to temp file")

	return wc
}

func (pwc *QMINScannerParquetWriterCommand) Run() (error, int) {
	if pwc.temp_path == "" {
		return fmt.Errorf("Path is missing"), int(common.WRONG_INPUT_ARGS)
	}
	if _, err := os.Stat(pwc.temp_path); os.IsNotExist(err) {
		return fmt.Errorf("File not Found"), int(common.WRONG_INPUT_ARGS)
	}

	qmin_scanner.WriteOutputParquet(pwc.temp_path, "./src/data/raw/qmin/out.parquet")

	return nil, 0
}

func base(args []string) (error, int) {
	if len(args) < 1 {
		return fmt.Errorf("You must choose what to do!"), int(common.WRONG_INPUT_ARGS)
	}

	cmds := []Runner{
		NewScannerCommand(),
		NewQMinServerCommand(),
		NewQMinScannerCommand(),
		NewQMINScannerParquetWriterCommand(),
	}

	if args[0] == "help" {
		for _, cmd := range cmds {
			fmt.Println(cmd.Name(), "\t", cmd.Description())
		}
		return nil, 0
	}

	for _, cmd := range cmds {
		if cmd.Name() == args[0] {
			cmd.Init(args[1:])
			return cmd.Run()
		}
	}

	return fmt.Errorf("Unknown Subcommand"), 1
}

func main() {
	if err, code := base(os.Args[1:]); err != nil {
		fmt.Println(err)
		os.Exit(code)
	}
}
