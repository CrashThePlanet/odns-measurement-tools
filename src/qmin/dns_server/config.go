package qmin_dnsserver

import (
	"github.com/ilyakaznacheev/cleanenv"
)

type Cfg_db struct {
	// base Domain for which this server acts as Authoritve DNS Server
	BaseURL string `yaml:"BaseURL"`
	// Ip on which to this server listens
	// 0.0.0.0 can work but nor always
	ListenIp string `yaml:"ListenIp"`
	// Port on which to listen
	// DNS is 53
	Port int `yaml:"Port"`
	//TCP or UDP
	Protocol string `yaml:"Protocol"`
	// Public IP of this Server
	IPAddr string `yaml:"IPAddr"`
	// the Server stores incoming requests
	// Timeout defines how "old" they can get before beeing deleted (in ms)
	Timeout int `yaml:"Timeout"`
	// how often the cleanup is run (in ms)
	SleepCycle int `yaml:"SleepCycle"`

	ResourceRecords []map[string]string `yaml:"resource_records"`
}

var Cfg Cfg_db

func Load_config(config_path string) {
	err := cleanenv.ReadConfig(config_path, &Cfg)
	if err != nil {
		panic(err)
	}
}
