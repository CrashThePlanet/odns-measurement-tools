package qmin_scanner

import "github.com/ilyakaznacheev/cleanenv"

type Cfg_db struct {
	// base Domain for which this server acts as Authoritve DNS Server
	BaseURL string `yaml:"BaseURL"`
	// Port on which to listen
	// DNS is 53
	Port int `yaml:"Port"`
	//TCP or UDP
	Protocol string `yaml:"Protocol"`
	// upper limit for random number of id Label in request
	// choose high to avoid two requests gettign the same id label
	RandMax int `yaml:"RandMax"`
	// how many label the request should be deep
	// used to test qmin pattern
	// > 2 to meaningfully test qmin
	LabelDepth int `yaml:"LabelDepth"`
	// how many IPs/Resolver to test in one go
	// depends on available compute power
	BatchSize int `yaml:"BatchSaize"`
	// how often to test each Resolver
	Rounds int `yaml:"Rounds"`
	// normal timeout for a DNS request (in ms)
	Timeout int `yaml:"Timeout"`
	// timeout for trying again
	RetryTimeout int    `yaml:"RetryTimeout"`
	OutputDir    string `yaml:"OutputDir"`
}

var Cfg Cfg_db

func Load_config(config_path string) {
	err := cleanenv.ReadConfig(config_path, &Cfg)
	if err != nil {
		panic(err)
	}
}
