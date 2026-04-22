module dns_tools

go 1.24.0

toolchain go1.24.1

require (
	github.com/f10d0/bpfutils v0.0.0-20250325140524-3a1c37d88542
	github.com/gopacket/gopacket v1.3.1
	github.com/ilyakaznacheev/cleanenv v1.5.0
	go.uber.org/ratelimit v0.3.1
	golang.org/x/net v0.48.0
)

require (
	golang.org/x/mod v0.31.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/tools v0.40.0 // indirect
)

require (
	github.com/BurntSushi/toml v1.4.0 // indirect
	github.com/benbjohnson/clock v1.3.0 // indirect
	github.com/joho/godotenv v1.5.1 // indirect
	github.com/miekg/dns v1.1.72
	golang.org/x/sys v0.39.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	olympos.io/encoding/edn v0.0.0-20201019073823-d3554ca0b0a3 // indirect
)

replace github.com/gopacket/gopacket => github.com/f10d0/gopacket v1.0.3
