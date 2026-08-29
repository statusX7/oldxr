module github.com/xtls/xray-core

replace github.com/panjf2000/gnet/v2 => ../gnet

replace github.com/pawelgaczynski/giouring => ../giouring

go 1.26

require (
	github.com/ghodss/yaml v1.0.1-0.20220118164431-d8423dcdf344
	github.com/golang/mock v1.6.0
	github.com/golang/protobuf v1.5.4
	github.com/google/go-cmp v0.7.0
	github.com/gorilla/websocket v1.5.3
	github.com/miekg/dns v1.1.50
	github.com/pelletier/go-toml v1.9.5
	github.com/pires/go-proxyproto v0.6.2
	github.com/quic-go/quic-go v0.59.1
	github.com/refraction-networking/utls v1.8.2
	github.com/sagernet/sing v0.4.1
	github.com/sagernet/sing-shadowsocks v0.2.7
	github.com/sagernet/wireguard-go v0.0.0-20221116151939-c99467f53f2c
	github.com/seiflotfy/cuckoofilter v0.0.0-20220411075957-e3b120b3f5fb
	github.com/stretchr/testify v1.11.1
	github.com/v2fly/ss-bloomring v0.0.0-20210312155135-28617310f63e
	github.com/xtls/go v0.0.0-20230107031059-4610f88d00f3
	go.starlark.net v0.0.0-20260708150628-5395d018f003
	golang.org/x/crypto v0.55.0
	golang.org/x/net v0.58.0
	golang.org/x/sync v0.22.0
	golang.org/x/sys v0.47.0
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.12
	gvisor.dev/gvisor v0.0.0-20260122175437-89a5d21be8f0
	h12.io/socks v1.0.3
)

require (
	github.com/panjf2000/ants/v2 v2.12.1 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.28.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dgryski/go-metro v0.0.0-20211217172704-adc40b04c140 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/klauspost/cpuid/v2 v2.2.3 // indirect
	github.com/panjf2000/gnet/v2 v2.10.0
	github.com/pawelgaczynski/giouring v0.0.0-20230826085535-69588b89acb9
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/riobard/go-bloom v0.0.0-20200614022211-cdc8013cb5b3 // indirect
	go.uber.org/atomic v1.10.0 // indirect
	golang.org/x/exp v0.0.0-20231110203233-9a3e6036ecaa // indirect
	golang.org/x/mod v0.40.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	golang.org/x/tools v0.49.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	lukechampine.com/blake3 v1.3.0 // indirect
)
