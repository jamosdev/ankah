module dotsdemo/edge

go 1.25.0

require (
	github.com/nttdots/go-dots v0.0.0-20250417053854-4e631d1257fd
	github.com/sirupsen/logrus v1.8.1
)

require (
	github.com/aristanetworks/goeapi v0.6.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/fatih/structs v1.1.0 // indirect
	github.com/go-sql-driver/mysql v1.6.0 // indirect
	github.com/go-xorm/xorm v0.7.9 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/julienschmidt/httprouter v1.3.0 // indirect
	github.com/lib/pq v1.10.5 // indirect
	github.com/mitchellh/mapstructure v1.4.3 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/osrg/gobgp/v3 v3.5.0 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/prometheus/client_golang v1.24.1
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.70.1 // indirect
	github.com/prometheus/procfs v0.21.1 // indirect
	github.com/shopspring/decimal v1.3.1 // indirect
	github.com/ugorji/go/codec v1.2.7 // indirect
	github.com/vaughan0/go-ini v0.0.0-20130923145212-a98ad7ee00ec // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20180127040702-4e3ac2762d5f // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	google.golang.org/genproto v0.0.0-20230410155749-daa745c078e1 // indirect
	google.golang.org/grpc v1.56.3 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	xorm.io/builder v0.3.6 // indirect
	xorm.io/core v0.7.2-0.20190928055935-90aeac8d08eb // indirect
)

// The Dockerfile fetches go-dots at the pinned commit into this directory and
// applies third_party/patches. See the example README.
replace github.com/nttdots/go-dots => ./third_party/go-dots
