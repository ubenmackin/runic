module runic

go 1.26.5

require (
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/mattn/go-sqlite3 v1.14.41
)

require github.com/gorilla/mux v1.8.1

require (
	github.com/gorilla/websocket v1.5.3
	github.com/minio/selfupdate v0.6.0
	github.com/prometheus/client_golang v1.23.2
	github.com/prometheus/client_model v0.6.2
	github.com/stretchr/testify v1.11.1
	golang.org/x/crypto v0.56.0 // GO-2026-5932: openpgp not imported (bcrypt/hkdf/pbkdf2 only); no fixed version upstream.
	golang.org/x/sync v0.20.0
	golang.org/x/term v0.45.0
)

require (
	aead.dev/minisign v0.2.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/common v0.66.1 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	golang.org/x/net v0.57.0
	golang.org/x/sys v0.47.0 // indirect
	google.golang.org/protobuf v1.36.8 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
