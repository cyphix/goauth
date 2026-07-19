module github.com/cyphix/goauth

go 1.26.0

replace github.com/cyphix/gologg => ../gologg

replace github.com/cyphix/godatabases => ../godatabases

require (
	github.com/alexedwards/argon2id v1.0.0
	github.com/alexedwards/scs/v2 v2.9.0
	github.com/alicebob/miniredis/v2 v2.36.1
	github.com/coreos/go-oidc/v3 v3.20.0
	github.com/cyphix/godatabases v0.0.0-00010101000000-000000000000
	github.com/cyphix/gologg v0.2.0
	github.com/fxamacker/cbor/v2 v2.9.2
	github.com/go-webauthn/webauthn v0.17.4
	github.com/labstack/echo/v4 v4.15.4
	github.com/redis/go-redis/v9 v9.21.0
	github.com/rs/zerolog v1.35.1
	github.com/stretchr/testify v1.11.1
	golang.org/x/oauth2 v0.36.0
	gorm.io/driver/sqlite v1.6.0
	gorm.io/gorm v1.31.2
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/x v0.2.6 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/labstack/gommon v0.5.0 // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mattn/go-isatty v0.0.22 // indirect
	github.com/mattn/go-sqlite3 v1.14.34 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasttemplate v1.2.2 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/yuin/gopher-lua v1.1.1 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.38.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
