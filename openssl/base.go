package openssl

const (
    OPENSSL     = "/usr/bin/openssl"
)

type OpenSSLer interface {
	String() string
	Array()  []string
	Exec()   error
}
