package openssl

const (
    OPENSSL     = "/usr/bin/openssl"
    ACTION      = "req"
    DESCRIPTION = "Create a self-signed certificate."
)

type OpenSSLer interface {
	String() string
	Array()  []string
	Exec()   error
}
