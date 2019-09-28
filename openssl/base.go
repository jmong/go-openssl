package openssl

var (
    Cmd string
)

type OpenSSLer interface {
    String() string
    Array()  []string
    Exec()   error
}
