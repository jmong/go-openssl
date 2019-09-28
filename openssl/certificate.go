package openssl

import (
    "os"
    "os/exec"
    "strings"
)

type CertificateBuilder interface {
    NewkeyRSA(int)     CertificateBuilder
    NewkeyDSA(string)  CertificateBuilder
    NewkeyEC(string)   CertificateBuilder
    Digest(string)     CertificateBuilder
    Out(string)        CertificateBuilder
    X509(bool)         CertificateBuilder
    Days(int)          CertificateBuilder
    NoDES(bool)        CertificateBuilder
    Key(string)        CertificateBuilder
    Extensions(string) CertificateBuilder
    Config(string)     CertificateBuilder
    New(bool)          CertificateBuilder
    Extra(string)      CertificateBuilder
    
    BuildCreate()      Certificate            
}

type CertificateBuild struct {
    newkeyrsa  Attribute
    newkeydsa  Attribute
    newkeyec   Attribute
    digest     Attribute
    out        Attribute
    x509       Attribute
    days       Attribute
    nodes      Attribute
    key        Attribute
    extensions Attribute
    config     Attribute
    new        Attribute
    extra      Attribute
}

/*
 *
 */
func NewCertificateBuilder() CertificateBuilder {
	return &CertificateBuild{}
}

/*
 *
 */
func (sb *CertificateBuild) NewkeyRSA(bits int) CertificateBuilder {
	sb.newkeyrsa = Attribute{Native: INT, IsUpdated: true, Arg: "-newkey", Prepend: "rsa:", ValueInt: bits}
	return sb
}

/*
 *
 */
func (sb *CertificateBuild) NewkeyDSA(file string) CertificateBuilder {
	sb.newkeydsa = Attribute{Native: STRING, IsUpdated: true, Arg: "-newkey", Prepend: "dsa:", Value: file}
	return sb
}

/*
 *
 */
func (sb *CertificateBuild) NewkeyEC(file string) CertificateBuilder {
	sb.newkeyec = Attribute{Native: STRING, IsUpdated: true, Arg: "-newkey", Prepend: "ec:", Value: file}
	return sb
}

/*
 *
 */
func (sb *CertificateBuild) Digest(digest string) CertificateBuilder {
	sb.digest = Attribute{Native: STRING, IsUpdated: true, Prepend: "-", Value: digest}
	return sb
}

/*
 *
 */
func (sb *CertificateBuild) Out(file string) CertificateBuilder {
	sb.out = Attribute{Native: STRING, IsUpdated: true, Arg: "-out", Value: file}
	return sb
}

/*
 *
 */
func (sb *CertificateBuild) X509(enabled bool) CertificateBuilder {
	sb.x509 = Attribute{Native: BOOL, IsUpdated: true, Arg: "-x509", ValueBool: enabled}
	return sb
}

/*
 *
 */
func (sb *CertificateBuild) Days(days int) CertificateBuilder {
	sb.days = Attribute{Native: INT, IsUpdated: true, Arg: "-days", ValueInt: days}
	return sb
}

/*
 *
 */
func (sb *CertificateBuild) NoDES(enabled bool) CertificateBuilder {
	sb.nodes = Attribute{Native: BOOL, IsUpdated: true, Arg: "-nodes", ValueBool: enabled}
	return sb
}

/*
 *
 */
func (sb *CertificateBuild) Key(file string) CertificateBuilder {
	sb.key = Attribute{Native: STRING, IsUpdated: true, Arg: "-key", Value: file}
	return sb
}

/*
 *
 */
func (sb *CertificateBuild) Extensions(certext string) CertificateBuilder {
	sb.extensions = Attribute{Native: STRING, IsUpdated: true, Arg: "-extensions", Value: certext}
	return sb
}

/*
 *
 */
func (sb *CertificateBuild) Config(file string) CertificateBuilder {
	sb.config = Attribute{Native: STRING, IsUpdated: true, Arg: "-config", Value: file}
	return sb
}

/*
 *
 */
func (sb *CertificateBuild) New(isnew bool) CertificateBuilder {
	sb.new = Attribute{Native: BOOL, IsUpdated: true, Arg: "-new", ValueBool: isnew}
	return sb
}

/*
 *
 */
func (sb *CertificateBuild) Extra(args string) CertificateBuilder {
	sb.extra = Attribute{Native: STRING, IsUpdated: true, Value: args}
	return sb
}

/*
 *
 */
func (sb *CertificateBuild) BuildCreate() Certificate {
    arr := []string{Cmd, "certificate"}
    arr = append(arr, toArray(true, sb.newkeyrsa, sb.newkeydsa, sb.newkeyec,
                 sb.digest, sb.out, sb.x509, sb.days, sb.nodes, 
                 sb.key, sb.extensions, sb.config, sb.new, sb.extra)...)
    
    return Certificate{
        cmd:          Cmd,
        action:       "req",
        array:        arr,
        Description:  "Create certificate",
        NewkeyRSA:    sb.newkeyrsa,
        NewkeyDSA:    sb.newkeydsa,
        NewkeyEC:     sb.newkeyec,
        Digest:       sb.digest,
        Out:          sb.out,
        X509:         sb.x509,
        Days:         sb.days,
        NoDES:        sb.nodes,
        Key:          sb.key,
        Extensions:   sb.extensions,
        Config:       sb.config,
        New:          sb.new,
        Extra:        sb.extra,
    }
}

type Certificate struct {
    cmd          string
    action       string
    array        []string
    Description  string
    NewkeyRSA    Attribute
    NewkeyDSA    Attribute
    NewkeyEC     Attribute
    Digest       Attribute
    Out          Attribute
    X509         Attribute
    Days         Attribute
    NoDES        Attribute
    Key          Attribute
    Extensions   Attribute
    Config       Attribute
    New          Attribute
    Extra        Attribute
}

/*
 *
 */
func (ss *Certificate) String() string {
    return strings.Join(ss.array, " ")
}

/*
 *
 */
func (ss *Certificate) Array() []string {
    return ss.array
}

/*
 */
func (ss *Certificate) Exec() error {
	r := ss.Array()
    c, args := r[0], r[1:]
    cmd := exec.Command(c, args...)
    cmd.Stdout = os.Stdout
    cmd.Stdin = os.Stdin
    cmd.Stderr = os.Stderr
    
    return cmd.Run()
}


