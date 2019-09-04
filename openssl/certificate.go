package openssl

import (
    "os"
    "os/exec"
    "strconv"
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
    
    Build()            Certificate            
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
func (sb *CertificateBuild) Build() Certificate {
    return Certificate{
		cmd:          OPENSSL,
		action:       "req",
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
	}
}

type Certificate struct {
	cmd          string
	action       string
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
}

/*
 *
 */
func (ss *Certificate) String() string {
	cmdline := ss.cmd + " " + ss.action + " "
	if ss.NewkeyRSA.IsSet() {
		cmdline = cmdline + " " + ss.NewkeyRSA.Arg + " " + ss.NewkeyRSA.Prepend + strconv.Itoa(ss.NewkeyRSA.ValueInt)
	}
	if ss.NewkeyDSA.IsSet() {
		cmdline = cmdline + " " + ss.NewkeyDSA.Arg + " " + ss.NewkeyDSA.Prepend + ss.NewkeyDSA.Value
	}
	if ss.NewkeyEC.IsSet() {
		cmdline = cmdline + " " + ss.NewkeyEC.Arg + " " + ss.NewkeyEC.Prepend + ss.NewkeyEC.Value
	}
	if ss.Digest.IsSet() {
		cmdline = cmdline + " " + ss.Digest.Prepend + ss.Digest.Value
	}
	if ss.Days.IsSet() {
		cmdline = cmdline + " " + ss.Days.Arg + " " + strconv.Itoa(ss.Days.ValueInt)
	}
	if ss.Out.IsSet() {
		cmdline = cmdline + " " + ss.Out.Arg + " " + ss.Out.Value
	}
	if ss.X509.IsSet() {
		cmdline = cmdline + " " + ss.X509.Arg
	}
	if ss.NoDES.IsSet() {
		cmdline = cmdline + " " + ss.NoDES.Arg
	}
    if ss.Key.IsSet() {
		cmdline = cmdline + " " + ss.Key.Arg + " " + ss.Key.Value
	}
    if ss.Extensions.IsSet() {
		cmdline = cmdline + " " + ss.Extensions.Arg + " " + ss.Extensions.Value
	}
    if ss.Config.IsSet() {
		cmdline = cmdline + " " + ss.Config.Arg + " " + ss.Config.Value
	}
    if ss.New.IsSet() {
		cmdline = cmdline + " " + ss.New.Arg
	}
	
	return cmdline
}

func (ss *Certificate) Array() []string {
    r := []string{}
    r = append(r, ss.cmd)
    r = append(r, ss.action)
    if ss.NewkeyRSA.IsSet() {
		r = append(r, ss.NewkeyRSA.Arg)
		r = append(r, ss.NewkeyRSA.Prepend + strconv.Itoa(ss.NewkeyRSA.ValueInt))
	}
    if ss.NewkeyDSA.IsSet() {
		r = append(r, ss.NewkeyDSA.Arg)
		r = append(r, ss.NewkeyRSA.Prepend + ss.NewkeyDSA.Value)
	}
	if ss.NewkeyEC.IsSet() {
		r = append(r, ss.NewkeyEC.Arg)
		r = append(r, ss.NewkeyRSA.Prepend + ss.NewkeyEC.Value)
	}
    if ss.Digest.IsSet() {
		r = append(r, ss.Digest.Prepend + ss.Digest.Value)
	}
    if ss.Out.IsSet() {
		r = append(r, ss.Out.Arg)
		r = append(r, ss.Out.Value)
	}
	if ss.Days.IsSet() {
		r = append(r, ss.Days.Arg)
		r = append(r, strconv.Itoa(ss.Days.ValueInt))
	}
	if ss.X509.IsSet() {
		r = append(r, ss.X509.Arg)
	}
	if ss.NoDES.IsSet() {
		r = append(r, ss.NoDES.Arg)
	}
    if ss.Key.IsSet() {
		r = append(r, ss.Key.Arg)
		r = append(r, ss.Key.Value)
	}
    if ss.Extensions.IsSet() {
		r = append(r, ss.Extensions.Arg)
		r = append(r, ss.Extensions.Value)
	}
    if ss.Config.IsSet() {
		r = append(r, ss.Config.Arg)
		r = append(r, ss.Config.Value)
	}
	if ss.New.IsSet() {
		r = append(r, ss.New.Arg)
	}
    
    return r
}

func (ss *Certificate) Exec() error {
	r := ss.Array()
    c, args := r[0], r[1:]
    cmd := exec.Command(c, args...)
    cmd.Stdout = os.Stdout
    cmd.Stdin = os.Stdin
    cmd.Stderr = os.Stderr
    
    return cmd.Run()
}


