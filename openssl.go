package main

import (
    "strconv"
)

const (
    OPENSSL     = "/usr/bin/openssl"
    ACTION      = "req"
    DESCRIPTION = "Create a self-signed certificate."
)

type SelfSignedBuilder interface {
    NewkeyRSA(int)     SelfSignedBuilder
    NewkeyDSA(string)  SelfSignedBuilder
    NewkeyEC(string)   SelfSignedBuilder
    Digest(string)     SelfSignedBuilder
    Out(string)        SelfSignedBuilder
    X509(bool)         SelfSignedBuilder
    Days(int)          SelfSignedBuilder
    NoDES(bool)        SelfSignedBuilder
    
    Build()            SelfSigned            
}

type selfSignedBuild struct {
	newkeyrsa  Attribute
    newkeydsa  Attribute
    newkeyec   Attribute
    digest     Attribute
    out        Attribute
    x509       Attribute
    days       Attribute
    nodes      Attribute
}

/*
 *
 */
func NewSelfSignedBuilder() SelfSignedBuilder {
	return &selfSignedBuild{}
}

/*
 *
 */
func (sb *selfSignedBuild) NewkeyRSA(bits int) SelfSignedBuilder {
	sb.newkeyrsa = Attribute{Native: INT, Arg: "-newkey", Prepend: "rsa:", ValueInt: bits}
	return sb
}

/*
 *
 */
func (sb *selfSignedBuild) NewkeyDSA(file string) SelfSignedBuilder {
	sb.newkeydsa = Attribute{Native: STRING, Arg: "-newkey", Prepend: "dsa:", Value: file}
	return sb
}

/*
 *
 */
func (sb *selfSignedBuild) NewkeyEC(file string) SelfSignedBuilder {
	sb.newkeyec = Attribute{Native: STRING, Arg: "-newkey", Prepend: "ec:", Value: file}
	return sb
}

/*
 *
 */
func (sb *selfSignedBuild) Digest(digest string) SelfSignedBuilder {
	sb.digest = Attribute{Native: STRING, Prepend: "-", Value: digest}
	return sb
}

/*
 *
 */
func (sb *selfSignedBuild) Out(file string) SelfSignedBuilder {
	sb.out = Attribute{Native: STRING, Arg: "-out", Value: file}
	return sb
}

/*
 *
 */
func (sb *selfSignedBuild) X509(enabled bool) SelfSignedBuilder {
	sb.x509 = Attribute{Native: BOOL, Arg: "-x509", ValueBool: enabled}
	return sb
}

/*
 *
 */
func (sb *selfSignedBuild) Days(days int) SelfSignedBuilder {
	sb.days = Attribute{Native: INT, Arg: "-days", ValueInt: days}
	return sb
}

/*
 *
 */
func (sb *selfSignedBuild) NoDES(enabled bool) SelfSignedBuilder {
	sb.nodes = Attribute{Native: BOOL, Arg: "-nodes", ValueBool: enabled}
	return sb
}

/*
 *
 */
func (sb *selfSignedBuild) Build() SelfSigned {
    return SelfSigned{
		cmd:          OPENSSL,
		action:       ACTION,
		Description:  DESCRIPTION,
		NewkeyRSA:    sb.newkeyrsa,
		NewkeyDSA:    sb.newkeydsa,
		NewkeyEC:     sb.newkeyec,
		Digest:       sb.digest,
		Out:          sb.out,
		X509:         sb.x509,
		Days:         sb.days,
		NoDES:        sb.nodes,
	}
}

type SelfSigneder interface {
	String() string
}

type SelfSigned struct {
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
}

/*
 *
 */
func (ss *SelfSigned) String() string {
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
	
	return cmdline
}

func (ss *SelfSigned) Array() []string {
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
    
    return r
}


/***********************************************************/

/*
type Ossl interface {
    toArray() []string
    toString() string
}

type Opt struct {
    name     string
    key      string
    value    string
    required bool
}

type OsslPrivKey struct {
    //openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem
    // Description
    Description  string
    // OpenSSL standard command
    cmd          string
    newey        string
    x509         string
    digest       string
    days         int
    nodes        string
    passphrase   string
    out          string
}

type OsslSelfSignedCert struct {
    //openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem
    // Description
    Description  string
    // OpenSSL standard command
    Cmd          OptionAttr
    Newkey       string
    X509         string
    Digest       string
    Days         int
    Nodes        string
    Passphrase   string
    Out          OptionAttr

    ReqDescription    string
}

func NewSelfSignedCert() *OsslSelfSignedCert {
    ossc := new(OsslSelfSignedCert)
    ossc.Cmd = OptionAttr{Argname: "cmd", Value: "req", Valtype: "string", Required: true, Description: "request a certificate"}
    ossc.Description = "Create a self-signed certificate."
    ossc.ReqDescription = `Request a self-signed certificate.
It will create a private key file called priv.key and a certificate file called pubkey.crt.
You will notice no chain of trust in the certificate.`
    ossc.X509 = "-x509"
    ossc.Nodes = "-nodes"
    ossc.Out  = OptionAttr{Argname: "out", Value: "pubkey.crt", Valtype: "string", Required: false, Description: "name of certificate file"}
    
    return ossc
}

func (ossc *OsslSelfSignedCert) toArray() []string {
    r := []string{}
    r = append(r, OPENSSL)
    r = append(r, ossc.Cmd.Value)
    r = append(r, "-newkey")
    r = append(r, ossc.Newkey)
    r = append(r, ossc.X509)
    r = append(r, ossc.Nodes)
    r = append(r, "-" + ossc.Digest)
    r = append(r, "-days")
    r = append(r, strconv.Itoa(ossc.Days))
    r = append(r, "-out")
    r = append(r, ossc.Out.Value)
    
    return r
}

func (ossc *OsslSelfSignedCert) toString() string {
	return OPENSSL + " " + ossc.Cmd.Value +
	       " -newkey " + ossc.Newkey + ossc.X509 +
	       " -" + ossc.Digest +
	       " -days " + strconv.Itoa(ossc.Days) +
	       " -out " + ossc.Out
}
*/
