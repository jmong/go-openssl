package openssl

import (
    "os"
    "os/exec"
    "strconv"
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
    Key(string)        SelfSignedBuilder
    Extensions(string) SelfSignedBuilder
    Config(string)     SelfSignedBuilder
    New(bool)          SelfSignedBuilder
    
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
    key        Attribute
    extensions Attribute
    config     Attribute
    new        Attribute
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
	sb.newkeyrsa = Attribute{Native: INT, IsUpdated: true, Arg: "-newkey", Prepend: "rsa:", ValueInt: bits}
	return sb
}

/*
 *
 */
func (sb *selfSignedBuild) NewkeyDSA(file string) SelfSignedBuilder {
	sb.newkeydsa = Attribute{Native: STRING, IsUpdated: true, Arg: "-newkey", Prepend: "dsa:", Value: file}
	return sb
}

/*
 *
 */
func (sb *selfSignedBuild) NewkeyEC(file string) SelfSignedBuilder {
	sb.newkeyec = Attribute{Native: STRING, IsUpdated: true, Arg: "-newkey", Prepend: "ec:", Value: file}
	return sb
}

/*
 *
 */
func (sb *selfSignedBuild) Digest(digest string) SelfSignedBuilder {
	sb.digest = Attribute{Native: STRING, IsUpdated: true, Prepend: "-", Value: digest}
	return sb
}

/*
 *
 */
func (sb *selfSignedBuild) Out(file string) SelfSignedBuilder {
	sb.out = Attribute{Native: STRING, IsUpdated: true, Arg: "-out", Value: file}
	return sb
}

/*
 *
 */
func (sb *selfSignedBuild) X509(enabled bool) SelfSignedBuilder {
	sb.x509 = Attribute{Native: BOOL, IsUpdated: true, Arg: "-x509", ValueBool: enabled}
	return sb
}

/*
 *
 */
func (sb *selfSignedBuild) Days(days int) SelfSignedBuilder {
	sb.days = Attribute{Native: INT, IsUpdated: true, Arg: "-days", ValueInt: days}
	return sb
}

/*
 *
 */
func (sb *selfSignedBuild) NoDES(enabled bool) SelfSignedBuilder {
	sb.nodes = Attribute{Native: BOOL, IsUpdated: true, Arg: "-nodes", ValueBool: enabled}
	return sb
}

/*
 *
 */
func (sb *selfSignedBuild) Key(file string) SelfSignedBuilder {
	sb.key = Attribute{Native: STRING, IsUpdated: true, Arg: "-key", Value: file}
	return sb
}

/*
 *
 */
func (sb *selfSignedBuild) Extensions(certext string) SelfSignedBuilder {
	sb.extensions = Attribute{Native: STRING, IsUpdated: true, Arg: "-extensions", Value: certext}
	return sb
}

/*
 *
 */
func (sb *selfSignedBuild) Config(file string) SelfSignedBuilder {
	sb.config = Attribute{Native: STRING, IsUpdated: true, Arg: "-config", Value: file}
	return sb
}

/*
 *
 */
func (sb *selfSignedBuild) New(isnew bool) SelfSignedBuilder {
	sb.new = Attribute{Native: BOOL, IsUpdated: true, Arg: "-new", ValueBool: isnew}
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
        Key:          sb.key,
        Extensions:   sb.extensions,
        Config:       sb.config,
        New:          sb.new,
	}
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
    Key          Attribute
    Extensions   Attribute
    Config       Attribute
    New          Attribute
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
    if ss.Key.IsSet() {
		cmdline = cmdline + " " + ss.Key.Arg + ss.Key.Value
	}
    if ss.Extensions.IsSet() {
		cmdline = cmdline + " " + ss.Extensions.Arg + ss.Extensions.Value
	}
    if ss.Config.IsSet() {
		cmdline = cmdline + " " + ss.Config.Arg + ss.Config.Value
	}
    if ss.New.IsSet() {
		cmdline = cmdline + " " + ss.New.Arg
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

func (ss *SelfSigned) Exec() error {
	r := ss.Array()
    c, args := r[0], r[1:]
    cmd := exec.Command(c, args...)
    cmd.Stdout = os.Stdout
    cmd.Stdin = os.Stdin
    cmd.Stderr = os.Stderr
    
    return cmd.Run()
}


