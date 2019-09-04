package openssl

import (
    "os"
    "os/exec"
    "strconv"
)

type IntermediateCABuilder interface {
    NewkeyRSA(int)     IntermediateCABuilder
    NewkeyDSA(string)  IntermediateCABuilder
    NewkeyEC(string)   IntermediateCABuilder
    Digest(string)     IntermediateCABuilder
    Out(string)        IntermediateCABuilder
    X509(bool)         IntermediateCABuilder
    Days(int)          IntermediateCABuilder
    NoDES(bool)        IntermediateCABuilder
    
    Build()            IntermediateCA            
}

type intermediateCABuild struct {
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
func NewIntermediateCABuilder() IntermediateCABuilder {
	return &intermediateCABuild{}
}

/*
 *
 */
func (sb *intermediateCABuild) NewkeyRSA(bits int) IntermediateCABuilder {
	sb.newkeyrsa = Attribute{Native: INT, IsUpdated: true, Arg: "-newkey", Prepend: "rsa:", ValueInt: bits}
	return sb
}

/*
 *
 */
func (sb *intermediateCABuild) NewkeyDSA(file string) IntermediateCABuilder {
	sb.newkeydsa = Attribute{Native: STRING, IsUpdated: true, Arg: "-newkey", Prepend: "dsa:", Value: file}
	return sb
}

/*
 *
 */
func (sb *intermediateCABuild) NewkeyEC(file string) IntermediateCABuilder {
	sb.newkeyec = Attribute{Native: STRING, IsUpdated: true, Arg: "-newkey", Prepend: "ec:", Value: file}
	return sb
}

/*
 *
 */
func (sb *intermediateCABuild) Digest(digest string) IntermediateCABuilder {
	sb.digest = Attribute{Native: STRING, IsUpdated: true, Prepend: "-", Value: digest}
	return sb
}

/*
 *
 */
func (sb *intermediateCABuild) Out(file string) IntermediateCABuilder {
	sb.out = Attribute{Native: STRING, IsUpdated: true, Arg: "-out", Value: file}
	return sb
}

/*
 *
 */
func (sb *intermediateCABuild) X509(enabled bool) IntermediateCABuilder {
	sb.x509 = Attribute{Native: BOOL, IsUpdated: true, Arg: "-x509", ValueBool: enabled}
	return sb
}

/*
 *
 */
func (sb *intermediateCABuild) Days(days int) IntermediateCABuilder {
	sb.days = Attribute{Native: INT, IsUpdated: true, Arg: "-days", ValueInt: days}
	return sb
}

/*
 *
 */
func (sb *intermediateCABuild) NoDES(enabled bool) IntermediateCABuilder {
	sb.nodes = Attribute{Native: BOOL, IsUpdated: true, Arg: "-nodes", ValueBool: enabled}
	return sb
}

/*
 *
 */
func (sb *intermediateCABuild) Build() IntermediateCA {
    return IntermediateCA{
		cmd:          OPENSSL,
		action:       "genrsa",
		Description:  "Create intermediate certificate",
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

type IntermediateCA struct {
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
func (ss *IntermediateCA) String() string {
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

func (ss *IntermediateCA) Array() []string {
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

func (ss *IntermediateCA) Exec() error {
	r := ss.Array()
    c, args := r[0], r[1:]
    cmd := exec.Command(c, args...)
    cmd.Stdout = os.Stdout
    cmd.Stdin = os.Stdin
    cmd.Stderr = os.Stderr
    
    return cmd.Run()
}


