package openssl

import (
    "os"
    "os/exec"
    "strings"
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
    Extra(string)      IntermediateCABuilder
    
    BuildCreate()      IntermediateCA            
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
    extra      Attribute
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
func (sb *intermediateCABuild) Extra(args string) IntermediateCABuilder {
	sb.extra = Attribute{Native: STRING, IsUpdated: true, Value: args}
	return sb
}

/*
 *
 */
func (sb *intermediateCABuild) BuildCreate() IntermediateCA {
    arr := []string{Cmd, "genrsa"}
    arr = append(arr, toArray(true, sb.newkeyrsa, sb.newkeydsa, sb.newkeyec,
                 sb.digest, sb.out, sb.x509, sb.days, sb.nodes, sb.extra)...)
    
    return IntermediateCA{
		cmd:          Cmd,
		action:       "genrsa",
        array:        arr,
		Description:  "Create intermediate certificate",
		NewkeyRSA:    sb.newkeyrsa,
		NewkeyDSA:    sb.newkeydsa,
		NewkeyEC:     sb.newkeyec,
		Digest:       sb.digest,
		Out:          sb.out,
		X509:         sb.x509,
		Days:         sb.days,
		NoDES:        sb.nodes,
        Extra:        sb.extra,
	}
}

type IntermediateCA struct {
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
    Extra        Attribute
}

/*
 *
 */
func (sb *IntermediateCA) String() string {
    return strings.Join(sb.array, " ")
}

/*
 *
 */
func (sb *IntermediateCA) Array() []string {
    return sb.array
}

func (sb *IntermediateCA) Exec() error {
	r := sb.Array()
    c, args := r[0], r[1:]
    cmd := exec.Command(c, args...)
    cmd.Stdout = os.Stdout
    cmd.Stdin = os.Stdin
    cmd.Stderr = os.Stderr
    
    return cmd.Run()
}


