package openssl

import (
    "os"
    "os/exec"
    "strings"
)

type CSRBuilder interface {
    NewkeyRSA(int)     CSRBuilder
    NewkeyDSA(string)  CSRBuilder
    NewkeyEC(string)   CSRBuilder
    Digest(string)     CSRBuilder
    In(string)         CSRBuilder
    Out(string)        CSRBuilder
    Days(int)          CSRBuilder
    NoDES(bool)        CSRBuilder
    Key(string)        CSRBuilder
    Extensions(string) CSRBuilder
    Config(string)     CSRBuilder
    New(bool)          CSRBuilder
    Text(bool)         CSRBuilder
    NoOut(bool)        CSRBuilder
    Extra(string)      CSRBuilder
    
    BuildCreate()      CSR
    BuildView()        CSR            
}

type CSRBuild struct {
    newkeyrsa  Attribute
    newkeydsa  Attribute
    newkeyec   Attribute
    digest     Attribute
    in         Attribute
    out        Attribute
    days       Attribute
    nodes      Attribute
    key        Attribute
    extensions Attribute
    config     Attribute
    new        Attribute
    text       Attribute
    noout      Attribute
    extra      Attribute
}

/*
 *
 */
func NewCSRBuilder() CSRBuilder {
	return &CSRBuild{}
}

/*
 *
 */
func (sb *CSRBuild) NewkeyRSA(bits int) CSRBuilder {
	sb.newkeyrsa = Attribute{Native: INT, IsUpdated: true, Arg: "-newkey", Prepend: "rsa:", ValueInt: bits}
	return sb
}

/*
 *
 */
func (sb *CSRBuild) NewkeyDSA(file string) CSRBuilder {
	sb.newkeydsa = Attribute{Native: STRING, IsUpdated: true, Arg: "-newkey", Prepend: "dsa:", Value: file}
	return sb
}

/*
 *
 */
func (sb *CSRBuild) NewkeyEC(file string) CSRBuilder {
	sb.newkeyec = Attribute{Native: STRING, IsUpdated: true, Arg: "-newkey", Prepend: "ec:", Value: file}
	return sb
}

/*
 *
 */
func (sb *CSRBuild) Digest(digest string) CSRBuilder {
	sb.digest = Attribute{Native: STRING, IsUpdated: true, Prepend: "-", Value: digest}
	return sb
}

/*
 *
 */
func (sb *CSRBuild) In(file string) CSRBuilder {
	sb.in = Attribute{Native: STRING, IsUpdated: true, Arg: "-in", Value: file}
	return sb
}

/*
 *
 */
func (sb *CSRBuild) Out(file string) CSRBuilder {
	sb.out = Attribute{Native: STRING, IsUpdated: true, Arg: "-out", Value: file}
	return sb
}

/*
 *
 */
func (sb *CSRBuild) Days(days int) CSRBuilder {
	sb.days = Attribute{Native: INT, IsUpdated: true, Arg: "-days", ValueInt: days}
	return sb
}

/*
 *
 */
func (sb *CSRBuild) NoDES(enabled bool) CSRBuilder {
	sb.nodes = Attribute{Native: BOOL, IsUpdated: true, Arg: "-nodes", ValueBool: enabled}
	return sb
}

/*
 *
 */
func (sb *CSRBuild) Key(file string) CSRBuilder {
	sb.key = Attribute{Native: STRING, IsUpdated: true, Arg: "-key", Value: file}
	return sb
}

/*
 *
 */
func (sb *CSRBuild) Extensions(certext string) CSRBuilder {
	sb.extensions = Attribute{Native: STRING, IsUpdated: true, Arg: "-extensions", Value: certext}
	return sb
}

/*
 *
 */
func (sb *CSRBuild) Config(file string) CSRBuilder {
	sb.config = Attribute{Native: STRING, IsUpdated: true, Arg: "-config", Value: file}
	return sb
}

/*
 *
 */
func (sb *CSRBuild) New(isnew bool) CSRBuilder {
	sb.new = Attribute{Native: BOOL, IsUpdated: true, Arg: "-new", ValueBool: isnew}
	return sb
}

/*
 *
 */
func (sb *CSRBuild) Text(istext bool) CSRBuilder {
	sb.text = Attribute{Native: BOOL, IsUpdated: true, Arg: "-text", ValueBool: istext}
	return sb
}

/*
 *
 */
func (sb *CSRBuild) NoOut(isnoout bool) CSRBuilder {
	sb.noout = Attribute{Native: BOOL, IsUpdated: true, Arg: "-noout", ValueBool: isnoout}
	return sb
}

/*
 *
 */
func (sb *CSRBuild) Extra(args string) CSRBuilder {
	sb.extra = Attribute{Native: STRING, IsUpdated: true, Value: args}
	return sb
}

/*
 *
 */
func (sb *CSRBuild) BuildCreate() CSR {
    arr := []string{Cmd, "req"}
    arr = append(arr, toArray(true, sb.newkeyrsa, sb.newkeydsa, sb.newkeyec,
                 sb.digest, sb.out, sb.days, sb.nodes, 
                 sb.key, sb.extensions, sb.config, sb.new, sb.extra)...)
    
    return CSR{
        cmd:          Cmd,
        action:       "req",
        array:        arr,
        Description:  "Create certificate",
        NewkeyRSA:    sb.newkeyrsa,
        NewkeyDSA:    sb.newkeydsa,
        NewkeyEC:     sb.newkeyec,
        Digest:       sb.digest,
        Out:          sb.out,
        Days:         sb.days,
        NoDES:        sb.nodes,
        Key:          sb.key,
        Extensions:   sb.extensions,
        Config:       sb.config,
        New:          sb.new,
        Extra:        sb.extra,
    }
}

/*
 *
 */
func (sb *CSRBuild) BuildView() CSR {
    arr := []string{Cmd, "req"}
    arr = append(arr, toArray(true, sb.in, sb.text, sb.noout, sb.extra)...)
    
    return CSR{
        cmd:          Cmd,
        action:       "req",
        array:        arr,
        Description:  "View CSR",
        In:           sb.in,
        Text:         sb.text,
        NoOut:        sb.noout,
        Extra:        sb.extra,
    }
}

type CSR struct {
    cmd          string
    action       string
    array        []string
    Description  string
    NewkeyRSA    Attribute
    NewkeyDSA    Attribute
    NewkeyEC     Attribute
    Digest       Attribute
    In           Attribute
    Out          Attribute
    Days         Attribute
    NoDES        Attribute
    Key          Attribute
    Extensions   Attribute
    Config       Attribute
    New          Attribute
    Text         Attribute
    NoOut        Attribute
    Extra        Attribute
}

/*
 *
 */
func (ss *CSR) String() string {
    return strings.Join(ss.array, " ")
}

/*
 *
 */
func (ss *CSR) Array() []string {
    return ss.array
}

/*
 */
func (ss *CSR) Exec() error {
	r := ss.Array()
    c, args := r[0], r[1:]
    cmd := exec.Command(c, args...)
    cmd.Stdout = os.Stdout
    cmd.Stdin = os.Stdin
    cmd.Stderr = os.Stderr
    
    return cmd.Run()
}


