package openssl

import (
    "os"
    "os/exec"
//    "strconv"
    "strings"
)

type PrivKeyBuilder interface {
    Digest(string)  PrivKeyBuilder
    Out(string)     PrivKeyBuilder
    Seed(bool)      PrivKeyBuilder
    In(string)      PrivKeyBuilder
    NoOut(bool)     PrivKeyBuilder
    Check(bool)     PrivKeyBuilder
    Text(bool)      PrivKeyBuilder
    Bits(int)       PrivKeyBuilder
    InFile(string)  PrivKeyBuilder

    BuildCreate()   PrivKey
    BuildView()     PrivKey
}

type privKeyBuild struct {
    digest  Attribute
    out     Attribute
    seed    Attribute
    in      Attribute
    noout   Attribute
    check   Attribute
    text    Attribute
    bits    Attribute
    infile  Attribute
}

/*
 *
 */
func NewPrivKeyBuilder() PrivKeyBuilder {
	return &privKeyBuild{}
}

/*
 *
 */
func (sb *privKeyBuild) Bits(size int) PrivKeyBuilder {
	sb.bits = Attribute{Native: INT, IsUpdated: true, ValueInt: size}
	return sb
}

/*
 *
 */
func (sb *privKeyBuild) InFile(file string) PrivKeyBuilder {
	sb.infile = Attribute{Native: STRING, IsUpdated: true, Arg: "-in", Value: file}
	return sb
}

/*
 *
 */
func (sb *privKeyBuild) Digest(digest string) PrivKeyBuilder {
	sb.digest = Attribute{Native: STRING, IsUpdated: true, Prepend: "-", Value: digest}
	return sb
}

/*
 *
 */
func (sb *privKeyBuild) Out(file string) PrivKeyBuilder {
	sb.out = Attribute{Native: STRING, IsUpdated: true, Arg: "-out", Value: file}
	return sb
}

/*
 *
 */
func (sb *privKeyBuild) Seed(enabled bool) PrivKeyBuilder {
	sb.seed = Attribute{Native: BOOL, IsUpdated: true, Arg: "-seed", ValueBool: enabled}
	return sb
}

/*
 *
 */
func (sb *privKeyBuild) In(file string) PrivKeyBuilder {
	sb.in = Attribute{Native: STRING, IsUpdated: true, Arg: "-in", Value: file}
	return sb
}

/*
 *
 */
func (sb *privKeyBuild) NoOut(enabled bool) PrivKeyBuilder {
	sb.noout = Attribute{Native: BOOL, IsUpdated: true, Arg: "-noout", ValueBool: enabled}
	return sb
}

/*
 *
 */
func (sb *privKeyBuild) Check(enabled bool) PrivKeyBuilder {
	sb.check = Attribute{Native: BOOL, IsUpdated: true, Arg: "-check", ValueBool: enabled}
	return sb
}

/*
 *
 */
func (sb *privKeyBuild) Text(enabled bool) PrivKeyBuilder {
	sb.text = Attribute{Native: BOOL, IsUpdated: true, Arg: "-text", ValueBool: enabled}
	return sb
}

/*
 *
 */
func (sb *privKeyBuild) BuildCreate() PrivKey {
    arr := []string{OPENSSL, "genrsa"}
    arr = append(arr, toArray(true, sb.bits, sb.digest, sb.out, sb.seed)...) 
    
    return PrivKey{
		cmd:          OPENSSL,
		action:       "genrsa",
        array:        arr,
		Description:  "Create private key",
        Bits:         sb.bits,
		Digest:       sb.digest,
		Out:          sb.out,
		Seed:         sb.seed,
	}
}

/*
 *
 */
func (sb *privKeyBuild) BuildView() PrivKey {
    arr := []string{OPENSSL, "rsa"}
    arr = append(arr, toArray(true, sb.infile, sb.noout, sb.check, sb.text)...) 
    
    return PrivKey{
		cmd:          OPENSSL,
		action:       "rsa",
        array:        arr,
		Description:  "View private key",
        InFile:       sb.infile,
        In:           sb.in,
        NoOut:        sb.noout,
        Check:        sb.check,
        Text:         sb.text,
	}
}

type PrivKey struct {
    cmd          string
    action       string
    array        []string
    Description  string
    Digest       Attribute
    Out          Attribute
    Seed         Attribute
    In           Attribute
    NoOut        Attribute
    Check        Attribute
    Text         Attribute
    Bits         Attribute
    InFile       Attribute
}

/*
 *
 */
func (ss *PrivKey) String() string {    
    return strings.Join(ss.array, " ") 
}

/*
 *
 */
func (ss *PrivKey) Array() []string {
    return ss.array
}

/*
 *
 */
func (ss *PrivKey) Exec() error {
	r := ss.Array()
    c, args := r[0], r[1:]
    cmd := exec.Command(c, args...)
    cmd.Stdout = os.Stdout
    cmd.Stdin = os.Stdin
    cmd.Stderr = os.Stderr

    return cmd.Run()
}



