package openssl

import (
    "os"
    "os/exec"
    "strconv"
)

type PrivKeyBuilder interface {
    Bits(int)       PrivKeyBuilder
    Digest(string)  PrivKeyBuilder
    Out(string)     PrivKeyBuilder
    Seed(bool)      PrivKeyBuilder

    Build()         PrivKey
}

type privKeyBuild struct {
    bits    Attribute
    digest  Attribute
    out     Attribute
    seed    Attribute
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
func (sb *privKeyBuild) Build() PrivKey {
    return PrivKey{
		cmd:          OPENSSL,
		action:       "genrsa",
		Description:  DESCRIPTION,
        Bits:         sb.bits,
		Digest:       sb.digest,
		Out:          sb.out,
		Seed:         sb.seed,
	}
}

type PrivKey struct {
    cmd          string
    action       string
    Description  string
    Bits         Attribute
    Digest       Attribute
    Out          Attribute
    Seed         Attribute
}

/*
 *
 */
func (ss *PrivKey) String() string {
	cmdline := ss.cmd + " " + ss.action + " "
	if ss.Digest.IsSet() {
		cmdline = cmdline + " " + ss.Digest.Prepend + ss.Digest.Value
	}
	if ss.Out.IsSet() {
		cmdline = cmdline + " " + ss.Out.Arg + " " + ss.Out.Value
	}
	if ss.Seed.IsSet() {
		cmdline = cmdline + " " + ss.Seed.Arg
	}
    cmdline = cmdline + " " + strconv.Itoa(ss.Bits.ValueInt)

	return cmdline
}

func (ss *PrivKey) Array() []string {
    r := []string{}
    r = append(r, ss.cmd)
    r = append(r, ss.action)
    if ss.Digest.IsSet() {
		r = append(r, ss.Digest.Prepend + ss.Digest.Value)
	}
    if ss.Out.IsSet() {
		r = append(r, ss.Out.Arg)
		r = append(r, ss.Out.Value)
	}
	if ss.Seed.IsSet() {
		r = append(r, ss.Seed.Arg)
	}
    r = append(r, strconv.Itoa(ss.Bits.ValueInt))

    return r
}

func (ss *PrivKey) Exec() error {
	r := ss.Array()
    c, args := r[0], r[1:]
    cmd := exec.Command(c, args...)
    cmd.Stdout = os.Stdout
    cmd.Stdin = os.Stdin
    cmd.Stderr = os.Stderr

    return cmd.Run()
}


