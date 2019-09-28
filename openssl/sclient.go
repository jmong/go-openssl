package openssl

import (
    "os"
    "os/exec"
    "strconv"
    "strings"
)

type SClientBuilder interface {
    Host(string)          SClientBuilder
    Port(int)             SClientBuilder
    Connect(string, int)  SClientBuilder
    Extra(string)         SClientBuilder

    BuildConnect()   SClient
}

type SClientBuild struct {
    host        Attribute
    port        Attribute
    connectOpt  Attribute
    extra       Attribute
}

/*
 *
 */
func NewSClientBuilder() SClientBuilder {
    return &SClientBuild{}
}

/*
 *
 */
func (sb *SClientBuild) Port(port int) SClientBuilder {
    sb.port = Attribute{Native: INT, IsUpdated: true, ValueInt: port}
    return sb
}

/*
 *
 */
func (sb *SClientBuild) Host(hostname string) SClientBuilder {
    sb.host = Attribute{Native: STRING, IsUpdated: true, Value: hostname}
    return sb
}

/*
 *
 */
func (sb *SClientBuild) Connect(hostname string, port int) SClientBuilder {
    conn := hostname + ":" + strconv.Itoa(port)
    sb.connectOpt = Attribute{Native: STRING, IsUpdated: true, Arg: "-connect", Value: conn}
    return sb
}

/*
 *
 */
func (sb *SClientBuild) Extra(args string) SClientBuilder {
    sb.extra = Attribute{Native: STRING, IsUpdated: true, Value: args}
    return sb
}

/*
 *
 */
func (sb *SClientBuild) BuildConnect() SClient {
    arr := []string{Cmd, "s_client"}
    arr = append(arr, toArray(true, sb.connectOpt, sb.extra)...)

    return SClient{
	cmd:          Cmd,
	action:       "s_client",
        array:        arr,
	Description:  "Connect to secure url",
        Host:         sb.host,
	Port:         sb.port,
        Connect:      sb.connectOpt,
        Extra:        sb.extra,
    }
}

type SClient struct {
    cmd          string
    action       string
    array        []string
    Description  string
    Port         Attribute
    Host         Attribute
    Connect      Attribute
    Extra        Attribute
}

/*
 *
 */
func (ss *SClient) String() string {
    return strings.Join(ss.array, " ")
}

/*
 *
 */
func (ss *SClient) Array() []string {
    return ss.array
}

/*
 *
 */
func (ss *SClient) Exec() error {
    r := ss.Array()
    c, args := r[0], r[1:]
    cmd := exec.Command(c, args...)
    cmd.Stdout = os.Stdout
    cmd.Stdin = os.Stdin
    cmd.Stderr = os.Stderr

    return cmd.Run()
}

