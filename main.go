package main

import (
    "os"
    "os/exec"
//    "io"
    "bufio"
    "strings"
//    "runtime"
//    "log"
    "strconv"
    "fmt"
)

const (
    RET_SUCCESS = 0
    RET_ERROR   = 1
)

/*
 */
func isFile(file string) bool {
    info, err := os.Stat(file)
    if os.IsNotExist(err) {
        return false
    }
    return !info.IsDir()
}

/*
 */
func chooseGoal(reader *bufio.Reader) int {
	for ;; {
        fmt.Println("What is your goal?")
        fmt.Println("[1] Create a self-signed certificate")
        fmt.Print("Choose your goal [1-4]: ")
        goalChoice, _ := reader.ReadString('\n')
        goalChoice = strings.TrimSuffix(goalChoice, "\n")
        goalChoiceNum, _ := strconv.Atoi(goalChoice)
        if goalChoiceNum == 1 || goalChoiceNum == 2 {
            return goalChoiceNum
        }
    }
}

/*
 */
func buildSelfSignedCert(reader *bufio.Reader) SelfSigned {
    var value string

	selfsigned := NewSelfSignedBuilder()

    selfSigned.X509(true)
    selfSigned.NoDES(true)

    fmt.Print("Enter RSA bit size: ")
    value, _ = reader.ReadString('\n')
    value = strings.TrimSuffix(value, "\n")
    newkeyrsa, _ := strconv.Atoi(value)
    selfsigned.NewkeyRSA(newkeyrsa)

    fmt.Print("Enter digest: ")
    value, _ = reader.ReadString('\n')
    selfsigned.Digest(strings.TrimSuffix(value, "\n"))

    fmt.Print("Enter days: ")
    value, _ = reader.ReadString('\n')
    value = strings.TrimSuffix(value, "\n")
    days, _ := strconv.Atoi(value)
    selfsigned.Days(days)

    fmt.Print("Enter output file: ")
    value, _ = reader.ReadString('\n')
    selfsigned.Out(strings.TrimSuffix(value, "\n"))
    
    return selfsigned.Build()
}

/*
 */
func runCmd(args ...string) error {
    c, args := args[0], args[1:]
    cmd := exec.Command(c, args...)
    cmd.Stdout = os.Stdout
    cmd.Stdin = os.Stdin
    cmd.Stderr = os.Stderr
    return cmd.Run()
}

/*
 */
func main() {
    if ret := isFile(OPENSSL); ret == false {
        fmt.Printf("Error, %s command is not found", OPENSSL)
        os.Exit(RET_ERROR)
    }
    
    reader := bufio.NewReader(os.Stdin)

    switch goal := chooseGoal(reader); goal {
	case 1:
        selfsigned := buildSelfSignedCert(reader)
        fmt.Println(selfsigned.String())
        arr := selfsigned.Array()
        runCmd(arr...)
    }

    os.Exit(RET_SUCCESS)
}
