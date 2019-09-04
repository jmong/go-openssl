package main

import (
    "os"
//    "os/exec"
//    "io"
    "bufio"
    "strings"
//    "runtime"
//    "log"
    "strconv"
    "fmt"

    "learn-by-demo-ssl/openssl"
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
 * 
 */
func contains(needle string, haystack []string) bool {
    for _, v := range haystack {
        if v == needle {
            return true
        }
    }
    return false
}

/*
 * 
 */
func containsInt(needle int, haystack []int) bool {
    for _, v := range haystack {
        if v == needle {
            return true
        }
    }
    return false
}

/*
 */
func chooseGoal(reader *bufio.Reader) int {
	for ;; {
        fmt.Println("What is your goal?")
        fmt.Println("[1] Create a self-signed certificate")
        fmt.Println("[2] Create a private key")
        fmt.Println("[3] Create a root CA")
        fmt.Print("Choose your goal [1-4]: ")
        goalChoice, _ := reader.ReadString('\n')
        goalChoice = strings.TrimSuffix(goalChoice, "\n")
        goalChoiceNum, _ := strconv.Atoi(goalChoice)
        if containsInt(goalChoiceNum, []int{1, 2, 3}) {
            return goalChoiceNum
        }
    }
}

/*
 */
func buildSelfSignedCert(reader *bufio.Reader) openssl.SelfSigned {
    var value string

	selfsigned := openssl.NewSelfSignedBuilder()

    selfsigned.X509(true)
    selfsigned.NoDES(true)

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
func buildPrivKey(reader *bufio.Reader) openssl.PrivKey {
    var value string

	privkey := openssl.NewPrivKeyBuilder()

    fmt.Print("Enter bits size: ")
    value, _ = reader.ReadString('\n')
    value = strings.TrimSuffix(value, "\n")
    bits, _ := strconv.Atoi(value)
    privkey.Bits(bits)

    fmt.Print("Enter digest: ")
    value, _ = reader.ReadString('\n')
    privkey.Digest(strings.TrimSuffix(value, "\n"))

    fmt.Print("Encrypt PEM output with cbc seed? [y/n]: ")
    value, _ = reader.ReadString('\n')
    switch strings.TrimSuffix(value, "\n") {
    case "y":
        privkey.Seed(true)
    default:
        privkey.Seed(false)
    }

    fmt.Print("Enter output file: ")
    value, _ = reader.ReadString('\n')
    privkey.Out(strings.TrimSuffix(value, "\n"))
    
    return privkey.Build()
}

/* @TODO
 * 
 */
func buildRootCA(reader *bufio.Reader, privkey *openssl.PrivKey) {
    var value string

	selfsigned := openssl.NewSelfSignedBuilder()

    selfsigned.X509(true)
    selfsigned.NoDES(true)

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
func main() {
	var goal int
	
    if ret := isFile(openssl.OPENSSL); ret == false {
        fmt.Printf("Error, %s command is not found", openssl.OPENSSL)
        os.Exit(RET_ERROR)
    }

    reader := bufio.NewReader(os.Stdin)

    switch goal = chooseGoal(reader); goal {
	case 1:
        selfsigned := buildSelfSignedCert(reader)
        fmt.Println(selfsigned.String())
        selfsigned.Exec()
    case 2:
        privkey := buildPrivKey(reader)
        fmt.Println(privkey.String())
        privkey.Exec()
    case 3:
        privkey := buildPrivKey(reader)
        buildRootCA(reader, &privkey)
    }

    os.Exit(RET_SUCCESS)
}
