package main

import (
    "os"
    "bufio"
    "strings"
    "strconv"
    "fmt"

    "go-openssl/openssl"
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

/* @TODO
 */
func find(file string) string {
    return ""
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
func promptStr(reader *bufio.Reader, msg string) string {
    fmt.Print(msg)
    value, _ := reader.ReadString('\n')
    value = strings.TrimSuffix(value, "\n")
    return value
}

/*
 */
func promptInt(reader *bufio.Reader, msg string) int {
    for ;; {
        fmt.Print(msg)
        value, _ := reader.ReadString('\n')
        value = strings.TrimSuffix(value, "\n")
        valueInt, err := strconv.Atoi(value)
        if err == nil {
            return valueInt
        }
    }
}

/*
 */
func promptBool(reader *bufio.Reader, msg string) bool {
    for ;; {
        fmt.Print(msg)
        value, _ := reader.ReadString('\n')
        valueBool := strings.TrimSuffix(value, "\n")
        if valueBool == "y" {
            return true
        } else if valueBool == "n" {
            return false
        }
    }
}

/*
 */
func promptStrChoice(reader *bufio.Reader, msg string, choices ...string) string {
    for ;; {
        value := promptStr(reader, msg)
        if contains(value, choices) == true {
            return value
        }
    }
}

/*
 */
func chooseGoal(reader *bufio.Reader) int {
	for ;; {
        fmt.Println("What is your goal?")
        fmt.Println("[1] Create a self-signed certificate")
        fmt.Println("[2] Create a private key")
        fmt.Println("[3] View a private key")
        fmt.Println("[4] Create a root CA")
        fmt.Println("[5] Connect to secure url")
        goalChoiceNum := promptInt(reader, "Choose your goal [1-5]: ")
        if containsInt(goalChoiceNum, []int{1, 2, 3, 4, 5}) {
            return goalChoiceNum
        }
    }
}

/*
 */
func buildCertificateCert(reader *bufio.Reader) openssl.Certificate {
    fmt.Println("-- Creating certificate --")

	cert := openssl.NewCertificateBuilder()
    cert.X509(true)
    cert.NoDES(true)
    encryption := promptStrChoice(reader, "Enter encryption [rsa,dsa,ec]: ", "rsa", "dsa", "ec")
    switch encryption {
    case "rsa":
        cert.NewkeyRSA( promptInt(reader, "Enter RSA bit size: ") )
    case "dsa":
        cert.NewkeyDSA( promptStr(reader, "Enter DSA file: ") )
    case "ec":
        cert.NewkeyEC( promptStr(reader, "Enter EC file: ") )
    }
    cert.Digest( promptStr(reader, "Enter digest: ") )
    cert.Days( promptInt(reader, "Enter days: ") )
    cert.Out( promptStr(reader, "Enter output file: ") )

    return cert.Build()
}

/*
 */
func buildCreatePrivKey(reader *bufio.Reader) openssl.PrivKey {
    fmt.Println("-- Creating private key --")

	privkey := openssl.NewPrivKeyBuilder()
    privkey.Bits( promptInt(reader, "Enter bits size: ") )
    privkey.Digest( promptStr(reader, "Enter digest: ") )
    privkey.Seed( promptBool(reader, "Encrypt PEM output with cbc seed? [y/n]: ") )
    privkey.Out( promptStr(reader, "Enter output file: ") )

    return privkey.BuildCreate()
}

/*
 */
func buildViewPrivKey(reader *bufio.Reader) openssl.PrivKey {
    fmt.Println("-- Viewing private key --")

	privkey := openssl.NewPrivKeyBuilder()
    privkey.InFile( promptStr(reader, "Enter private key file: ") )
    privkey.NoOut( promptBool(reader, "Display? [y/n]: ") )
    privkey.Check( promptBool(reader, "Check? [y/n]: ") )
    privkey.Text( promptBool(reader, "Text? [y/n]: ") )
    
    return privkey.BuildView()
}

/* @TODO
 * @see https://jamielinux.com/docs/openssl-certificate-authority/create-the-root-pair.html
 */
func buildRootCA(reader *bufio.Reader, privkey *openssl.PrivKey) openssl.Certificate {
    fmt.Println("-- Creating CA certificate --")

	cert := openssl.NewCertificateBuilder()
    cert.X509(true)
    cert.NoDES(true)
    cert.New(true)
    if privkey.Out.IsUpdated {
        fmt.Printf("Enter private key file: %s\n", privkey.Out.Value)
        cert.Key(privkey.Out.Value)
    } else {
        cert.Key( promptStr(reader, "Enter private key file: ") )
    }
    cert.Config( promptStr(reader, "Enter config file: ") )
    cert.Extensions( promptStr(reader, "Enter extensions: ") )
    cert.Digest( promptStr(reader, "Enter digest: ") )
    cert.Days( promptInt(reader, "Enter days: ") )
    cert.Out( promptStr(reader, "Enter output file: ") )
    
    return cert.Build() 
}

/*
 */
func buildSClientConnect(reader *bufio.Reader) openssl.SClient {
    fmt.Println("-- Connecting to secure url --")

	sclient := openssl.NewSClientBuilder()
    hostname := promptStr(reader, "Enter url's hostname: ")
    sclient.Host(hostname)
    port := promptInt(reader, "Enter url's port: ")
    sclient.Port(port)
    sclient.Connect(hostname, port)
    
    return sclient.BuildConnect()
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
        cert := buildCertificateCert(reader)
        fmt.Println(cert.String())
        cert.Exec()
    case 2:
        privkey := buildCreatePrivKey(reader)
        fmt.Println(privkey.String())
        privkey.Exec()
    case 3:
        privkey := buildViewPrivKey(reader)
        fmt.Println(privkey.String())
        privkey.Exec()
    case 4:
        privkey := buildCreatePrivKey(reader)
        pkerr := privkey.Exec()
        if pkerr == nil {
            cacert := buildRootCA(reader, &privkey)
            fmt.Println(cacert.String())
            cacert.Exec()
        } else {
            fmt.Printf("Error creating private key: %s\n", pkerr)
        }
    case 5:
        sclient := buildSClientConnect(reader)
        fmt.Println(sclient.String())
        sclient.Exec()
    }

    os.Exit(RET_SUCCESS)
}
