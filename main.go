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

var (
    cert     openssl.Certificate
    privkey  openssl.PrivKey
    sclient  openssl.SClient
    csr      openssl.CSR
)

/* Checks if a file exists.
 * @param file To check
 * @return True if the file exists or else false
 */
func isFileExist(file string) bool {
    info, err := os.Stat(file)
    if os.IsNotExist(err) {
        return false
    }
    return !info.IsDir()
}

/* Find fullpath to a file.
 * @param file To find
 * @param paths Set of directories to find the file in 
 * @param delim Separator between each directory in {paths}
 * @return Fullpath to file or "" if not found
 */
func whichFile(file string, paths string, delim string) string {
    envpaths := strings.Split(paths, delim)
    for _, envpath := range envpaths {
        filepath := envpath + "/" + file
        if isFileExist(filepath) == true {
            return filepath
        }
    }

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
func chooseTask(reader *bufio.Reader) int {
	for ;; {
        fmt.Println("What do you want to do?")
        fmt.Println("[1] Create a TLS Certificate")
        fmt.Println("[2] Create a Private Key")
        fmt.Println("[3] View a Private Key")
        fmt.Println("[4] Create a Root CA")
        fmt.Println("[5] Connect to Secure URL")
        fmt.Println("[6] Create a CSR")
        fmt.Println("[7] View a CSR")
        taskNum := promptInt(reader, "Choose your task [1-7]: ")
        if containsInt(taskNum, []int{1, 2, 3, 4, 5, 6, 7}) {
            return taskNum
        }
    }
}

/*
 */
func main() {
    var goal int

    openssl.Cmd = whichFile("openssl", os.Getenv("PATH"), ":")
//    fmt.Printf("[Debug] openssl cmd = %s\n", openssl.Cmd)
    if openssl.Cmd == "" {
        fmt.Printf("Error, %s command is not found", openssl.Cmd)
        os.Exit(RET_ERROR)
    }

    reader := bufio.NewReader(os.Stdin)

    switch goal = chooseTask(reader); goal {
    case 1:
        cert = buildCertificateCreate(reader)
        fmt.Println(cert.String())
        cert.Exec()
    case 2:
        privkey = buildPrivKeyCreate(reader)
        fmt.Println(privkey.String())
        privkey.Exec()
    case 3:
        privkey = buildPrivKeyView(reader)
        fmt.Println(privkey.String())
        privkey.Exec()
    case 4:
        privkey = buildPrivKeyCreate(reader)
        pkerr := privkey.Exec()
        if pkerr == nil {
            cacert := buildRootCACreate(reader, &privkey)
            fmt.Println(cacert.String())
            cacert.Exec()
        } else {
            fmt.Printf("Error creating private key: %s\n", pkerr)
        }
    case 5:
        sclient = buildSClientConnect(reader)
        fmt.Println(sclient.String())
        sclient.Exec()
    case 6:
        csr = buildCSRCreate(reader)
        fmt.Println(csr.String())
        csr.Exec()
    case 7:
        csr = buildCSRView(reader)
        fmt.Println(csr.String())
        csr.Exec()
    }

    os.Exit(RET_SUCCESS)
}
