package main

import (
    "bufio"
    "fmt"

    "go-openssl/openssl"
)

/*
 */
func buildCSRCreate(reader *bufio.Reader) openssl.CSR {
    fmt.Println("-- Creating CSR --")

    csr := openssl.NewCSRBuilder()
    csr.NoDES(true)
    encryption := promptStrChoice(reader, "Enter encryption [rsa,dsa,ec]: ", "rsa", "dsa", "ec")
    switch encryption {
    case "rsa":
        csr.NewkeyRSA( promptInt(reader, "Enter RSA bit size: ") )
    case "dsa":
        csr.NewkeyDSA( promptStr(reader, "Enter DSA file: ") )
    case "ec":
        csr.NewkeyEC( promptStr(reader, "Enter EC file: ") )
    }
    csr.Digest( promptStr(reader, "Enter digest: ") )
    csr.Days( promptInt(reader, "Enter days: ") )
    csr.Out( promptStr(reader, "Enter output file: ") )

    return csr.BuildCreate()
}

/*
 */
func buildCSRView(reader *bufio.Reader) openssl.CSR {
    fmt.Println("-- Viewing CSR --")

    csr := openssl.NewCSRBuilder()
    csr.In( promptStr(reader, "Enter CSR file: ") )
    csr.Text( promptBool(reader, "To Text? [y/n]: ") )
    csr.NoOut( promptBool(reader, "Show the request? [y/n]: ") )

    return csr.BuildView()
}

/*
 */
func buildCertificateCreate(reader *bufio.Reader) openssl.Certificate {
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

    return cert.BuildCreate()
}

/*
 */
func buildPrivKeyCreate(reader *bufio.Reader) openssl.PrivKey {
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
func buildPrivKeyView(reader *bufio.Reader) openssl.PrivKey {
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
func buildRootCACreate(reader *bufio.Reader, privkey *openssl.PrivKey) openssl.Certificate {
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

    return cert.BuildCreate()
}

/*
 */
func buildSClientConnect(reader *bufio.Reader) openssl.SClient {
    fmt.Println("-- Connecting to secure url --")

    sclient := openssl.NewSClientBuilder()
    hostname := promptStr(reader, "Enter url hostname: ")
    sclient.Host(hostname)
    port := promptInt(reader, "Enter url port: ")
    sclient.Port(port)
    sclient.Connect(hostname, port)
    sclient.Extra( promptStr(reader, "(Optional) Enter any extra arguments []: ") )

    return sclient.BuildConnect()
}
