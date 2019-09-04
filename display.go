package main

import (
    "fmt"
    "openssl/selfsigned"
//    github.com/fatih/color
)

func Run(text string) {
//    color.Green("[RUN]")
    fmt.Println(text)
}

func Info(text string) {
//    color.Yellow("[INFO]")
    fmt.Println(text)
}

