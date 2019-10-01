package main

import (
    "fmt"
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

