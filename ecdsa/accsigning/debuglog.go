// Copyright 2023 Circle

package accsigning

import (
    "fmt"
    "os"
)

const logfile = "accountablelog.txt"

func Logf(format string, a ...any) (n int, err error) {
    msg := fmt.Sprintf(format, a...)
    msg = fmt.Sprintf("%s\n", msg)
    f, err := os.OpenFile(logfile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0666)
    if err != nil {
        n=0
        return
    }
    defer f.Close()
    n, err = f.WriteString(msg)
    return
}


