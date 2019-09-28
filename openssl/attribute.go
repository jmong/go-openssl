package openssl

import (
    "strconv"
    "strings"
)

type NativeType int
const (
    STRING = iota
    INT
    INT64
    BOOL
)

type Attribute struct {
    Arg         string
    Value       string
    ValueInt    int
    ValueInt64  int64
    ValueBool   bool
    Prepend     string
    Native      NativeType
    Required    bool
    IsUpdated   bool
}

/* Parse list of attribute values into an array.
 * @param  checkupdated Enables parsing if IsUpdated attribute is true
 * @param  list         List of attributes to parse
 * @return Array of the attributes values
 */
func toArray(checkupdated bool, list ...Attribute) []string {
    arr := []string{}
    for _, attr := range list {
        if checkupdated == true && attr.IsUpdated == false {
            continue
        }
        if attr.Arg != "" && attr.Native != BOOL {
            arr = append(arr, attr.Arg)
        }

        var val string
        switch attr.Native {
        case STRING:
            if attr.Value == "" {
                continue
            }
            // Hack
            args := strings.Split(attr.Value, " ")
            for _, val := range args {
                if attr.Prepend != "" {
                    val = attr.Prepend + val
                }
                arr = append(arr, val)
            }
            continue
        case INT:
            val = strconv.Itoa(attr.ValueInt)
        case INT64:
            val = strconv.FormatInt(attr.ValueInt64, 10)
        case BOOL:
            if attr.ValueBool == true {
                val = attr.Arg
            }
        }
        if attr.Prepend != "" {
            val = attr.Prepend + val
        }
        arr = append(arr, val)
    }

    return arr
}

/* @DEPRECATED
 * 
 */
func (attr *Attribute) IsSet() bool {
    switch attr.Native {
    case STRING:
        if attr.Value != "" {
            return true
        }
    case INT:
        if attr.ValueInt != 0 {
            return true
        }
    case INT64:
        if attr.ValueInt64 != 0 {
            return true
        }
    case BOOL:
        if attr.ValueBool != false {
            return true
        }
    }

    return false
}
