package main

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
}

/*
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
