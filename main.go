package main

import (
  "context"
  "encoding/json"
  "flag"
  "fmt"
  "os"

  "github.com/open-policy-agent/opa/rego"
)

func main() {
  flag.Usage = func () {
    fmt.Printf("Usage:\n  %s contains $CIDR $IP \n", os.Args[0])
    fmt.Printf("  %s contains $CIDR $TESTCIDR\n", os.Args[0])
    fmt.Printf("  %s expand $CIDR\n", os.Args[0])

    fmt.Printf("\nExample:\n  %s contains 192.168.0.0/16 192.168.7.42 \n", os.Args[0])
    fmt.Printf("  %s contains 192.168.0.0/16 192.168.0.0/24\n", os.Args[0])
    fmt.Printf("  %s expand 192.168.0.0/24\n", os.Args[0])

    flag.PrintDefaults()
  }

  flag.Parse()

  if len(os.Args) == 1 {
    fmt.Printf("No command provided.\n\n")
    flag.Usage()
    os.Exit(1)
  }

  command := os.Args[1]
  var exitCode int

  switch command {
  case "contains":
    result, err := contains(os.Args[2], os.Args[3])
    if err != nil {
      fmt.Println(err)
    }
    fmt.Println(result)
    if result == "false" {
      exitCode = 1
    }
  case "expand":
    result, err := expand(os.Args[2])
    if err != nil {
      fmt.Println(err)
    }
    fmt.Println(result)
  default:
    fmt.Printf("No valid command provided.\n\n")
    flag.Usage()
    os.Exit(1)
  }

  os.Exit(exitCode)
}

func contains(cidr, ip string) (string, error) {
  ctx := context.Background()

  module := `
    package cidr
    default contains = false
    contains = true {
      basecidr := input.basecidr
      testip := input.testip
      net.cidr_contains(basecidr, testip)
    }
  `

  reg := rego.New(
    rego.Query("data.cidr.contains"),
    rego.Module("contains", module),
    rego.Input(
      map[string]interface{}{
        "basecidr": cidr,
        "testip":   ip,
      },
    ),
  )

  rs, err := reg.Eval(ctx)
  if err != nil {
    return "false", err
  }

  result := fmt.Sprintf("%v\n", rs[0].Expressions[0])

  return result, nil
}

func expand(cidr string) (string, error) {
  ctx := context.Background()

  module := `
    package cidr
    expand[ips] {
      basecidr := input.basecidr
      ips := net.cidr_expand(basecidr)
    }
  `

  reg := rego.New(
    rego.Query("data.cidr.expand"),
    rego.Module("expand", module),
    rego.Input(
      map[string]interface{}{
        "basecidr": cidr,
      },
    ),
  )

  rs, err := reg.Eval(ctx)
  if err != nil {
    return "", err
  }

  type cidrIps struct {
    CIDR string      `json:"cidr"`
    IPs  interface{} `json:"ips"`
  }

  result, err := json.Marshal(
    cidrIps{
      CIDR: cidr,
      IPs:  rs[0].Expressions[0].Value,
    },
  )
  if err != nil {
    return "", err
  }

  return string(result), nil
}
