// A local-only client for exercising the real Headscale registration endpoint.
// Build it in the pinned Headscale module so its Tailscale dependency matches.
package main

import (
    "context"
    "encoding/json"
    "flag"
    "fmt"
    "os"
    "strings"
    "time"

    "tailscale.com/tsnet"
)

func main() {
    state := flag.String("state", "", "client state directory")
    host := flag.String("host", "", "synthetic client hostname")
    control := flag.String("control", "", "local Headscale URL")
    tags := flag.String("tags", "", "comma-separated advertised tags")
    timeout := flag.Duration("timeout", 20*time.Second, "registration timeout")
    flag.Parse()
    if *state == "" || *host == "" || *control == "" {
        fmt.Fprintln(os.Stderr, "state, host and control are required")
        os.Exit(2)
    }

    var input struct { Key string `json:"key"` }
    if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil || input.Key == "" {
        fmt.Fprintln(os.Stderr, "valid key JSON is required on stdin")
        os.Exit(2)
    }
    srv := &tsnet.Server{
        Dir: *state, Hostname: *host, ControlURL: *control,
        AuthKey: input.Key,
        UserLogf: func(string, ...any) {},
        Logf: func(string, ...any) {},
    }
    if *tags != "" {
        srv.AdvertiseTags = strings.Split(*tags, ",")
    }
    defer srv.Close()
    ctx, cancel := context.WithTimeout(context.Background(), *timeout)
    defer cancel()
    status, err := srv.Up(ctx)
    if err != nil {
        fmt.Println(`{"status":"registration_failed"}`)
        os.Exit(1)
    }
    result := struct {
        Status string `json:"status"`
        IPs []string `json:"ips"`
    }{Status: "online"}
    for _, ip := range status.TailscaleIPs {
        result.IPs = append(result.IPs, ip.String())
    }
    if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
        os.Exit(1)
    }
}
