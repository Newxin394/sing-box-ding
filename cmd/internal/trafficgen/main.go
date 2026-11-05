//go:build linux || android

// Command trafficgen pushes traffic through the local stack so that the eBPF
// inbound's cost can be measured under load. The device has no curl, and the
// public internet is not reliable enough for repeatable measurement, so the
// default modes stay local: a UDP query flood against a public resolver and a
// loopback TCP round trip. An http mode is kept for real-world spot checks.
//
// Usage: trafficgen <seconds> [udp|tcplocal|http]
package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const dnsQuery = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" +
	"\x03www\x07example\x03com\x00" +
	"\x00\x01\x00\x01"

// runUDPFlood sends as fast as the stack accepts writes. The default target is
// TEST-NET-1, which is guaranteed unroutable, so nothing answers and no real
// server is troubled: the point is only to drive the sendmsg hook hard. With
// external set, queries go to a public resolver and each reply crosses the
// recvmsg hook too, at a rate the resolver tolerates.
func runUDPFlood(deadline time.Time, workers int, external bool, sent, received *atomic.Int64) {
	var group sync.WaitGroup
	for range workers {
		group.Go(func() {
			target := "192.0.2.1:53"
			if external {
				target = "223.5.5.5:53"
			}
			conn, err := net.Dial("udp", target)
			if err != nil {
				return
			}
			defer conn.Close()
			buffer := make([]byte, 2048)
			for time.Now().Before(deadline) {
				for range 64 {
					if _, writeErr := conn.Write([]byte(dnsQuery)); writeErr != nil {
						break
					}
					sent.Add(1)
				}
				if external {
					_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
					if _, readErr := conn.Read(buffer); readErr == nil {
						received.Add(1)
					}
					time.Sleep(20 * time.Millisecond)
				} else {
					// 64 packets every 5 ms across 4 workers is about 50k
					// packets a second: enough to be measurable, not a flood.
					time.Sleep(5 * time.Millisecond)
				}
			}
		})
	}
	group.Wait()
}

// runTCPConnect measures the connect hook, which is the most expensive of the
// cgroup hooks because it runs the full policy chain for every new flow. The
// target is unroutable and the dial timeout is short, so the hook fires at a
// high rate and nothing on the internet is troubled; when the cgroup inbound is
// running the connect is answered by its local listener instead.
func runTCPConnect(deadline time.Time, workers int, sent, received *atomic.Int64) {
	var group sync.WaitGroup
	for range workers {
		group.Go(func() {
			dialer := net.Dialer{Timeout: 10 * time.Millisecond}
			for time.Now().Before(deadline) {
				sent.Add(1)
				conn, err := dialer.Dial("tcp", "192.0.2.1:9")
				if err != nil {
					continue
				}
				received.Add(1)
				_ = conn.Close()
			}
		})
	}
	group.Wait()
}

// runTCPLocal keeps a listener and a client in the same process, so the round
// trip crosses the connect, sendmsg and recvmsg hooks without needing any
// external host.
func runTCPLocal(deadline time.Time, sent, received *atomic.Int64) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		return
	}
	defer listener.Close()
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buffer := make([]byte, 32*1024)
				for {
					read, readErr := conn.Read(buffer)
					if readErr != nil {
						break
					}
					if _, writeErr := conn.Write(buffer[:read]); writeErr != nil {
						return
					}
				}
			}(conn)
		}
	}()
	var group sync.WaitGroup
	for range 4 {
		group.Go(func() {
			buffer := make([]byte, 32*1024)
			for time.Now().Before(deadline) {
				conn, dialErr := net.Dial("tcp", listener.Addr().String())
				if dialErr != nil {
					continue
				}
				for range 64 {
					if _, writeErr := conn.Write(buffer); writeErr != nil {
						break
					}
					sent.Add(int64(len(buffer)))
					_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
					read, readErr := io.ReadFull(conn, buffer)
					if readErr != nil {
						break
					}
					received.Add(int64(read))
				}
				_ = conn.Close()
			}
		})
	}
	group.Wait()
}

func runHTTP(deadline time.Time, url string, sent, received *atomic.Int64) {
	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 4,
			DialContext: (&net.Dialer{
				Timeout: 5 * time.Second,
			}).DialContext,
		},
		Timeout: 20 * time.Second,
	}
	var group sync.WaitGroup
	for range 2 {
		group.Go(func() {
			buffer := make([]byte, 64*1024)
			for time.Now().Before(deadline) {
				response, err := client.Get(url)
				if err != nil {
					time.Sleep(300 * time.Millisecond)
					continue
				}
				read, _ := io.CopyBuffer(io.Discard, response.Body, buffer)
				_ = response.Body.Close()
				received.Add(read)
				sent.Add(read)
			}
		})
	}
	group.Wait()
}

func main() {
	seconds := 10
	mode := "udp"
	if len(os.Args) > 1 {
		if parsed, err := strconv.Atoi(os.Args[1]); err == nil {
			seconds = parsed
		}
	}
	if len(os.Args) > 2 {
		mode = os.Args[2]
	}
	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	var sent, received atomic.Int64
	start := time.Now()
	switch mode {
	case "udp":
		runUDPFlood(deadline, 4, false, &sent, &received)
	case "udpexternal":
		runUDPFlood(deadline, 4, true, &sent, &received)
	case "tcpconn":
		runTCPConnect(deadline, 8, &sent, &received)
	case "tcplocal":
		runTCPLocal(deadline, &sent, &received)
	case "http":
		url := "http://speed.cloudflare.com/__down?bytes=104857600"
		if len(os.Args) > 3 {
			url = os.Args[3]
		}
		runHTTP(deadline, url, &sent, &received)
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q\n", mode)
		os.Exit(2)
	}
	elapsed := time.Since(start).Seconds()
	fmt.Printf("%s: sent %d, received %d in %.1fs (%.1f kB/s)\n",
		mode, sent.Load(), received.Load(), elapsed, float64(received.Load())/1024/elapsed)
}
