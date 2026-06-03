package main

import (
	"flag"
	"fmt"
	"log"
	"net"
)

func main() {
	port := flag.Int("port", 1080, "port to listen on")
	flag.Parse()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on :%d", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}
func handleConnection(conn net.Conn) {
	defer conn.Close()

	// 1. Read client greeting and choose authentication method
	method, err := negotiateAuth(conn)
	if err != nil {
		log.Printf("authentication negotiation error: %v", err)
		return
	}

	// 2. If username/password authentication is required, check credentials
	if method == methodUserPass {
		if err := authenticateUserPass(conn); err != nil {
			log.Printf("username/password authentication error: %v", err)
			return
		}
	}

	// 3. Read CONNECT request and get target address
	targetAddr, err := readConnectRequest(conn)
	if err != nil {
		log.Printf("CONNECT request error: %v", err)
		return
	}

	// 4. Connect to the target server
	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("failed to connect to target %s: %v", targetAddr, err)
		_ = sendReply(conn, repGeneralFailure)
		return
	}
	defer targetConn.Close()

	// 5. Send success reply to the client
	if err := sendReply(conn, repSuccess); err != nil {
		log.Printf("failed to send success reply: %v", err)
		return
	}

	// 6. Relay data between client and target
	relay(conn, targetConn)
}

