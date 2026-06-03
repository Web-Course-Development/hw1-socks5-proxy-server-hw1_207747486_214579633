package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"io"
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

	method, err := negotiateAuth(conn)
	if err != nil {
		log.Printf("auth negotiation error: %v", err)
		return
	}

	if method == 0x02 {
		if err := authenticate(conn); err != nil {
			log.Printf("authentication failed: %v", err)
			return
		}
	}

	targetAddr, err := readConnectRequest(conn)
	if err != nil {
		log.Printf("connect request error: %v", err)
		sendReply(conn, 0x01)
		return
	}

	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("failed to connect to target %s: %v", targetAddr, err)
		sendReply(conn, 0x05)
		return
	}
	defer targetConn.Close()

	if err := sendReply(conn, 0x00); err != nil {
		log.Printf("failed to send success reply: %v", err)
		return
	}

	relay(conn, targetConn)
}

func negotiateAuth(conn net.Conn) (byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, err
	}

	if header[0] != 0x05 {
		return 0, fmt.Errorf("invalid SOCKS version")
	}

	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return 0, err
	}

	authRequired := os.Getenv("PROXY_USER") != ""

	var selected byte = 0xFF

	for _, method := range methods {
		if authRequired && method == 0x02 {
			selected = 0x02
			break
		}
		if !authRequired && method == 0x00 {
			selected = 0x00
			break
		}
	}

	_, err := conn.Write([]byte{0x05, selected})
	if err != nil {
		return 0, err
	}

	if selected == 0xFF {
		return 0, fmt.Errorf("no acceptable authentication method")
	}

	return selected, nil
}

func authenticate(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	if header[0] != 0x01 {
		conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("invalid auth version")
	}

	usernameLength := int(header[1])
	usernameBytes := make([]byte, usernameLength)
	if _, err := io.ReadFull(conn, usernameBytes); err != nil {
		return err
	}

	passwordLengthBytes := make([]byte, 1)
	if _, err := io.ReadFull(conn, passwordLengthBytes); err != nil {
		return err
	}

	passwordLength := int(passwordLengthBytes[0])
	passwordBytes := make([]byte, passwordLength)
	if _, err := io.ReadFull(conn, passwordBytes); err != nil {
		return err
	}

	username := string(usernameBytes)
	password := string(passwordBytes)

	expectedUser := os.Getenv("PROXY_USER")
	expectedPass := os.Getenv("PROXY_PASS")

	if username == expectedUser && password == expectedPass {
		_, err := conn.Write([]byte{0x01, 0x00})
		return err
	}

	conn.Write([]byte{0x01, 0x01})
	return fmt.Errorf("invalid username or password")
}

func readConnectRequest(conn net.Conn) (string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}

	if header[0] != 0x05 {
		return "", fmt.Errorf("invalid SOCKS version in CONNECT request")
	}

	if header[1] != 0x01 {
		return "", fmt.Errorf("unsupported command")
	}

	if header[2] != 0x00 {
		return "", fmt.Errorf("invalid reserved byte")
	}

	addressType := header[3]
	var host string

	switch addressType {
	case 0x01:
		ipBytes := make([]byte, 4)
		if _, err := io.ReadFull(conn, ipBytes); err != nil {
			return "", err
		}
		host = net.IP(ipBytes).String()

	case 0x03:
		lengthBytes := make([]byte, 1)
		if _, err := io.ReadFull(conn, lengthBytes); err != nil {
			return "", err
		}

		domainLength := int(lengthBytes[0])
		domainBytes := make([]byte, domainLength)
		if _, err := io.ReadFull(conn, domainBytes); err != nil {
			return "", err
		}

		host = string(domainBytes)

	default:
		return "", fmt.Errorf("unsupported address type")
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", err
	}

	port := binary.BigEndian.Uint16(portBytes)

	return fmt.Sprintf("%s:%d", host, port), nil
}

func sendReply(conn net.Conn, rep byte) error {
	reply := []byte{
		0x05,
		rep,
		0x00,
		0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}

	_, err := conn.Write(reply)
	return err
}

func relay(client net.Conn, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(target, client)
		if tcpConn, ok := target.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(client, target)
		if tcpConn, ok := client.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	wg.Wait()
}