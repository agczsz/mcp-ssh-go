package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type socks5Observation struct {
	host, port, username, password string
	err                            error
}

func TestDialSSHClientThroughSOCKS5(t *testing.T) {
	for _, authenticated := range []bool{false, true} {
		t.Run(fmt.Sprintf("authenticated_%t", authenticated), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()

			observed := make(chan socks5Observation, 1)
			go func() {
				result := socks5Observation{}
				conn, err := listener.Accept()
				if err != nil {
					result.err = err
					observed <- result
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				reader := bufio.NewReader(conn)
				read := func(data []byte) bool {
					_, result.err = io.ReadFull(reader, data)
					return result.err == nil
				}
				write := func(data []byte) bool {
					_, result.err = conn.Write(data)
					return result.err == nil
				}

				var greeting [2]byte
				if !read(greeting[:]) {
					observed <- result
					return
				}
				methods := make([]byte, int(greeting[1]))
				if !read(methods) {
					observed <- result
					return
				}
				method := byte(0)
				if authenticated {
					method = 2
				}
				if !write([]byte{5, method}) {
					observed <- result
					return
				}
				if authenticated {
					var header [2]byte
					if !read(header[:]) {
						observed <- result
						return
					}
					username := make([]byte, int(header[1]))
					if !read(username) {
						observed <- result
						return
					}
					var passLength [1]byte
					if !read(passLength[:]) {
						observed <- result
						return
					}
					password := make([]byte, int(passLength[0]))
					if !read(password) {
						observed <- result
						return
					}
					result.username, result.password = string(username), string(password)
					if !write([]byte{1, 0}) {
						observed <- result
						return
					}
				}

				var request [4]byte
				if !read(request[:]) {
					observed <- result
					return
				}
				switch request[3] {
				case 1:
					address := make([]byte, net.IPv4len)
					if !read(address) {
						observed <- result
						return
					}
					result.host = net.IP(address).String()
				case 3:
					var size [1]byte
					if !read(size[:]) {
						observed <- result
						return
					}
					address := make([]byte, int(size[0]))
					if !read(address) {
						observed <- result
						return
					}
					result.host = string(address)
				case 4:
					address := make([]byte, net.IPv6len)
					if !read(address) {
						observed <- result
						return
					}
					result.host = net.IP(address).String()
				default:
					result.err = fmt.Errorf("unexpected SOCKS5 address type %d", request[3])
					observed <- result
					return
				}
				var port [2]byte
				if !read(port[:]) {
					observed <- result
					return
				}
				result.port = strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))
				if !write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 22}) {
					observed <- result
					return
				}
				_, result.err = reader.ReadString('\n')
				observed <- result
			}()

			port := listener.Addr().(*net.TCPAddr).Port
			secrets := memorySecrets{}
			target := resolved{hostName: "ssh.example", port: "22", socks5Host: "127.0.0.1", socks5Port: port}
			if authenticated {
				target.socks5Username = "proxy-user"
				target.credentialID = "edge"
				secrets[socks5PasswordKey("edge")] = "proxy-password"
			}
			clientConfig := &ssh.ClientConfig{User: "test", HostKeyCallback: ssh.InsecureIgnoreHostKey()}
			client, err := dialSSHClient(target, clientConfig, 2*time.Second, secrets)
			if client != nil {
				_ = client.Close()
			}
			if err == nil {
				t.Fatal("expected SSH handshake to fail after SOCKS5 connect")
			}
			result := <-observed
			if result.err != nil {
				t.Fatal(result.err)
			}
			if result.host != "ssh.example" || result.port != "22" {
				t.Fatalf("SOCKS5 destination = %s:%s, want ssh.example:22", result.host, result.port)
			}
			if authenticated && (result.username != "proxy-user" || result.password != "proxy-password") {
				t.Fatalf("SOCKS5 credentials = %q / %q", result.username, result.password)
			}
			if !authenticated && (result.username != "" || result.password != "") {
				t.Fatalf("unexpected SOCKS5 credentials = %q / %q", result.username, result.password)
			}
		})
	}
}
