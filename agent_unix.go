//go:build !windows

package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

func dialAgent() (net.Conn, error) {
	socket := strings.TrimSpace(os.Getenv("SSH_AUTH_SOCK"))
	if socket == "" {
		return nil, fmt.Errorf("SSH_AUTH_SOCK is not set; start ssh-agent and add a key with ssh-add")
	}
	conn, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to ssh-agent at SSH_AUTH_SOCK: %w; start ssh-agent and add a key with ssh-add", err)
	}
	return conn, nil
}
