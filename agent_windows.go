//go:build windows

package main

import (
	"fmt"
	"net"
	"time"

	"github.com/Microsoft/go-winio"
)

func dialAgent() (net.Conn, error) {
	timeout := 5 * time.Second
	conn, err := winio.DialPipe(`\\.\pipe\openssh-ssh-agent`, &timeout)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to the OpenSSH agent pipe; start the OpenSSH Authentication Agent service, run ssh-add in the same user session, and do not run this MCP as SYSTEM: %w", err)
	}
	return conn, nil
}
