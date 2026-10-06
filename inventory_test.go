package main

import "testing"

func TestValidateServerSOCKS5(t *testing.T) {
	base := serverConfig{ID: "edge", Name: "Edge", Host: "ssh.example", AuthMethod: "agent"}
	for _, test := range []struct {
		name    string
		server  serverConfig
		wantErr bool
	}{
		{name: "hostname", server: serverConfig{ID: base.ID, Name: base.Name, Host: base.Host, AuthMethod: base.AuthMethod, Socks5Host: "proxy.example"}},
		{name: "IPv6", server: serverConfig{ID: base.ID, Name: base.Name, Host: base.Host, AuthMethod: base.AuthMethod, Socks5Host: "[::1]"}},
		{name: "host with port", server: serverConfig{ID: base.ID, Name: base.Name, Host: base.Host, AuthMethod: base.AuthMethod, Socks5Host: "proxy.example:1080"}, wantErr: true},
		{name: "proxy jump conflict", server: serverConfig{ID: base.ID, Name: base.Name, Host: base.Host, AuthMethod: base.AuthMethod, Socks5Host: "proxy.example", Jump: "bastion"}, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateServer(test.server)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateServer() error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}
