package main

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type resolved struct {
	hostName       string
	port           string
	user           string
	identity       []string
	proxyJump      string
	socks5Host     string
	socks5Port     int
	socks5Username string
	authMethod     string
	credentialID   string
	timeoutSec     int
}

func authMethods(target resolved, secrets secretStore) ([]ssh.AuthMethod, func(), error) {
	switch target.authMethod {
	case "agent":
		conn, err := dialAgent()
		if err != nil {
			return nil, nil, err
		}
		client := agent.NewClient(conn)
		signers, err := client.Signers()
		if err != nil {
			_ = conn.Close()
			return nil, nil, fmt.Errorf("query ssh-agent keys: %w", err)
		}
		if len(signers) == 0 {
			_ = conn.Close()
			return nil, nil, fmt.Errorf("ssh-agent is connected but has no keys; add one with ssh-add")
		}
		return []ssh.AuthMethod{ssh.PublicKeysCallback(client.Signers)}, func() { _ = conn.Close() }, nil
	case "password":
		password, err := secrets.Get(passwordKey(target.credentialID))
		if err != nil {
			if errors.Is(err, errSecretNotFound) {
				return nil, nil, fmt.Errorf("no password is stored for server %q; set it in the local GUI", target.credentialID)
			}
			return nil, nil, fmt.Errorf("read password from the system keyring: %w", err)
		}
		return []ssh.AuthMethod{ssh.Password(password)}, func() {}, nil
	case "key":
		return keyAuthMethods(target, secrets)
	default:
		return nil, nil, fmt.Errorf("unsupported authentication method %q", target.authMethod)
	}
}

func keyAuthMethods(target resolved, secrets secretStore) ([]ssh.AuthMethod, func(), error) {
	if len(target.identity) == 0 {
		return nil, nil, fmt.Errorf("no private key configured")
	}
	var passphrase string
	if target.credentialID != "" {
		value, err := secrets.Get(passphraseKey(target.credentialID))
		if err != nil && !errors.Is(err, errSecretNotFound) {
			return nil, nil, fmt.Errorf("read private key passphrase from the system keyring: %w", err)
		}
		if err == nil {
			passphrase = value
		}
	}
	var signers []ssh.Signer
	var firstErr error
	for _, path := range target.identity {
		key, err := readGuarded(path)
		if err != nil {
			wrapped := fmt.Errorf("read private key %q: %w; add its directory to SSH_MCP_ALLOWED_KEY_DIRS if it is outside the allowed directories", path, err)
			if target.credentialID != "" {
				return nil, nil, wrapped
			}
			if firstErr == nil {
				firstErr = wrapped
			}
			continue
		}
		var signer ssh.Signer
		if passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(key, []byte(passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(key)
		}
		if err != nil {
			wrapped := fmt.Errorf("parse private key %q: %w", path, err)
			if target.credentialID != "" {
				if passphrase == "" {
					return nil, nil, fmt.Errorf("%w; if the key is encrypted, set its passphrase in the local GUI", wrapped)
				}
				return nil, nil, wrapped
			}
			if firstErr == nil {
				firstErr = wrapped
			}
			continue
		}
		signers = append(signers, signer)
	}
	if len(signers) == 0 {
		if firstErr != nil {
			return nil, nil, firstErr
		}
		return nil, nil, fmt.Errorf("no usable private key found (checked: %s)", strings.Join(target.identity, ", "))
	}
	return []ssh.AuthMethod{ssh.PublicKeys(signers...)}, func() {}, nil
}

func agentStatus() (bool, int, string) {
	conn, err := dialAgent()
	if err != nil {
		return false, 0, err.Error()
	}
	defer conn.Close()
	client := agent.NewClient(conn)
	signers, err := client.Signers()
	if err != nil {
		return false, 0, fmt.Sprintf("query ssh-agent keys: %v", err)
	}
	return true, len(signers), ""
}
