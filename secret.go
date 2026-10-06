package main

import (
	"errors"

	"github.com/zalando/go-keyring"
)

const secretService = "mcp-ssh-go"

var errSecretNotFound = keyring.ErrNotFound

type secretStore interface {
	Get(string) (string, error)
	Set(string, string) error
	Delete(string) error
}

type systemKeyring struct{}

func (systemKeyring) Get(key string) (string, error) {
	return keyring.Get(secretService, key)
}

func (systemKeyring) Set(key, value string) error {
	return keyring.Set(secretService, key, value)
}

func (systemKeyring) Delete(key string) error {
	err := keyring.Delete(secretService, key)
	if errors.Is(err, errSecretNotFound) {
		return nil
	}
	return err
}

func passwordKey(id string) string       { return "password:" + id }
func passphraseKey(id string) string     { return "passphrase:" + id }
func socks5PasswordKey(id string) string { return "socks5-password:" + id }
