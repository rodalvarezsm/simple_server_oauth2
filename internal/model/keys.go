package model

import "crypto/rsa"

type Key struct {
	Kid    string
	RSAKey rsa.PrivateKey
}
