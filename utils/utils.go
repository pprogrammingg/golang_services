// utils/crypto_utils.go

package utils

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/rand"
	"os"
)

// createIdentityArray
//
//	Creates an identity array of input length.
//
// params: int length
// returns []int identity array
func CreateIdentityArray(length int) []int {
	// Create an array of size 10001 and assign values to each index
	array := make([]int, length)
	for i := 0; i <= length; i++ {
		array[i] = i
	}

	return array
}

// shuffleArray
// Given an array, shuffle its value and return it
//
// params: []int input array
// returns []int shuffled array
func ShuffleArray(array []int) []int {
	for i := len(array) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		array[i], array[j] = array[j], array[i]
	}

	return array
}

// Function to load RSA private key from a secret file
// reuturns tuple of pointer to the private key or error
func LoadPrivateKeyFromSecretFile() (*rsa.PrivateKey, error) {
	// Read private key file
	privateKeyData, err := os.ReadFile("/etc/secrets/priv_key")
	if err != nil {
		return nil, err
	}

	// Decode PEM encoded data
	block, _ := pem.Decode(privateKeyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Parse RSA private key
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}
