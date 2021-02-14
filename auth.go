package main

import (
	"bufio"
	"errors"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var (
	filename string
)

func AuthLoadFile(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	f.Close()

	filename = file
	return nil
}

func AuthReady() bool {
	return (filename != "")
}

// Returns bcrypt-hash, email
// email can be empty in which case it is not checked
func AuthFetch(username string) (string, []string, error) {
	if !AuthReady() {
		return "", nil, errors.New("Authentication file not specified. Call LoadFile() first")
	}

	file, err := os.Open(filename)
	if err != nil {
		return "", nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())

		if len(parts) < 2 || len(parts) > 3 {
			continue
		}

		if strings.ToLower(username) != strings.ToLower(parts[0]) {
			continue
		}

		hash := parts[1]
		email := []string(nil)

		if len(parts) >= 3 {
			email = strings.Split(parts[2], ",")
		}

		return hash, email, nil
	}

	return "", nil, errors.New("User not found")
}

func AuthCheckPassword(username string, secret string) error {
	hash, _, err := AuthFetch(username)
	if err != nil {
		return err
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(secret)) == nil {
		return nil
	}
	return errors.New("Password invalid")
}
