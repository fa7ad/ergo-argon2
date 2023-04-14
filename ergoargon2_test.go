package ergoArgon2_test

import (
	"testing"

	ergoArgon2 "github.com/fa7ad/ergo-argon2"
)

func TestHashPassword(t *testing.T) {
	password := "password123"
	hash := ergoArgon2.HashPassword(password)

	if len(hash) == 0 {
		t.Errorf("HashPassword() returned an empty string")
	}

	if len(hash) < 74 {
		t.Errorf("HashPassword() returned a hash shorter than 74 characters")
	}
}

func TestVerifyPassword(t *testing.T) {
	password := "password123"
	hash := ergoArgon2.HashPassword(password)

	if !ergoArgon2.VerifyPassword(password, hash) {
		t.Errorf("VerifyPassword() returned false for a valid password")
	}

	if ergoArgon2.VerifyPassword("wrongPassword", hash) {
		t.Errorf("VerifyPassword() returned true for an invalid password")
	}

	if ergoArgon2.VerifyPassword(password, "invalidHash") {
		t.Errorf("VerifyPassword() returned true for an invalid hash")
	}
}
