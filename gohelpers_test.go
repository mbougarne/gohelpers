package gohelpers

import (
	"os"
	"reflect"
	"testing"
)

func TestMain(m *testing.M) {
	LoadDotEnvToOsEnv()
	os.Exit(m.Run())
}

func TestGenerateSecretKey(t *testing.T) {
	want := "abc123456XYZ"
	data, err := GenerateSecretKet("SECRET_KEY", true)

	if want != string(data) || err != nil {
		t.Fatalf(`GenerateSecretKet("SECRET_KEY") = %q, %v, want match for %#q, nil`, data, err, want)
	}
}

func TestGenerateSecretKeyInBytes(t *testing.T) {
	var want []byte
	data, err := GenerateSecretKet("abc123456XYZ")
	if reflect.TypeOf(want) != reflect.TypeOf(data) || err != nil {
		t.Fatalf(`data = %T, want match for %T\n`, data, want)
	}
}

func TestGetEnvKey(t *testing.T) {
	key := GetEnvKey("SECRET_KEY")
	want := "abc123456XYZ"

	if want != key || key == "" {
		t.Fatalf(`GetEnvKey("SECRET_KEY") = %v, want match for %v, nil`, key, want)
	}
}

func TestHashPassword(t *testing.T) {
	password := "secret"
	hashed, err := HashPassword(password)

	if hashed == password || err != nil {
		t.Fatalf(`HashPassword(password) = %q, %v, want match for %#q, nil`, hashed, err, password)
	}
}
