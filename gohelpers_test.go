package gohelpers

import "testing"

func TestGenerateSecretKet(t *testing.T) {
	want := "abc123456XYZ"
	data, err := GenerateSecretKet("SECRET_KEY")

	if want != string(data) || err != nil {
		t.Fatalf(`GenerateSecretKet("SECRET_KEY") = %q, %v, want match for %#q, nil`, data, err, want)
	}
}
