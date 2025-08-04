package gohelpers

import (
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestMain(m *testing.M) {
	LoadDotEnvToOsEnv()
	os.Exit(m.Run())
}

type jwtCustomClaims struct {
	Username string `json:"username"`
	Uuid     string `json:"uuid"`
	jwt.RegisteredClaims
}

func createCustomClaim(expiresAt ...time.Time) jwtCustomClaims {
	var tokenLifeTime time.Time

	if len(expiresAt) > 0 {
		tokenLifeTime = expiresAt[0]
	} else {
		tokenLifeTime = time.Now().Add(12 * time.Minute)
	}

	return jwtCustomClaims{
		Username: "johnDoe",
		Uuid:     "550e8400-e29b-41d4-a716-446655440000",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(tokenLifeTime),
		},
	}
}

func TestGenerateSecretKey(t *testing.T) {
	want := "abc123456XYZ"
	data, err := GenerateSecretKey("SECRET_KEY", true)

	if want != string(data) || err != nil {
		t.Fatalf(`GenerateSecretKet("SECRET_KEY") = %q, %v, want match for %#q, nil`, data, err, want)
	}
}

func TestGenerateSecretKeyInBytes(t *testing.T) {
	var want []byte
	data, err := GenerateSecretKey("abc123456XYZ")
	if reflect.TypeOf(want) != reflect.TypeOf(data) || err != nil {
		t.Fatalf(`data = %T, want match for %T\n`, data, want)
	}
}

func TestGetEnvKey(t *testing.T) {
	key := GetEnvKey("SECRET_KEY")
	want := "abc123456XYZ"
	dsn := GetEnvKey("MY_DB_URL")
	wantDsn := "mongodb://username:secret@localhost:27017/schema_db?ssl=enabled"
	fmt.Printf("dsn: %v", dsn)
	if want != key || key == "" {
		t.Fatalf(`GetEnvKey("SECRET_KEY") = %v, want match for %v, nil`, key, want)
	}

	if wantDsn != dsn || dsn == "" {
		t.Fatalf(`GetEnvKey("MY_DB_URL") = %v, want match for %v, nil`, key, want)
	}
}

func TestHashPassword(t *testing.T) {
	password := "secret"
	hashed, err := HashPassword(password)

	if hashed == password || err != nil {
		t.Fatalf(`HashPassword(password) = %q, %v, want match for %#q, nil`, hashed, err, password)
	}
}

func TestVerifyPassword(t *testing.T) {
	password := "secret"
	hashed, _ := HashPassword(password) // the err not used here because it checked in the previous test.
	isMatched := VerifyHashedPassword(password, hashed)

	if !isMatched {
		t.Fatal("VerifyHashedPassword isn't working as expected!")
	}
}

func TestGenerateJwtToken(t *testing.T) {
	token, err := GenerateJwtToken([]byte("abcde12345"))

	if token == "" || err != nil {
		t.Fatalf("GenerateJwtToken: cannot generate a valid token: %v, it returns an error: %v", token, err.Error())
	}
}

func TestGenerateJwtTokenWithCustomClaims(t *testing.T) {
	claims := createCustomClaim()
	token, err := GenerateJwtToken([]byte("abcde12345"), claims)

	if token == "" || err != nil {
		t.Fatalf("TestGenerateJwtTokenWithCustomClaims: cannot generate a valid token with custom claims: %v, it returns an error: %v", token, err.Error())
	}
}

func TestGenerateJwtTokenWithCustomClaimsAndEnvSecretKey(t *testing.T) {
	claims := createCustomClaim()
	secretKey, _ := GenerateSecretKey("SECRET_KEY")
	token, err := GenerateJwtToken(secretKey, claims)

	if token == "" || err != nil {
		t.Fatalf("TestGenerateJwtTokenWithCustomClaimsAndEnvSecretKey: cannot generate a valid token with custom claims, and 'SECRET_KEY' of .env file: %v, it returns an error: %v", token, err.Error())
	}
}

func TestGetClaims(t *testing.T) {
	secretKey, _ := GenerateSecretKey("SECRET_KEY")
	token, err := GenerateJwtToken(secretKey)

	if token == "" || err != nil {
		t.Fatalf("TestGetDefaultClaims: cannot generate a valid token with custom claims: %v, it returns an error: %v", token, err.Error())
	}

	jwtClaims, _ := GetClaims(token, secretKey)
	claims := jwtClaims.(jwt.MapClaims)
	fmt.Println(claims)
	if claims["exp"] == nil || err != nil {
		t.Fatal("TestGetDefaultClaims: the username and uuid of jwtCustomClaims are not set")
	}
}

func TestGetClaimsWithCustomClaims(t *testing.T) {
	claims := createCustomClaim()
	secretKey, _ := GenerateSecretKey("SECRET_KEY")
	token, err := GenerateJwtToken(secretKey, claims)

	if token == "" || err != nil {
		t.Fatalf("TestGetDefaultClaims: cannot generate a valid token with custom claims: %v, it returns an error: %v", token, err.Error())
	}

	jwtClaims, _ := GetClaims(token, secretKey)
	err = CastJwtClaimsToCustomClaims(jwtClaims, &claims)

	if claims.Username != "johnDoe" || claims.ExpiresAt == nil || claims.Uuid != "550e8400-e29b-41d4-a716-446655440000" || err != nil {
		t.Fatal("TestGetClaimsWithCustomClaims: does not cast to custom claim")
	}
}

func TestVerifyToken(t *testing.T) {
	claims := createCustomClaim()
	secretKey, _ := GenerateSecretKey("SECRET_KEY")
	token, _ := GenerateJwtToken(secretKey, claims)

	isValid, err := VerifyJwtToken(token, secretKey)

	if !isValid || err != nil {
		t.Fatalf("TestVerifyToken: the isValid should be 'true' but we got %v, err %v", isValid, err.Error())
	}
}

func TestVerifyTokenWithExpiredToken(t *testing.T) {
	expiresAt := time.Now().Add(3 * time.Second)
	claims := createCustomClaim(expiresAt)
	secretKey, _ := GenerateSecretKey("SECRET_KEY")
	token, _ := GenerateJwtToken(secretKey, claims)

	time.Sleep(4 * time.Second)

	isValid, err := VerifyJwtToken(token, secretKey)

	if isValid || err == nil {
		t.Fatalf("TestVerifyToken: the isValid should be 'false' but we got %v", isValid)
	}
}

func TestVerifyTokenWithInvalidToken(t *testing.T) {
	claims := createCustomClaim()
	secretKey, _ := GenerateSecretKey("SECRET_KEY")
	envSecretKey, _ := GenerateSecretKey("SECRET_KEY", true)
	token, _ := GenerateJwtToken(secretKey, claims)

	isValid, err := VerifyJwtToken(token, envSecretKey)

	if isValid || err == nil {
		t.Fatalf("TestVerifyToken: the isValid should be 'false' but we got %v", isValid)
	}
}
