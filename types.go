package gohelpers

import "github.com/golang-jwt/jwt/v5"

type jwtCustomClaims struct {
	Username string `json:"username"`
	Uuid     string `json:"uuid"`
	jwt.RegisteredClaims
}
