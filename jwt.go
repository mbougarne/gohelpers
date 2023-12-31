package gohelpers

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

/*
Generate JWT token, this func will generate an access token or a refresh token, based on the claims.
If no custom claims sent as second arg, it will go with the `jwtCustomClaims` struct that contains:
`username`, `uuid`, and `jwt.RegisteredClaims`
*/
func GenerateJwtToken(secretKey []byte, customClaims ...jwt.Claims) (string, error) {
	claims := prepareClaims(customClaims)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(secretKey)

	if err != nil {
		return "", err
	}

	return tokenString, nil
}

/*
Verify the issued tokens, access and refresh. You can use the return error and check if the `access_token` is expired. Therefore, generate new one based on the refresh token validity.
Intended to be used in middlewares.
*/
func VerifyJwtToken(tokenString string, secretKey []byte) (bool, error) {
	_, err := jwt.Parse(tokenString, func(jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("invalid token")
		}
		return secretKey, nil
	})

	if err != nil {
		// TODO: Implement token expired error to issued new token based on validity of the refresh token.
		return false, errors.New("invalid token")
	}

	return true, nil
}

// Get claims from the token, and the used secret key to generate the token.
func GetClaims(tokenString string, secretKey []byte) (interface{}, error) {
	token, err := jwt.Parse(tokenString, func(jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("invalid token")
		}
		return secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	return token.Claims, nil
}

func prepareClaims(customClaims []jwt.Claims) jwt.Claims {
	if len(customClaims) > 0 {
		return customClaims[0]
	}

	claims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(12 * time.Minute)),
	}

	return claims
}

// Cast jwt Claims to custom interfaces
func CastJwtClaimsToCustomClaims(mapClaims, claims interface{}) error {
	tmp, err := json.Marshal(mapClaims)

	if err != nil {
		return err
	}

	err = json.Unmarshal(tmp, &claims)

	if err != nil {
		return err
	}

	return nil
}
