package gohelpers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ParseOptions config for parsing/verifying tokens from *http.Request.
type ParseOptions struct {
	Secret         []byte        // required
	AllowedMethods []string      // default: HS256 only
	Leeway         time.Duration // default: 30s
	Audience       string        // optional: add if you set aud in your tokens
	Issuer         string        // optional: add if you set iss in your tokens

	// Extraction knobs (header is always tried first)
	CookieName string // if set, try cookie by this name
	QueryParam string // if set, try ?token=... (or any custom name)
}

/*
Generate JWT token, this func will generate an access token or a refresh token, based on the claims.
If no custom claims sent as second arg, it will go with the `jwtCustomClaims` struct that contains:
`username`, `uuid`, and `jwt.RegisteredClaims`
*/
func GenerateJwtToken(secretKey []byte, customClaims ...jwt.Claims) (string, error) {
	claims := prepareClaims(customClaims)
	claims = ensureUniqueClaims(claims)
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
	token, err := jwt.Parse(tokenString, func(jwtToken *jwt.Token) (interface{}, error) {
		if jwtToken.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("unexpected signing method")
		}
		return secretKey, nil
	},
		// jwt.WithLeeway(30*time.Second),
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
	)
	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenSignatureInvalid):
			return false, jwt.ErrTokenSignatureInvalid
		case errors.Is(err, jwt.ErrTokenExpired):
			return false, jwt.ErrTokenExpired
		case errors.Is(err, jwt.ErrTokenNotValidYet):
			return false, jwt.ErrTokenNotValidYet
		default:
			return false, err
		}
	}
	if !token.Valid {
		return false, errors.New("invalid token")
	}
	return true, nil
}

// Get claims from the token, and the used secret key to generate the token.
func GetClaims(tokenString string, secretKey []byte) (interface{}, error) {
	token, err := jwt.Parse(tokenString, func(jwtToken *jwt.Token) (interface{}, error) {
		if jwtToken.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("unexpected signing method")
		}
		return secretKey, nil
	}, jwt.WithLeeway(30*time.Second), jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}
	return token.Claims, nil
}

// GetClaimsAs parses the token and unmarshals claims into dst (pointer to struct).
func GetClaimsAs(tokenString string, secretKey []byte, dst interface{}) error {
	claims, err := GetClaims(tokenString, secretKey)
	if err != nil {
		return err
	}

	return CastJwtClaimsToCustomClaims(claims, dst)
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

// ParseFromRequest extracts a JWT from the request (Authorization: Bearer ...,
// or cookie, or query param) and verifies it with the provided options.
// Works with net/http directly (Gin: use c.Request).
func ParseFromRequest(r *http.Request, opts ParseOptions) (*jwt.Token, error) {
	if len(opts.Secret) == 0 {
		return nil, errors.New("missing secret")
	}
	methods := opts.AllowedMethods
	if len(methods) == 0 {
		methods = []string{jwt.SigningMethodHS256.Alg()}
	}
	leeway := opts.Leeway
	if leeway == 0 {
		leeway = 30 * time.Second
	}

	raw, err := extractTokenString(r, opts)
	if err != nil {
		return nil, err
	}

	keyFunc := func(t *jwt.Token) (interface{}, error) {
		if t.Method == nil || t.Method.Alg() == "" {
			return nil, errors.New("missing signing method")
		}
		return opts.Secret, nil
	}

	var parseOpts []jwt.ParserOption
	parseOpts = append(parseOpts, jwt.WithValidMethods(methods), jwt.WithLeeway(leeway))
	if opts.Audience != "" {
		parseOpts = append(parseOpts, jwt.WithAudience(opts.Audience))
	}
	if opts.Issuer != "" {
		parseOpts = append(parseOpts, jwt.WithIssuer(opts.Issuer))
	}

	token, parseErr := jwt.Parse(raw, keyFunc, parseOpts...)
	if parseErr != nil {
		switch {
		case errors.Is(parseErr, jwt.ErrTokenSignatureInvalid):
			return nil, jwt.ErrTokenSignatureInvalid
		case errors.Is(parseErr, jwt.ErrTokenExpired):
			return nil, jwt.ErrTokenExpired
		case errors.Is(parseErr, jwt.ErrTokenNotValidYet):
			return nil, jwt.ErrTokenNotValidYet
		default:
			return nil, parseErr
		}
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}
	return token, nil
}

// VerifyFromRequest returns (true,nil) when the token from the request is valid.
func VerifyFromRequest(r *http.Request, opts ParseOptions) (bool, error) {
	_, err := ParseFromRequest(r, opts)
	if err != nil {
		return false, err
	}
	return true, nil
}

// GetClaimsFromRequest returns token.Claims after parsing/verification.
func GetClaimsFromRequest(r *http.Request, opts ParseOptions) (interface{}, error) {
	tok, err := ParseFromRequest(r, opts)
	if err != nil {
		return nil, err
	}
	return tok.Claims, nil
}

// GetClaimsAsFromRequest parses from request and unmarshals into dst (pointer).
func GetClaimsAsFromRequest(r *http.Request, opts ParseOptions, dst interface{}) error {
	claims, err := GetClaimsFromRequest(r, opts)
	if err != nil {
		return err
	}
	return CastJwtClaimsToCustomClaims(claims, dst)
}

func newJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func ensureUniqueClaims(claims jwt.Claims) jwt.Claims {
	now := time.Now().UTC()

	switch c := claims.(type) {
	case jwt.MapClaims:
		if _, ok := c["iat"]; !ok {
			c["iat"] = now.Unix()
		}
		if _, ok := c["jti"]; !ok {
			c["jti"] = newJTI()
		}
		return c

	case *jwt.RegisteredClaims:
		if c.IssuedAt == nil {
			c.IssuedAt = jwt.NewNumericDate(now)
		}
		if c.ID == "" {
			c.ID = newJTI()
		}
		return c

	default:
		m := jwt.MapClaims{}
		if b, err := json.Marshal(c); err == nil {
			_ = json.Unmarshal(b, &m)
		}

		if _, ok := m["iat"]; !ok {
			m["iat"] = now.Unix()
		}

		if _, ok := m["jti"]; !ok {
			m["jti"] = newJTI()
		}

		return m
	}
}

func extractTokenString(r *http.Request, opts ParseOptions) (string, error) {
	// 1) Authorization header
	if h := r.Header.Get("Authorization"); h != "" {
		if token := parseBearerHeader(h); token != "" {
			return token, nil
		}
	}

	// 2) Cookie
	if opts.CookieName != "" {
		if c, err := r.Cookie(opts.CookieName); err == nil && c != nil && strings.TrimSpace(c.Value) != "" {
			return c.Value, nil
		}
	}

	// 3) Query param
	if opts.QueryParam != "" {
		if v := strings.TrimSpace(r.URL.Query().Get(opts.QueryParam)); v != "" {
			return v, nil
		}
	}

	return "", errors.New("token not found in request")
}

func parseBearerHeader(headerVal string) string {
	// Accepts case-insensitive "Bearer <token>"
	parts := strings.Fields(headerVal)
	if len(parts) != 2 {
		return ""
	}
	if strings.ToLower(parts[0]) != "bearer" {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
