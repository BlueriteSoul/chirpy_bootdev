package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	claims := jwt.RegisteredClaims{
		Issuer:    "chirpy",
		Subject:   userID.String(),
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiresIn)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	// Parse and validate the token
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(tokenSecret), nil
	})

	if err != nil {
		return uuid.Nil, err // Token invalid or expired
	}

	// Extract claims
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || !token.Valid {
		return uuid.Nil, errors.New("invalid token")
	}

	// Parse user ID from Subject field
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil, errors.New("invalid user ID in token")
	}

	return userID, nil

}

func GetBearerToken(headers http.Header) (string, error) {
	// 1. Get the Authorization header
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		// If header doesn't exist, return an error
		return "", fmt.Errorf("Authorization header not found")
	}

	// 2. Check if it starts with "Bearer "
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", fmt.Errorf("Authorization header format must be 'Bearer {token}'")
	}

	// 3. Extract the token part (removing "Bearer " prefix)
	// The token starts after "Bearer " (index 7)
	token := strings.TrimSpace(authHeader[7:])

	if token == "" {
		return "", fmt.Errorf("Token not found in Authorization header")
	}

	return token, nil
}

func MakeRefreshToken() (string, error) {
	// Create a 32-byte slice
	bytes := make([]byte, 32)

	// Fill it with cryptographically secure random data
	_, err := rand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}

	// Convert the random bytes to a hex string
	return hex.EncodeToString(bytes), nil
}

func GetAPIPolkaKey(headers http.Header) (string, error) {
	// Get the Authorization header
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("authorization header missing")
	}

	// Split the Authorization header into parts (ApiKey and actual key)
	parts := strings.Fields(authHeader)
	if len(parts) != 2 || parts[0] != "ApiKey" {
		return "", errors.New("invalid authorization header format")
	}

	// Return the API key (second part)
	return parts[1], nil
}
