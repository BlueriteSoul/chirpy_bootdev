package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestMakeJWT(t *testing.T) {
	// Test parameters
	userID := uuid.New()
	tokenSecret := "supersecretkey"
	expiresIn := 2 * time.Hour

	// Call the function to generate a JWT
	token, err := MakeJWT(userID, tokenSecret, expiresIn)

	// Assertions
	assert.NoError(t, err)         // No error should occur
	assert.NotEmpty(t, token)      // The token should not be empty
	assert.Contains(t, token, ".") // JWT token should have 3 parts separated by "."
}

func TestValidateJWT(t *testing.T) {
	// Test parameters
	userID := uuid.New()
	tokenSecret := "supersecretkey"
	expiresIn := 2 * time.Hour

	// Generate a token
	token, err := MakeJWT(userID, tokenSecret, expiresIn)
	assert.NoError(t, err) // Ensure token creation didn't fail

	// Validating the generated token
	validUserID, err := ValidateJWT(token, tokenSecret)
	assert.NoError(t, err)               // No error should occur
	assert.Equal(t, userID, validUserID) // User ID from token should match the original user ID

	// Test with an invalid token (wrong secret key)
	invalidUserID, err := ValidateJWT(token, "wrongsecretkey")
	assert.Error(t, err)                     // Error should occur (invalid signature)
	assert.Equal(t, uuid.Nil, invalidUserID) // Should return empty UUID (invalid token)

	// Test with an expired token
	expiredToken, err := MakeJWT(userID, tokenSecret, -time.Second) // Token that expired already
	assert.NoError(t, err)

	// Wait a little bit to ensure the expiration time has passed
	time.Sleep(1 * time.Second)

	// Try validating the expired token
	expiredUserID, err := ValidateJWT(expiredToken, tokenSecret)
	assert.Error(t, err)                     // Error should occur (token expired)
	assert.Equal(t, uuid.Nil, expiredUserID) // Should return empty UUID (expired token)
}
