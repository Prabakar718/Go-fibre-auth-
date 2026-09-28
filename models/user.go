package models

import "github.com/golang-jwt/jwt/v5"

// Role constants
const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

// User represents the user entity in the database
type User struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"-"` // Omit password hash in JSON responses
	Role     string `json:"role"`
}

// RegisterRequest defines the input payload for user registration
type RegisterRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

// LoginRequest defines the input payload for user login
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginResponse defines the JWT response returned after successful login
type LoginResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"` // Expiration time in seconds
	User        User   `json:"user"`
}

// JWTClaims defines the payload stored inside the signed JWT token
type JWTClaims struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}
