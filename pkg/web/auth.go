// Package web provides authentication for the TOTVS Horus dashboard.
package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// User represents a dashboard user.
type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"` // admin, viewer
	CreatedAt    time.Time `json:"created_at"`
}

// Session represents an authenticated session.
type Session struct {
	Token     string
	UserID    string
	Username  string
	Role      string
	ExpiresAt time.Time
}

// AuthService handles authentication.
type AuthService struct {
	mu       sync.RWMutex
	users    map[string]*User
	sessions map[string]*Session
	jwtSecret string
}

// NewAuthService creates a new auth service.
func NewAuthService(jwtSecret string) *AuthService {
	return &AuthService{
		users:     make(map[string]*User),
		sessions:  make(map[string]*Session),
		jwtSecret: jwtSecret,
	}
}

// CreateUser creates a new user.
func (s *AuthService) CreateUser(username, password, role string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[username]; exists {
		return nil, fmt.Errorf("user %s already exists", username)
	}

	user := &User{
		ID:        generateID(),
		Username:  username,
		Role:      role,
		CreatedAt: time.Now().UTC(),
	}
	user.PasswordHash = hashPassword(password)
	s.users[username] = user

	return user, nil
}

// Authenticate validates credentials and returns a session.
func (s *AuthService) Authenticate(username, password string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, ok := s.users[username]
	if !ok {
		return nil, fmt.Errorf("invalid credentials")
	}

	if !verifyPassword(password, user.PasswordHash) {
		return nil, fmt.Errorf("invalid credentials")
	}

	session := &Session{
		Token:     generateToken(),
		UserID:    user.ID,
		Username:  user.Username,
		Role:      user.Role,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	s.sessions[session.Token] = session

	return session, nil
}

// ValidateSession validates a session token.
func (s *AuthService) ValidateSession(token string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, ok := s.sessions[token]
	if !ok {
		return nil, fmt.Errorf("invalid session")
	}

	if time.Now().After(session.ExpiresAt) {
		delete(s.sessions, token)
		return nil, fmt.Errorf("session expired")
	}

	return session, nil
}

// Logout invalidates a session.
func (s *AuthService) Logout(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
}

// HasPermission checks if a user has a specific permission.
func (s *AuthService) HasPermission(session *Session, permission string) bool {
	switch session.Role {
	case "admin":
		return true
	case "viewer":
		return permission == "read"
	default:
		return false
	}
}

// AuthMiddleware returns the Gin auth middleware.
func (s *AuthService) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		session, err := s.ValidateSession(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		c.Set("user", session)
		c.Next()
	}
}

// GetCurrentSession returns the current session from context.
func GetCurrentSession(c *gin.Context) *Session {
	session, _ := c.Get("user")
	if s, ok := session.(*Session); ok {
		return s
	}
	return nil
}

// Helper functions

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func hashPassword(password string) string {
	// Simple hash for demo - use bcrypt in production
	return base64.StdEncoding.EncodeToString([]byte(password))
}

func verifyPassword(password, hash string) bool {
	expected := base64.StdEncoding.EncodeToString([]byte(password))
	return subtle.ConstantTimeCompare([]byte(hash), []byte(expected)) == 1
}
