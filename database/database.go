package database

import (
	"errors"
	"strings"
	"sync"

	"role-auth-api/models"
)

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrEmailAlreadyExists = errors.New("email already registered")
)

// UserStore provides thread-safe in-memory storage for users
type UserStore struct {
	mu      sync.RWMutex
	users   map[string]models.User // keyed by User ID
	byEmail map[string]string      // maps lowercase email -> User ID
}

// Global database instance
var DB *UserStore

// InitDB initializes the in-memory database
func InitDB() {
	DB = &UserStore{
		users:   make(map[string]models.User),
		byEmail: make(map[string]string),
	}
}

// CreateUser saves a new user if email is unique
func (s *UserStore) CreateUser(user models.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	normalizedEmail := strings.ToLower(strings.TrimSpace(user.Email))
	if _, exists := s.byEmail[normalizedEmail]; exists {
		return ErrEmailAlreadyExists
	}

	s.users[user.ID] = user
	s.byEmail[normalizedEmail] = user.ID
	return nil
}

// FindByEmail retrieves a user by their email address
func (s *UserStore) FindByEmail(email string) (models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	normalizedEmail := strings.ToLower(strings.TrimSpace(email))
	userID, exists := s.byEmail[normalizedEmail]
	if !exists {
		return models.User{}, ErrUserNotFound
	}

	user, exists := s.users[userID]
	if !exists {
		return models.User{}, ErrUserNotFound
	}

	return user, nil
}

// FindByID retrieves a user by their unique ID
func (s *UserStore) FindByID(id string) (models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[id]
	if !exists {
		return models.User{}, ErrUserNotFound
	}

	return user, nil
}
