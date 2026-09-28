package main

import (
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// ---------------------------------------------------------
// Constants & Models
// ---------------------------------------------------------

var JWTSecret = []byte("super-secret-jwt-key-change-in-production")

const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

type User struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"-"`
	Role     string `json:"role"`
}

type RegisterRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	User        User   `json:"user"`
}

type JWTClaims struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// ---------------------------------------------------------
// Thread-Safe In-Memory Database
// ---------------------------------------------------------

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrEmailAlreadyExists = errors.New("email already registered")
)

type UserStore struct {
	mu      sync.RWMutex
	users   map[string]User
	byEmail map[string]string
}

var DB = &UserStore{
	users:   make(map[string]User),
	byEmail: make(map[string]string),
}

func (s *UserStore) CreateUser(u User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	normalizedEmail := strings.ToLower(strings.TrimSpace(u.Email))
	if _, exists := s.byEmail[normalizedEmail]; exists {
		return ErrEmailAlreadyExists
	}
	s.users[u.ID] = u
	s.byEmail[normalizedEmail] = u.ID
	return nil
}

func (s *UserStore) FindByEmail(email string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	normalizedEmail := strings.ToLower(strings.TrimSpace(email))
	userID, exists := s.byEmail[normalizedEmail]
	if !exists {
		return User{}, ErrUserNotFound
	}
	u, ok := s.users[userID]
	if !ok {
		return User{}, ErrUserNotFound
	}
	return u, nil
}

func (s *UserStore) FindByID(id string) (User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	u, exists := s.users[id]
	if !exists {
		return User{}, ErrUserNotFound
	}
	return u, nil
}

// ---------------------------------------------------------
// Middlewares
// ---------------------------------------------------------

// AuthMiddleware extracts and validates JWT from Authorization: Bearer <token>
func AuthMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Missing Authorization header",
			})
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid Authorization header format. Use 'Bearer <token>'",
			})
		}

		tokenString := strings.TrimSpace(parts[1])
		claims := &JWTClaims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fiber.ErrUnauthorized
			}
			return JWTSecret, nil
		})

		if err != nil || !token.Valid {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid or expired token",
			})
		}

		// Store authenticated user's ID and role in Fiber context
		c.Locals("user_id", claims.UserID)
		c.Locals("role", claims.Role)

		return c.Next()
	}
}

// RequireRole checks if the authenticated user has the necessary role
func RequireRole(allowedRoles ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userRole, ok := c.Locals("role").(string)
		if !ok || userRole == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Unauthorized: role not found in context",
			})
		}

		for _, role := range allowedRoles {
			if strings.EqualFold(userRole, role) {
				return c.Next()
			}
		}

		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "Forbidden: insufficient permissions",
		})
	}
}

// ---------------------------------------------------------
// Handlers
// ---------------------------------------------------------

// Register handles POST /api/register
func Register(c *fiber.Ctx) error {
	var req RegisterRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}

	req.Name = strings.TrimSpace(req.Name)
	req.Email = strings.TrimSpace(req.Email)
	req.Role = strings.ToLower(strings.TrimSpace(req.Role))

	if req.Name == "" || req.Email == "" || req.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Name, email, and password are required",
		})
	}

	if len(req.Password) < 6 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Password must be at least 6 characters long",
		})
	}

	if req.Role != RoleAdmin && req.Role != RoleUser {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Role must be 'admin' or 'user'",
		})
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to hash password"})
	}

	user := User{
		ID:       uuid.New().String(),
		Name:     req.Name,
		Email:    req.Email,
		Password: string(hashedPassword),
		Role:     req.Role,
	}

	if err := DB.CreateUser(user); err != nil {
		if err == ErrEmailAlreadyExists {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "Email is already registered"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create user"})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": "User registered successfully",
		"user": fiber.Map{
			"id":    user.ID,
			"name":  user.Name,
			"email": user.Email,
			"role":  user.Role,
		},
	})
}

// Login handles POST /api/login
func Login(c *fiber.Ctx) error {
	var req LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
	}

	user, err := DB.FindByEmail(req.Email)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid email or password"})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid email or password"})
	}

	tokenDuration := 24 * time.Hour
	expirationTime := time.Now().Add(tokenDuration)

	claims := JWTClaims{
		UserID: user.ID,
		Role:   user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   user.ID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(JWTSecret)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate token"})
	}

	return c.Status(fiber.StatusOK).JSON(LoginResponse{
		AccessToken: tokenString,
		TokenType:   "Bearer",
		ExpiresIn:   int64(tokenDuration.Seconds()),
		User: User{
			ID:    user.ID,
			Name:  user.Name,
			Email: user.Email,
			Role:  user.Role,
		},
	})
}

func GetProfile(c *fiber.Ctx) error {
	userID, _ := c.Locals("user_id").(string)
	role, _ := c.Locals("role").(string)

	user, err := DB.FindByID(userID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}

	return c.JSON(fiber.Map{
		"message": "Authenticated user profile",
		"user": fiber.Map{
			"id":    user.ID,
			"name":  user.Name,
			"email": user.Email,
			"role":  role,
		},
	})
}

func AdminDashboard(c *fiber.Ctx) error {
	adminID, _ := c.Locals("user_id").(string)
	role, _ := c.Locals("role").(string)

	return c.JSON(fiber.Map{
		"message":  "Welcome to Admin Dashboard",
		"admin_id": adminID,
		"role":     role,
		"data":     "Sensitive admin statistics & system controls",
	})
}

// ---------------------------------------------------------
// Server Main
// ---------------------------------------------------------

func main() {
	app := fiber.New()

	app.Use(logger.New())
	app.Use(recover.New())
	app.Use(cors.New())

	api := app.Group("/api")

	// 1. User Registration & 2. User Login
	api.Post("/register", Register)
	api.Post("/login", Login)

	// 3. Authentication Middleware
	protected := api.Group("", AuthMiddleware())
	protected.Get("/profile", GetProfile)

	// 4. Authorization Middleware: RequireRole("admin")
	adminGroup := protected.Group("/admin", RequireRole("admin"))
	adminGroup.Get("/dashboard", AdminDashboard)

	log.Println("Server is running on port :3000")
	log.Fatal(app.Listen(":3000"))
}
