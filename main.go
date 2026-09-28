package main

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"

	"role-auth-api/database"
	"role-auth-api/handlers"
	"role-auth-api/middleware"
)

func main() {
	// Initialize in-memory database
	database.InitDB()

	// Initialize Fiber application
	app := fiber.New(fiber.Config{
		AppName: "Go Fiber Auth & Role-Based Authorization API",
	})

	// Global middlewares
	app.Use(logger.New())
	app.Use(recover.New())
	app.Use(cors.New())

	// Welcome / Health check
	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "Go Fiber Auth & Role-Based Authorization API is running",
			"status":  "ok",
		})
	})

	// API route group
	api := app.Group("/api")

	// 1 & 2: Public Authentication Routes
	api.Post("/register", handlers.Register)
	api.Post("/login", handlers.Login)

	// 3: Authenticated Routes (Requires valid JWT in 'Authorization: Bearer <token>')
	protected := api.Group("", middleware.AuthMiddleware())

	// Accessible by any authenticated user (admin or user)
	protected.Get("/profile", handlers.GetProfile)

	// 4: Role-based Protected Route (Requires 'admin' role)
	// Example requirement: RequireRole("admin")
	adminGroup := protected.Group("/admin", middleware.RequireRole("admin"))
	adminGroup.Get("/dashboard", handlers.AdminDashboard)

	// Start server on port 3000
	log.Println("Server running on http://localhost:3000")
	log.Fatal(app.Listen(":3000"))
}
