package handlers

import (
	"github.com/gofiber/fiber/v2"

	"role-auth-api/database"
)

// GetProfile is an authenticated endpoint accessible to both 'admin' and 'user'.
// It retrieves the authenticated user's ID and role from context.
func GetProfile(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	role, _ := c.Locals("role").(string)

	user, err := database.DB.FindByID(userID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "User record not found",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Access granted to authenticated profile",
		"user": fiber.Map{
			"id":    user.ID,
			"name":  user.Name,
			"email": user.Email,
			"role":  role,
		},
	})
}

// AdminDashboard is an admin-only endpoint protected by RequireRole("admin").
func AdminDashboard(c *fiber.Ctx) error {
	adminID, _ := c.Locals("user_id").(string)
	role, _ := c.Locals("role").(string)

	return c.JSON(fiber.Map{
		"message":  "Welcome to the Admin Dashboard",
		"admin_id": adminID,
		"role":     role,
		"stats": fiber.Map{
			"active_services": 12,
			"database_status": "Healthy",
			"security_level":  "High",
		},
	})
}
