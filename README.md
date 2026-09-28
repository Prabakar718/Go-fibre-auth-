# Go Fiber Auth & Role-Based Authorization API

A REST API built with **Go**, **Fiber**, and **JWT** demonstrating user registration, password hashing with **bcrypt**, JWT authentication, and role-based access control (RBAC).

---

## 🚀 Features

- **User Registration (`POST /api/register`)**:
  - Fields: `name`, `email`, `password`, `role`
  - Validates allowed roles: `admin`, `user`
  - Hashes passwords securely with **bcrypt**
  - Enforces unique email addresses
- **User Login (`POST /api/login`)**:
  - Validates credentials against bcrypt password hashes
  - Issues a signed JWT access token containing `user_id`, `role`, and `exp`
- **Authentication Middleware (`middleware.AuthMiddleware()`)**:
  - Extracts JWT token from the `Authorization: Bearer <token>` header
  - Validates HMAC-SHA256 signature and token expiration
  - Stores authenticated user's ID and role in Fiber context (`c.Locals("user_id")`, `c.Locals("role")`)
  - Returns `401 Unauthorized` for missing, malformed, or expired tokens
- **Authorization Middleware (`middleware.RequireRole("admin")`)**:
  - Checks user role stored in context against required role(s)
  - Returns `403 Forbidden` if permissions are insufficient

---

## 📁 Project Structure

```
├── database/
│   └── database.go      # Thread-safe in-memory user repository
├── handlers/
│   ├── auth.go          # Register and Login handlers
│   └── protected.go     # Protected profile & admin endpoints
├── middleware/
│   └── auth.go          # AuthMiddleware and RequireRole middlewares
├── models/
│   └── user.go          # User struct, request/response models & JWT claims
├── go.mod               # Go module dependencies
├── main.go              # Server initialization & route declarations
└── README.md            # Documentation & testing guide
```

---

## 🛠️ Getting Started

### 1. Install Dependencies
```bash
go mod tidy
```

### 2. Run the Application
```bash
go run main.go
```
The server will start listening at: `http://localhost:3000`

---

## 📡 API Endpoints

### 1. User Registration
- **URL**: `POST /api/register`
- **Body**:
```json
{
  "name": "Alice Admin",
  "email": "admin@example.com",
  "password": "secretPassword123",
  "role": "admin"
}
```
- **Response** (`201 Created`):
```json
{
  "message": "User registered successfully",
  "user": {
    "id": "c1f7f62d-0b73-42e5-bc7b-9c60f2bb9d30",
    "name": "Alice Admin",
    "email": "admin@example.com",
    "role": "admin"
  }
}
```

---

### 2. User Login
- **URL**: `POST /api/login`
- **Body**:
```json
{
  "email": "admin@example.com",
  "password": "secretPassword123"
}
```
- **Response** (`200 OK`):
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 86400,
  "user": {
    "id": "c1f7f62d-0b73-42e5-bc7b-9c60f2bb9d30",
    "name": "Alice Admin",
    "email": "admin@example.com",
    "role": "admin"
  }
}
```

---

### 3. Authenticated Profile (Any Authenticated User)
- **URL**: `GET /api/profile`
- **Headers**: `Authorization: Bearer <access_token>`
- **Response** (`200 OK`):
```json
{
  "message": "Access granted to authenticated profile",
  "user": {
    "id": "c1f7f62d-0b73-42e5-bc7b-9c60f2bb9d30",
    "name": "Alice Admin",
    "email": "admin@example.com",
    "role": "admin"
  }
}
```

---

### 4. Admin-Only Dashboard (`RequireRole("admin")`)
- **URL**: `GET /api/admin/dashboard`
- **Headers**: `Authorization: Bearer <access_token>`
- **Response for Admin (`200 OK`)**:
```json
{
  "admin_id": "c1f7f62d-0b73-42e5-bc7b-9c60f2bb9d30",
  "message": "Welcome to the Admin Dashboard",
  "role": "admin",
  "stats": {
    "active_services": 12,
    "database_status": "Healthy",
    "security_level": "High"
  }
}
```
- **Response for Standard User (`403 Forbidden`)**:
```json
{
  "error": "Forbidden: insufficient permissions to access this resource"
}
```

---

## 🧪 Testing with cURL

```bash
# 1. Register an Admin
curl -X POST http://localhost:3000/api/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Admin User","email":"admin@example.com","password":"password123","role":"admin"}'

# 2. Register a Regular User
curl -X POST http://localhost:3000/api/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Regular User","email":"user@example.com","password":"password123","role":"user"}'

# 3. Login as Admin
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"password123"}'

# 4. Access Admin Route with Token
curl -X GET http://localhost:3000/api/admin/dashboard \
  -H "Authorization: Bearer <YOUR_ADMIN_TOKEN>"

# 5. Try accessing Admin Route with User Token (Will return 403 Forbidden)
curl -X GET http://localhost:3000/api/admin/dashboard \
  -H "Authorization: Bearer <YOUR_USER_TOKEN>"
```
