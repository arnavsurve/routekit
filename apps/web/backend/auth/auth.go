package auth

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

type UserCredentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Handler struct {
	DBPool    *pgxpool.Pool
	JWTSecret []byte
}

const jwtExpirationHours = 24

func (h *Handler) HandleSignup(c echo.Context) error {
	var creds UserCredentials
	if err := c.Bind(&creds); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request format."})
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "Server error during signup."})
	}

	_, err = h.DBPool.Exec(context.Background(), "INSERT INTO users (email, password_hash) VALUES ($1, $2)", creds.Email, string(hashedPassword))
	if err != nil {
		log.Printf("Error signing up user: %v", err)
		return c.JSON(http.StatusConflict, map[string]string{"error": "User with this email already exists."})
	}

	return c.JSON(http.StatusCreated, map[string]string{"message": "User created successfully."})
}

func (h *Handler) HandleLogin(c echo.Context) error {
	var creds UserCredentials
	if err := c.Bind(&creds); err != nil {
		return c.JSON(http.StatusBadRequest, "Invalid request")
	}

	var userID, storedHash string
	err := h.DBPool.QueryRow(context.Background(), "SELECT id, password_hash FROM users WHERE email = $1", creds.Email).Scan(&userID, &storedHash)
	if err != nil {
		if err == pgx.ErrNoRows {
			return c.JSON(http.StatusUnauthorized, "Invalid credentials")
		}
		return c.JSON(http.StatusInternalServerError, "Database error")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(creds.Password)); err != nil {
		return c.JSON(http.StatusUnauthorized, "Invalid credentials")
	}

	expiration := time.Now().Add(time.Hour * jwtExpirationHours)
	claims := &Claims{
		UserID:           userID,
		Email:            creds.Email,
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(expiration)},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(h.JWTSecret)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, "Failed to create token")
	}

	c.SetCookie(&http.Cookie{
		Name: "token", Value: tokenString, Expires: expiration, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	return c.JSON(http.StatusOK, map[string]string{"message": "Login successful"})
}

func (h *Handler) HandleGetMe(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*Claims)
	return c.JSON(http.StatusOK, map[string]string{"email": claims.Email})
}

func (h *Handler) AuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		cookie, err := c.Cookie("token")
		if err != nil {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		}

		token, err := jwt.ParseWithClaims(cookie.Value, &Claims{}, func(token *jwt.Token) (any, error) {
			return h.JWTSecret, nil
		})
		if err != nil || !token.Valid {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		}
		c.Set("user", token)
		return next(c)
	}
}
