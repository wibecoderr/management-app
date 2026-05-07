package storex

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
)

var validate = validator.New()

// ─── HTTP helpers ────────────────────────────────────────────

func RespondJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func RespondError(w http.ResponseWriter, status int, err error, msg string) {
	body := map[string]string{"error": msg}
	if err != nil {
		body["detail"] = err.Error()
	}
	RespondJSON(w, status, body)
}

func RespondValidationError(w http.ResponseWriter, errs map[string]string) {
	RespondJSON(w, http.StatusUnprocessableEntity, map[string]interface{}{
		"error":  "validation failed",
		"fields": errs,
	})
}

func ParseBody(body io.ReadCloser, dst interface{}) error {
	defer body.Close()
	return json.NewDecoder(body).Decode(dst)
}

func ValidateStruct(s interface{}) map[string]string {
	if err := validate.Struct(s); err != nil {
		errs := make(map[string]string)
		for _, fe := range err.(validator.ValidationErrors) {
			errs[fe.Field()] = fe.Tag()
		}
		return errs
	}
	return nil
}

// ─── JWT ────────────────────────────────────────────────────

type jwtClaims struct {
	UserID    string `json:"user_id"`
	SessionID string `json:"session_id"`
	jwt.RegisteredClaims
}

func jwtSecret() []byte {
	s := os.Getenv("JWT_SECRET")
	if s == "" {
		s = "change-me-in-production"
	}
	return []byte(s)
}

func GenerateJWT(userID, sessionID string) (string, error) {
	claims := jwtClaims{
		UserID:    userID,
		SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret())
}

func VerifyJWT(tokenStr string) (userID string, sessionID string, err error) {
	token, err := jwt.ParseWithClaims(tokenStr, &jwtClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return jwtSecret(), nil
	})
	if err != nil {
		return "", "", err
	}

	claims, ok := token.Claims.(*jwtClaims)
	if !ok || !token.Valid {
		return "", "", fmt.Errorf("invalid token")
	}

	return claims.UserID, claims.SessionID, nil
}
