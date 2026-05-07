package handler

import (
	"context"
	"net/http"
	"os"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	utils "github.com/wibecoderr/storex"
	"github.com/wibecoderr/storex/database"
	"github.com/wibecoderr/storex/middleware"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/api/option"
)

var firebaseAuth *auth.Client

// InitFirebase initialises the Firebase Admin SDK.
// Set FIREBASE_CREDENTIALS_JSON env var to the path of your service-account
// JSON file (or the raw JSON string on Railway).
func InitFirebase() {
	credPath := os.Getenv("FIREBASE_CREDENTIALS_JSON")
	if credPath == "" {
		// Firebase auth is optional — skip silently if not configured.
		return
	}

	var opt option.ClientOption
	// If the value looks like a file path use it as a file; otherwise treat as raw JSON.
	if len(credPath) < 300 {
		opt = option.WithCredentialsFile(credPath)
	} else {
		opt = option.WithCredentialsJSON([]byte(credPath))
	}

	app, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		return
	}
	firebaseAuth, _ = app.Auth(context.Background())
}

// ─── Register / Login ────────────────────────────────────────

type registerRequest struct {
	Name     string `json:"name"     validate:"required"`
	Email    string `json:"email"    validate:"required,email"`
	Password string `json:"password" validate:"required,min=6"`
}

func RegisterUser(w http.ResponseWriter, r *http.Request) {
	var body registerRequest
	if err := utils.ParseBody(r.Body, &body); err != nil {
		utils.RespondError(w, http.StatusBadRequest, err, "failed to parse body")
		return
	}
	if errs := utils.ValidateStruct(body); errs != nil {
		utils.RespondValidationError(w, errs)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, err, "failed to hash password")
		return
	}

	var userID string
	err = database.DB.QueryRow(
		`INSERT INTO users (name, email, password_hash, role)
		 VALUES ($1, $2, $3, 'member') RETURNING id`,
		body.Name, body.Email, string(hash),
	).Scan(&userID)
	if err != nil {
		utils.RespondError(w, http.StatusConflict, err, "email already in use")
		return
	}

	utils.RespondJSON(w, http.StatusCreated, map[string]string{"id": userID})
}

type loginRequest struct {
	Email    string `json:"email"    validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

func LoginUser(w http.ResponseWriter, r *http.Request) {
	var body loginRequest
	if err := utils.ParseBody(r.Body, &body); err != nil {
		utils.RespondError(w, http.StatusBadRequest, err, "failed to parse body")
		return
	}
	if errs := utils.ValidateStruct(body); errs != nil {
		utils.RespondValidationError(w, errs)
		return
	}

	var userID, passwordHash string
	err := database.DB.QueryRow(
		`SELECT id, password_hash FROM users WHERE email=$1 AND archived_at IS NULL`,
		body.Email,
	).Scan(&userID, &passwordHash)
	if err != nil {
		utils.RespondError(w, http.StatusUnauthorized, nil, "invalid credentials")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(body.Password)); err != nil {
		utils.RespondError(w, http.StatusUnauthorized, nil, "invalid credentials")
		return
	}

	var sessionID string
	err = database.DB.QueryRow(
		`INSERT INTO sessions (user_id) VALUES ($1) RETURNING id`, userID,
	).Scan(&sessionID)
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, err, "failed to create session")
		return
	}

	token, err := utils.GenerateJWT(userID, sessionID)
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, err, "failed to generate token")
		return
	}

	utils.RespondJSON(w, http.StatusOK, map[string]string{"token": token})
}

func LogoutUser(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserContext(r)
	if user == nil {
		utils.RespondError(w, http.StatusUnauthorized, nil, "unauthorized")
		return
	}

	_, _ = database.DB.Exec(`DELETE FROM sessions WHERE id=$1`, user.SessionId)
	utils.RespondJSON(w, http.StatusOK, map[string]string{"message": "logged out"})
}

// ─── Firebase OAuth ──────────────────────────────────────────

type firebaseLoginRequest struct {
	IDToken string `json:"id_token" validate:"required"`
}

func FirebaseLogin(w http.ResponseWriter, r *http.Request) {
	if firebaseAuth == nil {
		utils.RespondError(w, http.StatusServiceUnavailable, nil, "firebase not configured")
		return
	}

	var body firebaseLoginRequest
	if err := utils.ParseBody(r.Body, &body); err != nil {
		utils.RespondError(w, http.StatusBadRequest, err, "failed to parse body")
		return
	}
	if errs := utils.ValidateStruct(body); errs != nil {
		utils.RespondValidationError(w, errs)
		return
	}

	fbToken, err := firebaseAuth.VerifyIDToken(context.Background(), body.IDToken)
	if err != nil {
		utils.RespondError(w, http.StatusUnauthorized, err, "invalid firebase token")
		return
	}

	email, _ := fbToken.Claims["email"].(string)
	name, _ := fbToken.Claims["name"].(string)
	if name == "" {
		name = email
	}

	var userID string
	err = database.DB.QueryRow(
		`SELECT id FROM users WHERE email=$1 AND archived_at IS NULL`, email,
	).Scan(&userID)
	if err != nil {
		// auto-create on first OAuth login
		err = database.DB.QueryRow(
			`INSERT INTO users (name, email, role) VALUES ($1, $2, 'member') RETURNING id`,
			name, email,
		).Scan(&userID)
		if err != nil {
			utils.RespondError(w, http.StatusInternalServerError, err, "failed to create user")
			return
		}
	}

	var sessionID string
	if err = database.DB.QueryRow(
		`INSERT INTO sessions (user_id) VALUES ($1) RETURNING id`, userID,
	).Scan(&sessionID); err != nil {
		utils.RespondError(w, http.StatusInternalServerError, err, "failed to create session")
		return
	}

	token, err := utils.GenerateJWT(userID, sessionID)
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, err, "failed to generate token")
		return
	}

	utils.RespondJSON(w, http.StatusOK, map[string]string{"token": token})
}

// ─── Admin: Create Employee ──────────────────────────────────

type createEmployeeRequest struct {
	Name     string `json:"name"     validate:"required"`
	Email    string `json:"email"    validate:"required,email"`
	Password string `json:"password" validate:"required,min=6"`
	Role     string `json:"role"     validate:"required,oneof=admin member"`
}

func CreateEmployee(w http.ResponseWriter, r *http.Request) {
	var body createEmployeeRequest
	if err := utils.ParseBody(r.Body, &body); err != nil {
		utils.RespondError(w, http.StatusBadRequest, err, "failed to parse body")
		return
	}
	if errs := utils.ValidateStruct(body); errs != nil {
		utils.RespondValidationError(w, errs)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		utils.RespondError(w, http.StatusInternalServerError, err, "failed to hash password")
		return
	}

	var userID string
	err = database.DB.QueryRow(
		`INSERT INTO users (name, email, password_hash, role)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		body.Name, body.Email, string(hash), body.Role,
	).Scan(&userID)
	if err != nil {
		utils.RespondError(w, http.StatusConflict, err, "email already in use")
		return
	}

	utils.RespondJSON(w, http.StatusCreated, map[string]interface{}{
		"message": "employee created",
		"id":      userID,
		"role":    body.Role,
	})
}

