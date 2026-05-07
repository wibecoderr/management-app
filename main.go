package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/joho/godotenv"
	"github.com/wibecoderr/storex/database"
	server "github.com/wibecoderr/storex/router"
)

func main() {
	// Load .env (ignored if not present — Railway injects env vars directly)
	_ = godotenv.Load()

	// Connect to Postgres
	if err := database.Connect(); err != nil {
		log.Fatalf("database connection failed: %v", err)
	}
	defer database.DB.Close()

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	server.SetUpRoutes(r)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Printf("Server listening on :%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
