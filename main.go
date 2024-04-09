package main

import (
	"log"

	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	server := NewAPIServer(":8080")
	server.Run()
	// getting path parameters in your handlers
	// middlewares
	// declerative http methods
	// sub-routing

}
