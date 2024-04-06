package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
)

type APIServer struct {
	addr string
}

// constructor
func NewAPIServer(addr string) *APIServer {
	return &APIServer{addr}
}

func (s *APIServer) Run() error {
	router := http.NewServeMux()

	// only 1 space between method and path
	// if omitted, method is GET by default
	router.HandleFunc("GET /users/{userID}", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Fire router handler")
		userID := r.PathValue("userID")
		w.Write([]byte("User ID " + userID))
	})

	router.HandleFunc("/posts", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Handling request for posts")
		w.Write([]byte("Posts"))
	})

	v1 := http.NewServeMux()
	v1.Handle("/api/v1/", http.StripPrefix("/api/v1", router))

	middlewareChain := MiddlewareChain(
		RequestLoggerMiddleware,
		RequireAuthMiddleware,
	)

	server := http.Server{
		Addr:    s.addr,
		Handler: middlewareChain(v1),
	}

	log.Printf("Serving has started %s", s.addr)

	return server.ListenAndServe()
}

func RequestLoggerMiddleware(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Fire RequestLoggerMiddleware")
		log.Printf("method %s, path: %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	}
}

func RequireAuthMiddleware(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Fire RequireAuthMiddleware")
		// chekc if the user is authenticated
		token := r.Header.Get("Authorization")
		if token != "Bearer token" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	}
}

type Middleware func(http.Handler) http.HandlerFunc

func MiddlewareChain(middlewares ...Middleware) Middleware {
	return func(next http.Handler) http.HandlerFunc {
		for i := len(middlewares) - 1; i >= 0; i-- {
			next = middlewares[i](next)
		}

		return next.ServeHTTP
	}
}

// Function to create and shuffle an array
func createAndShuffleArray() []int {
	// Create an array of size 10001 and assign values to each index
	array := make([]int, 10001)
	for i := 0; i <= 10000; i++ {
		array[i] = i
	}

	// Shuffle the array
	shuffleArray(array)

	return array
}

// Function to shuffle an array
func shuffleArray(array []int) {
	for i := len(array) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		array[i], array[j] = array[j], array[i]
	}
}

func write_ecrypted_shuffled_arr() {

}

func loadPrivateKey() (*rsa.PrivateKey, error) {
	// Read private key file
	privateKeyData, err := os.ReadFile("private_key.pem")
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	// Decode PEM data
	block, _ := pem.Decode(privateKeyData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the private key")
	}

	// Parse RSA private key
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return privateKey.(*rsa.PrivateKey), nil
}
