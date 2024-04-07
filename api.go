package main

import (
	"encoding/json"
	"log"
	"net/http"
	"pprogrammingg/go_services/utils"
)

type APIServer struct {
	addr string
}

// constructor
func NewAPIServer(addr string) *APIServer {
	return &APIServer{addr}
}

// define routes, handlers and middleware
func (s *APIServer) Run() error {
	router := http.NewServeMux()

	// dummy route for testing
	router.HandleFunc("GET /users/{userID}", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Fire router handler")
		userID := r.PathValue("userID")
		w.Write([]byte("User ID " + userID))
	})

	// dummy route for testing
	router.HandleFunc("/posts", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Handling request for posts")
		w.Write([]byte("Posts"))
	})

	// test_encrypt_decrypt
	// 	creates and shuffles an identity array, encrypts and decrypts
	//  as an experiment
	router.HandleFunc("POST /test_encrypt_decrypt", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Handling request for test_encrypt_decrypt")
		shuffledIdentityArray := utils.ShuffleArray(utils.CreateIdentityArray(10001))

		// Marshal the array into JSON
		shuffledJSON, err := json.Marshal(shuffledIdentityArray)
		if err != nil {
			http.Error(w, "Failed to marshal JSON", http.StatusInternalServerError)
			return
		}

		// Set Content-Type header to application/json
		w.Header().Set("Content-Type", "application/json")

		// Write the JSON response
		w.Write(shuffledJSON)
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
		if token != "api_key" {
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
