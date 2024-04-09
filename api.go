package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"pprogrammingg/go_services/utils"
	"reflect"
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
	router.HandleFunc("POST /encrypt_decrypt", HandleEcryptDecryptHybrid)

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

func HandleEcryptDecryptHybrid(w http.ResponseWriter, r *http.Request) {
	// Generate AES key
	aesKey := utils.GenerateAESKey()

	// JSON message
	shuffledIdentityArray := utils.ShuffleArray(utils.CreateIdentityArray(10001))

	// Marshal the array into JSON
	jsonBytes, err := json.Marshal(shuffledIdentityArray)
	if err != nil {
		http.Error(w, "Failed to marshal JSON", http.StatusInternalServerError)
		return
	}

	// Encrypt JSON message
	encryptedJSON, _ := utils.EncryptHybrid(jsonBytes, aesKey)

	// Encrypt AES key with RSA public key
	rsaPrivateKey, err := utils.LoadPrivateKeyFromSecretFile()
	if err != nil {
		http.Error(w, "Failed to load private key ", http.StatusInternalServerError)
		log.Printf("Failed to load private key: %v", err)
		return
	}

	rsaPublicKey := rsaPrivateKey.PublicKey
	encryptedAESKey, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &rsaPublicKey, aesKey, nil)

	// Send encryptedJSON and encryptedAESKey to recipient

	// Decryption (recipient's side)
	// Decrypt AES key with RSA private key
	decryptedAESKey, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPrivateKey, encryptedAESKey, nil)

	// Decrypt JSON message with AES key
	decryptedJSON, _ := utils.DecryptHybrid(encryptedJSON, decryptedAESKey)

	fmt.Println(string(decryptedJSON))

	if !reflect.DeepEqual(decryptedJSON, jsonBytes) {
		fmt.Println("Decrypted JSON does not match expected JSON")
	} else {

		fmt.Println("we are good!")
	}

	w.Write(decryptedJSON)
}
