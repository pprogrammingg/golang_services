package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"pprogrammingg/go_services/utils"
	"strconv"

	"github.com/joho/godotenv"
)

var (
	ENCODED_ENCRYPTED_JSON_MSG_PATH string
	ENCODED_ENCRYPTED_AES_KEY_PATH  string
)

func init() {
	log.Printf("api.go init")
	// Load environment variables from .env file
	if os.Getenv("GO_ENVIRONMENT") == "local" {
		log.Printf("detected local env")
		if err := godotenv.Load(); err != nil {
			log.Fatalf("Error loading .env file: %v", err)
		}
	}

	// Assign environment variables to package-level variables
	ENCODED_ENCRYPTED_JSON_MSG_PATH = os.Getenv("ENCODED_ENCRYPTED_JSON_MSG_PATH")
	ENCODED_ENCRYPTED_AES_KEY_PATH = os.Getenv("ENCODED_ENCRYPTED_AES_KEY_PATH")
}

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
	router.HandleFunc("GET /ping", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ping : make server alive"))
	})

	// return nft_id  given sequence
	router.HandleFunc("POST /make_nft_id", HandleProduceNftIdFromSequence)

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
		if token != os.Getenv("FRONT_END_TO_DLT_API_KEY") {
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

type DecryptionResult struct {
	DecryptedJSON []byte
	Err           error
}

func decrypt_msg_key() DecryptionResult {
	// Encrypt AES key with RSA public key
	rsaPrivateKey, err := utils.LoadPrivateKeyFromSecretFile()
	if err != nil {
		log.Printf("Failed to load private key: %v", err)
		return DecryptionResult{nil, err}
	}

	// Decrypt AES key with RSA private key

	// Read encoded AES key from file
	encodedAESKeyFromFile, err := os.ReadFile(ENCODED_ENCRYPTED_AES_KEY_PATH)
	if err != nil {
		log.Printf("Failed to read encoded encrypted AES key from file, %v", err)
		return DecryptionResult{nil, err}
	}

	// Decode base64-encoded AES key
	encryptedAESKeyFromFile, err := base64.StdEncoding.DecodeString(string(encodedAESKeyFromFile))

	decryptedAESKey, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPrivateKey, encryptedAESKeyFromFile, nil)

	encodedEncryptedJSONFromFile, err := os.ReadFile(ENCODED_ENCRYPTED_JSON_MSG_PATH)
	if err != nil {
		log.Printf("Failed to read encoded encrypted JSON message from file, %v", err)
		return DecryptionResult{nil, err}
	}

	// debug
	// encodedJSONMsg, _ := json.Marshal(map[string]string{"encoded_json_msg": string(encodedEncryptedJSONFromFile)})
	// w.Header().Set("Content-Type", "application/json")
	// w.Write(encodedJSONMsg)

	// Decode base64-encoded encrypted JSON
	encryptedAESJsonFromFile, err := base64.StdEncoding.DecodeString(string(encodedEncryptedJSONFromFile))

	// Decrypt JSON message with AES key
	decryptedJSON, _ := utils.DecryptHybrid(encryptedAESJsonFromFile, decryptedAESKey)
	if err != nil {
		log.Printf("Failed to decrypt JSON using AES key, %v", err)
		return DecryptionResult{nil, err}
	}

	return DecryptionResult{decryptedJSON, nil}
}

func HandleProduceNftIdFromSequence(w http.ResponseWriter, r *http.Request) {

	result := decrypt_msg_key()
	if result.Err != nil {
		// Handle error
		log.Printf("Failed to decrypt message: %v", result.Err)
		http.Error(w, "Failed to decrypt message", http.StatusInternalServerError)
		return
	} else {
		var shuffled_array []int
		err := json.Unmarshal(result.DecryptedJSON, &shuffled_array)
		if err != nil {
			fmt.Printf("Error unmarshaling JSON: %v", err)
			http.Error(w, "Error unmarshaling JSON", http.StatusInternalServerError)
			return
		} else {
			// Extract sequence field value from request
			// Read request body
			requestBody, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Failed to read request body", http.StatusInternalServerError)
				return
			}
			defer r.Body.Close()

			// Parse JSON request body
			var requestData struct {
				Sequence string `json:"sequence"`
			}
			if err := json.Unmarshal(requestBody, &requestData); err != nil {
				http.Error(w, "Failed to parse request body", http.StatusBadRequest)
				return
			}

			sequence := requestData.Sequence

			if sequence == "" {
				http.Error(w, "Sequence field is empty", http.StatusBadRequest)
				return
			}

			// Convert sequence string to int
			index, err := strconv.Atoi(sequence)
			if err != nil {
				http.Error(w, "Invalid sequence value", http.StatusBadRequest)
				return
			}

			// Check if index is within bounds of shuffled array
			if index < 0 || index >= len(shuffled_array) {
				http.Error(w, "Index out of range", http.StatusBadRequest)
				return
			}

			// Return the value at the index as JSON output
			response := struct {
				Value int `json:"value"`
			}{
				Value: shuffled_array[index],
			}

			// Write JSON response
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		}
	}
}
