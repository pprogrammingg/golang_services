package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"pprogrammingg/go_services/utils"
	"reflect"

	"github.com/joho/godotenv"
)

var (
	ENCODED_ENCRYPTED_JSON_MSG_PATH string
	ENCODED_ENCRYPTED_AES_KEY_PATH  string
)

func init() {
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

	// decrypt message loaded to env
	router.HandleFunc("POST /decrypt", HandleDecryptMsgFromEnv)

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

	ENCODED_ENCRYPTED_JSON_MSG_PATH := os.Getenv("ENCODED_ENCRYPTED_JSON_MSG_PATH")
	ENCODED_ENCRYPTED_AES_KEY_PATH := os.Getenv("ENCODED_ENCRYPTED_AES_KEY_PATH")

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

	// Encode encrypted JSON to base64
	encodedJSON := base64.StdEncoding.EncodeToString(encryptedJSON)

	// Write encoded encrypted JSON to a file
	if err := os.WriteFile(ENCODED_ENCRYPTED_JSON_MSG_PATH, []byte(encodedJSON), 0644); err != nil {
		http.Error(w, "Failed to write encrypted JSON to file", http.StatusInternalServerError)
		return
	}

	// Encrypt AES key with RSA public key
	rsaPrivateKey, err := utils.LoadPrivateKeyFromSecretFile()
	if err != nil {
		http.Error(w, "Failed to load private key ", http.StatusInternalServerError)
		log.Printf("Failed to load private key: %v", err)
		return
	}

	rsaPublicKey := rsaPrivateKey.PublicKey
	encryptedAESKey, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &rsaPublicKey, aesKey, nil)

	// Encode encrypted AES key to base64
	encodedAESKey := base64.StdEncoding.EncodeToString(encryptedAESKey)

	// Write encoded encrypted AES key to a file
	if err := os.WriteFile(ENCODED_ENCRYPTED_AES_KEY_PATH, []byte(encodedAESKey), 0644); err != nil {
		http.Error(w, "Failed to write encrypted AES key to file", http.StatusInternalServerError)
		return
	}
	// Send encryptedJSON and encryptedAESKey to recipient

	// Decryption (recipient's side)
	// Decrypt AES key with RSA private key

	// Read encoded AES key from file
	encodedAESKeyFromFile, err := os.ReadFile("encrypted_aes_key.txt")
	if err != nil {
		http.Error(w, "Failed to read encoded AES key from file", http.StatusInternalServerError)
		return
	}

	// Decode base64-encoded AES key
	encryptedAESKeyFromFile, err := base64.StdEncoding.DecodeString(string(encodedAESKeyFromFile))

	decryptedAESKey, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPrivateKey, encryptedAESKeyFromFile, nil)

	encodedEncryptedJSONFromFile, err := os.ReadFile("encrypted_json.txt")
	if err != nil {
		// Handle error
	}

	// Decode base64-encoded encrypted JSON
	encryptedAESJsonFromFile, err := base64.StdEncoding.DecodeString(string(encodedEncryptedJSONFromFile))

	// Decrypt JSON message with AES key
	decryptedJSON, _ := utils.DecryptHybrid(encryptedAESJsonFromFile, decryptedAESKey)

	fmt.Println(string(decryptedJSON))

	if !reflect.DeepEqual(decryptedJSON, jsonBytes) {
		fmt.Println("Decrypted JSON does not match expected JSON")
	} else {

		fmt.Println("we are good!")
	}

	w.Write(decryptedJSON)
}

func HandleDecryptMsgFromEnv(w http.ResponseWriter, r *http.Request) {

	// Encrypt AES key with RSA public key
	rsaPrivateKey, err := utils.LoadPrivateKeyFromSecretFile()
	if err != nil {
		http.Error(w, "Failed to load private key ", http.StatusInternalServerError)
		log.Printf("Failed to load private key: %v", err)
		return
	}

	// Decrypt AES key with RSA private key

	// Read encoded AES key from file
	encodedAESKeyFromFile, err := os.ReadFile(ENCODED_ENCRYPTED_AES_KEY_PATH)
	if err != nil {
		http.Error(w, "Failed to read encoded AES key from file", http.StatusInternalServerError)
		return
	}

	// debug
	// encodedAESKeyJSON, _ := json.Marshal(map[string]string{"encoded_aes_key": string(encodedAESKeyFromFile)})
	// w.Header().Set("Content-Type", "application/json")
	// w.Write(encodedAESKeyJSON)

	// Decode base64-encoded AES key
	encryptedAESKeyFromFile, err := base64.StdEncoding.DecodeString(string(encodedAESKeyFromFile))

	decryptedAESKey, _ := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPrivateKey, encryptedAESKeyFromFile, nil)

	encodedEncryptedJSONFromFile, err := os.ReadFile(ENCODED_ENCRYPTED_JSON_MSG_PATH)
	if err != nil {
		http.Error(w, "Failed to read encoded encrypted JSON message from file", http.StatusInternalServerError)
		return
	}

	// debug
	encodedJSONMsg, _ := json.Marshal(map[string]string{"encoded_json_msg": string(encodedEncryptedJSONFromFile)})
	w.Header().Set("Content-Type", "application/json")
	w.Write(encodedJSONMsg)

	// Decode base64-encoded encrypted JSON
	encryptedAESJsonFromFile, err := base64.StdEncoding.DecodeString(string(encodedEncryptedJSONFromFile))

	// Decrypt JSON message with AES key
	decryptedJSON, _ := utils.DecryptHybrid(encryptedAESJsonFromFile, decryptedAESKey)

	fmt.Println(string(decryptedJSON))

	w.Write(decryptedJSON)
}
