package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/jasonlvhit/gocron"
)

func main() {
	go executeCronJob()
	server := NewAPIServer(":8080")
	server.Run()
}

func myTask() {
	fmt.Println("ping: hey server stay alive!!!")

	// Create a new HTTP request with the GET method and the /ping endpoint
	req, err := http.NewRequest("GET", "http://localhost:8080/api/v1/ping", nil)
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return
	}

	// Set the "Authorization" header with the value of os.Getenv("FRONT_END_TO_DLT_API_KEY")
	req.Header.Set("Authorization", os.Getenv("FRONT_END_TO_DLT_API_KEY"))

	// Make the HTTP request using the default client
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Error pinging server:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Server ping failed with status code: %d\n", resp.StatusCode)
	} else {
		fmt.Println("Server pinged successfully")
	}
}

func executeCronJob() {
	gocron.Every(5).Minute().Do(myTask)
	<-gocron.Start()
}
