package main

import (
	"fmt"
	"time"
)

func main() {
	go startCronJob()

	server := NewAPIServer(":8080")
	server.Run()
}

func startCronJob() {
	fmt.Println("Starting Cron job to keep pinging!")

	// Define a ticker that ticks every 6 min
	ticker := time.NewTicker(360 * time.Second)

	// Start an infinite loop to perform the task periodically
	for {
		select {
		case <-ticker.C:
			// Ping the health endpoint
			fmt.Printf("Cron ping - keeping it alive!")
		}
	}
}
