package main

import (
	"fmt"

	"github.com/jasonlvhit/gocron"
)

func main() {
	go executeCronJob()
	server := NewAPIServer(":8080")
	server.Run()
}

func myTask() {
	fmt.Println("This task will run periodically")
}
func executeCronJob() {
	gocron.Every(6).Minute().Do(myTask)
	<-gocron.Start()
}

// func startPingJob() {
// 	// Define a ticker that ticks every 360 seconds (6 minutes)
// 	ticker := time.NewTicker(2 * time.Second)

// 	// Start an infinite loop to perform the task periodically
// 	for {
// 		select {
// 		case <-ticker.C:
// 			// Perform the ping
// 			if err := pingServer(); err != nil {
// 				fmt.Println("Ping failed:", err)
// 			} else {
// 				fmt.Println("Server pinged successfully")
// 			}
// 		}
// 	}
// }

// func pingServer() error {
// 	url := "https://golang-services.onrender.com"

// 	client := &http.Client{}
// 	req, err := http.NewRequest("GET", url, nil)
// 	if err != nil {
// 		return err
// 	}
// 	// Add custom headers as needed
// 	log.Printf("key is %s", os.Getenv("FRONT_END_TO_DLT_API_KEY"))
// 	req.Header.Add("Authorization", os.Getenv("FRONT_END_TO_DLT_API_KEY"))

// 	// Perform HTTP request
// 	resp, err := client.Do(req)
// 	if err != nil {
// 		return err
// 	}
// 	defer resp.Body.Close()

// 	// Check response status code
// 	if resp.StatusCode != http.StatusOK {
// 		return fmt.Errorf("Server ping failed with status code: %d", resp.StatusCode)
// 	}

// 	return nil
// }
