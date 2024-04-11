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
	fmt.Println("ping: hey server stay alive!!!")
}
func executeCronJob() {
	gocron.Every(6).Minute().Do(myTask)
	<-gocron.Start()
}
