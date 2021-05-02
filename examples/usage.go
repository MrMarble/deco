package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/mrmarble/deco"
)

func main() {
	c := deco.New("192.168.1.1")
	err := c.Authenticate("router_password")
	if err != nil {
		log.Fatal(err.Error())
	}

	printPerformance(c)
	printDevices(c)
}

func printPerformance(c *deco.Client) {
	fmt.Println("[+] Permormance")
	result, err := c.Performance()
	if err != nil {
		log.Fatal(err.Error())
	}
	// Print response as json
	jsonData, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(jsonData))
}

func printDevices(c *deco.Client) {
	fmt.Println("[+] Devices")
	result, err := c.ClientList()
	if err != nil {
		log.Fatal(err.Error())
	}
	for _, device := range result.Result.ClientList {

		fmt.Printf("%s\n - Online: %t\n", device.Name, device.Online)
	}
}
