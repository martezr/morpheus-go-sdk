package main

import (
	"fmt"
	"log"

	"github.com/gomorpheus/morpheus-go-sdk"
)

func main() {
	client := morpheus.NewClient("https://yourmorpheus.com", morpheus.Insecure())
	client.SetUsernameAndPassword("username", "password")
	resp, err := client.Login()
	if err != nil {
		fmt.Println("LOGIN ERROR: ", err)
	}
	fmt.Println("LOGIN RESPONSE:", resp)

	// List clusters
	req := &morpheus.Request{}
	response, err := client.ListClusters(req)
	if err != nil {
		log.Fatal(err)
	}
	result := response.Result.(*morpheus.ListClustersResult)
	log.Println(result.Clusters)

	// List Clusters Datastores
	req = &morpheus.Request{}
	response, err = client.ListClusterDatastores(1, req)
	if err != nil {
		log.Fatal(err)
	}
	datastoreResult := response.Result.(*morpheus.ListClusterDatastoresResults)
	log.Println(datastoreResult.Datastores)
}
