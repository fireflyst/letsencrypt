package main

import (
	"context"
	"fmt"
	"os"
	
	"github.com/ovmvo/letsencrypt"
)

func main() {
	domains := []string{"example.com","www.example.com"}
	path := domains[0]
	ctx := context.Background()
	_, err := os.Stat(path)
	if err != nil {
		err = os.Mkdir(path,644)
		if err != nil {
			fmt.Println(0, err)
		}
	}

	c, err := letsencrypt.New(ctx, path + "_ca.key", "test@aaa.com", path)
	if err != nil {
		fmt.Println(1,err)
	}

	//dns changes
	//err = c.Create(ctx,  domain + ".key", domain + ".crt", ":dns", domain, domains...)
	//if err != nil {
	//	fmt.Println(2, err)
	//}

	////http changes
	err = c.Create(ctx,  path + ".key", path + ".crt", ":http", path, domains...)
	if err != nil {
		fmt.Println(2, err)
	}
}