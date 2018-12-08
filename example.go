package main

import (
	"context"
	"fmt"

	"github.com/ovmvo/letsencrypt/acme"
)

func main() {
	domains := []string{"example.com", "www.example.com"}
	dir := "aaa"
	name := dir

	ctx := context.Background()
	c, err := acme.New(ctx, dir,"account", "test@example.com", )
	if err != nil {
		fmt.Println(err)
	}

	//dns changes
	err = c.Create(ctx, dir, name, "dns", domains...)
	if err != nil {
		fmt.Println(err)
	}

	////http changes
	//err = c.Create(ctx, dir, name, "http", domains...)
	//if err != nil {
	//	fmt.Println(err)
	//}
}