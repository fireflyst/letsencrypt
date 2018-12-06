package main

import (
	"context"
	"fmt"

	"SSL_Apply/letsencrypt"
)

func main() {
	ctx := context.Background()

	c, err := letsencrypt.New(ctx, "account.key", "test@aaa.com")
	
	if err != nil {
		fmt.Println(1,err)
	}

	// dns changes
	domains := []string{"nvtia.com","www.nvtia.com"}
	err = c.Create(ctx,  "test.key", "test.crt", ":dns", domains...)
	if err != nil {
		fmt.Println(2, err)
	}

	//http changes
	//err = c.Create(ctx,  "test.key", "test.crt", ":http", domains...)
	//if err != nil {
	//	fmt.Println(2, err)
	//}


}