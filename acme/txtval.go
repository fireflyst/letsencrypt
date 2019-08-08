package acme

import (
	"net"
)

func TxtChange(name string)(textList []string) {
	textList, err := net.LookupTXT(name)
	if err != nil {
		textList = []string{}
		return
	}
	return textList
}