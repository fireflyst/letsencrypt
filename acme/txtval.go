package acme

import (
	"encoding/json"
	"io"
	"net/http"
)

type Mone struct {
	Code  int   `json:"code"`
	Error error `json:"error"`
	Data  Mtwo  `json:"data"`
}

type Mtwo struct {
	Ca []Mthree `json:"01"`
	Hk []Mthree `json:"852"`
	Us []Mthree `json:"86"`
}

type Mthree struct {
	Answer Mfour `json:"answer"`
}

type Mfour struct {
	Timeconsume string `json:"time_consume"`
	Records     []E    `json:"records"`
	Error       string `json:"error"`
}

type E struct {
	Ttl   int    `json:"ttl"`
	Value string `json:"value"`
}

func TxtChange(domain string) (res string) {
	url := "https://myssl.com/api/v1/tools/dns_query?qtype=16&host=" + "_acme-challenge." + domain + "&qmode=-1"
	resp, err := http.Get(url)
	if err != nil {
		return res
	}
	defer resp.Body.Close()
	var jsonstr string
	buf := make([]byte, 2*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n == 0 {
			if err != io.EOF {
				return res
			}
			break
		}
		jsonstr += string(buf[:n])
	}

	var contrast Mone
	err = json.Unmarshal([]byte(jsonstr), &contrast)
	if err != nil {
		return res
	}
	res = contrast.Data.Us[0].Answer.Records[0].Value
	return res
}
