package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"letsencrypt/acme"
	"log"
	"os"
	"strings"
)

type acmeAccount struct {
	Url        string
	PrivateKey string
	Contacts   []string
	Domains    []string
}

type Data struct {
	DirectoryUrl string
	Contacts     string
	Domains      []string
	AccountFile  string
	KeyFile      string
	CertFile     string
}

func main() {
	directoryUrl := acme.LetsEncryptStaging
	//directoryUrl := acme.LetsEncryptProduction
	contactsList := "ssghuo@163.com"
	domains := []string{"nvtia.com", "*.nvtia.com"}
	accountFile := "data/cache/account.json"
	keyFile := "data/ssl/key.pem"
	certFile := "data/ssl/cert.pem"

	data := Data{DirectoryUrl: directoryUrl,
		Contacts:    contactsList,
		Domains:     domains,
		AccountFile: accountFile,
		KeyFile:     keyFile,
		CertFile:    certFile,
	}
	textList, err := ObtainChangeDns(data)
	if err != nil {
		log.Println(err)
	}
	log.Println(textList)
	for _, texts := range textList {
		for name, text := range texts {
			log.Println(name, " : ", text)
			//err := VarChangeDns(name, text)
			//if err != nil {
			//	log.Println(err)
			//}
		}
	}
	if err := ChangeDns(data); err != nil {
		log.Println(err)
	}
}

func ChangeDns(data Data) (err error) {
	client, err := acme.NewClient(data.DirectoryUrl)
	if err != nil {
		log.Fatalf("Error connecting to acme directory: %v", err)
		return err
	}
	account, err := loadAccount(client, data.AccountFile)
	if err != nil {
		return err
	}

	var ids []acme.Identifier
	for _, domain := range data.Domains {
		ids = append(ids, acme.Identifier{Type: "dns", Value: domain})
	}
	order, err := client.NewOrder(account, ids)
	if err != nil {
		log.Fatalf("Error creating new order: %v", err)
		return err
	}
	text := make(chan string)
	for _, authUrl := range order.Authorizations {
		go func(authUrl string) (err error) {
			auth, err := client.FetchAuthorization(account, authUrl)
			if err != nil {
				log.Fatalf("Error fetching authorization url %q: %v", authUrl, err)
				return err
			}
			ch, ok := auth.ChallengeMap[acme.ChallengeTypeDNS01]
			if !ok {
				log.Fatalf("Unable to find dns challenge for auth %s", auth.Identifier.Value)
				return errors.New("Unable to find dns challenge for auth " + auth.Identifier.Value)
			}
			if err := varChangeDns("_acme-challenge."+auth.Identifier.Value, acme.EncodeDNS01KeyAuthorization(ch.KeyAuthorization)); err != nil {
				return err
			}
			ch, err = client.UpdateChallenge(account, ch)
			text <- auth.Identifier.Value
			return nil
		}(authUrl)
	}

	for i := 1; i <= len(data.Domains); i++ {
		 <-text
	}
	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error generating certificate key: %v", err)
	}
	certKeyRsa := x509.MarshalPKCS1PrivateKey(certKey)

	key := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY",
		Bytes: certKeyRsa,
	})
	log.Println(string(key))
	if err := ioutil.WriteFile(data.KeyFile, key, 0600); err != nil {
		return err
	}

	tpl := &x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		PublicKey: certKey.Public(),
		Subject: pkix.Name{CommonName: data.Domains[0]},
		DNSNames: data.Domains,
	}

	csrDer, err := x509.CreateCertificateRequest(rand.Reader, tpl, certKey)
	if err != nil {
		return err
	}
	csr, err := x509.ParseCertificateRequest(csrDer)
	if err != nil {
		return err
	}

	order, err = client.FinalizeOrder(account, order, csr)
	if err != nil {
		return err
	}
	certs, err := client.FetchCertificates(account, order.Certificate)
	if err != nil {
		return err
	}
	var pemData []string
	for _, c := range certs {
		pemData = append(pemData, strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE",
			Bytes: c.Raw,
		}))))
	}
	if err := ioutil.WriteFile(data.CertFile, []byte(strings.Join(pemData, "\n")),0600); err != nil {
		return err
	}
	log.Println(strings.Join(pemData, "\n"))
	return nil
}

func ObtainChangeDns(data Data) ([]map[string]string, error) {
	var txtList []map[string]string
	client, err := acme.NewClient(data.DirectoryUrl)
	if err != nil {
		log.Fatalf("Error connecting to acme directory: %v", err)
		return txtList, err
	}
	account, err := loadAccount(client, data.AccountFile)
	if err != nil {
		log.Println("no account.json")
		account, err = createAccount(client, data.AccountFile, data.Contacts, data.Domains)
		if err != nil {
			log.Fatalf("Error creaing new account: %v", err)
			return txtList, err
		}
	}

	var ids []acme.Identifier
	for _, domain := range data.Domains {
		ids = append(ids, acme.Identifier{Type: "dns", Value: domain})
	}
	order, err := client.NewOrder(account, ids)
	if err != nil {
		log.Fatalf("Error creating new order: %v", err)
		return txtList, err
	}
	txt := make(chan map[string]string)
	for _, authUrl := range order.Authorizations {
		go func(authUrl string) {
			auth, err := client.FetchAuthorization(account, authUrl)
			if err != nil {
				log.Fatalf("Error fetching authorization url %q: %v", authUrl, err)
			}
			ch, ok := auth.ChallengeMap[acme.ChallengeTypeDNS01]
			if !ok {
				log.Fatalf("Unable to find dns challenge for auth %s", auth.Identifier.Value)
			}
			data := make(map[string]string)
			data["_acme-challenge."+auth.Identifier.Value] = acme.EncodeDNS01KeyAuthorization(ch.KeyAuthorization)
			txt <- data
		}(authUrl)
	}

	for i := 1; i <= len(data.Domains); i++ {
		txtList = append(txtList, <-txt)
	}
	return txtList, nil
}

func varChangeDns(name, text string) (err error) {
	rest := false
	resList := acme.TxtChange(name)
	for _, res := range resList {
		if res == text {
			rest = true
			break
		}
	}
	if !rest {
		return errors.New("获取验证错误  " + name + " : " + text)
	}
	return nil
}

func loadAccount(client acme.Client, accountFile string) (acme.Account, error) {
	if _, err := os.Stat(accountFile); err != nil {
		return acme.Account{}, err
	}
	b, err := ioutil.ReadFile(accountFile)
	if err != nil {
		return acme.Account{}, err
	}
	var aaccount acmeAccount
	if err := json.Unmarshal(b, &aaccount); err != nil {
		return acme.Account{}, err
	}

	raw, _ := pem.Decode([]byte(aaccount.PrivateKey))
	if raw == nil || raw.Type != "RSA PRIVATE KEY" {
		return acme.Account{}, err
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(raw.Bytes)
	if err != nil {
		return acme.Account{}, err
	}
	acc := acme.Account{PrivateKey: privateKey, URL: aaccount.Url}
	account, err := client.UpdateAccount(acc, true, aaccount.Contacts...)
	if err != nil {
		return acme.Account{}, err
	}
	return account, nil
}

func createAccount(client acme.Client, accountFile,  contactsList string, domains []string) (acme.Account, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return acme.Account{}, err
	}
	account, err := client.NewAccount(key, false, true, getContacts(contactsList)...)
	if err != nil {
		return acme.Account{}, err
	}
	privateKey := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	raw, err := json.Marshal(acmeAccount{PrivateKey: string(privateKey), Url: account.URL, Contacts: getContacts(contactsList)})
	if err != nil {
		return acme.Account{}, err
	}
	if err := ioutil.WriteFile(accountFile, raw, 0600); err != nil {
		return acme.Account{}, err
	}
	return account, nil
}

func getContacts(contactsList string) []string {
	var contacts []string
	if contactsList != "" {
		contacts = strings.Split(contactsList, ",")
		for i := 0; i < len(contacts); i++ {
			contacts[i] = "mailto:" + contacts[i]
		}
	}
	return contacts
}
