package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	math_rand "math/rand"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

func main() {
	log.Println("Loading config ...")

	c, err := loadConfig()

	if err != nil {
		log.Fatalf("Error: %s\n", err)
	}

	log.Println("Attempting to determine public IP ...")

	actualExternalIP, err := doLookup("resolver1.opendns.com", "myip.opendns.com")

	if err != nil {
		log.Fatalf("Unable to determine current public IP: %s", err)
	}

	log.Printf("Current external IP is:    %s\n", actualExternalIP)

	token := ""

	for domain, records := range c.Domains {
		log.Printf("Processing %s ...\n", domain)

		for subdomain, record := range records {
			var lookupDomain string

			switch subdomain {
			case "@":
				lookupDomain = domain
			case "*":
				lookupDomain = "test." + domain
			default:
				lookupDomain = subdomain + "." + domain
			}

			if lookupDomain[0] == '*' {
				lookupDomain = strings.ReplaceAll(lookupDomain, "*", "test")
			}

			configuredExternalIP, err := doLookup("ns0.transip.net", lookupDomain)

			if err != nil {
				log.Printf("Unable to determine configured public IP: %s", err)

				continue
			}

			log.Printf("Configured external IP is: %s\n", configuredExternalIP)

			if configuredExternalIP == actualExternalIP {
				log.Println("Nothing to do, external IP is already properly configured.")

				continue
			}

			if token == "" { // Lazy load the token once, only if it's needed
				pk, err := loadPrivateKey(getEnvWithDefault("TRANSIP_PRIV_KEY_FILE", absolutePath("transip.key")))

				if err != nil {
					log.Fatalf("Unable to load private key: %s", err)
				}

				login := getEnvWithDefault("TRANSIP_USERNAME", "")

				if login == "" {
					log.Fatalf("Unable to load determine login, TRANSIP_USERNAME not set")
				}

				t, err := fetchAPIToken(pk, login)

				if err != nil {
					log.Fatalf("Unable to load fetch API token: %s", err)
				}

				log.Println("API Token successfully retrieved")

				token = t
			}

			request := map[string]interface{}{
				"dnsEntry": map[string]interface{}{
					"name":    subdomain,
					"expire":  record.Ttl,
					"type":    "A",
					"content": actualExternalIP,
				},
			}

			requestBody, err := json.Marshal(request)

			if err != nil {
				log.Printf("Unable to serialize request body for updating '%s' on '%s'\n", subdomain, domain)

				continue
			}

			updateDNSRecordRequest, err := http.NewRequest("PATCH", fmt.Sprintf("https://api.transip.nl/v6/domains/%s/dns", domain), bytes.NewReader(requestBody))

			if err != nil {
				log.Printf("Unable to create HTTP request for updating '%s' on '%s'\n", subdomain, domain)

				continue
			}

			updateDNSRecordRequest.Header.Set("Authorization", "Bearer "+token)

			response, err := http.DefaultClient.Do(updateDNSRecordRequest)

			fmt.Println(fmt.Sprintf("https://api.transip.nl/v6/domains/%s/dns", domain))
			fmt.Println(string(requestBody))
			fmt.Println(response.StatusCode)
			fmt.Println(err)

			b, _ := io.ReadAll(response.Body)

			fmt.Println(string(b))
		}
	}
}

type config struct {
	Domains map[string]domainConfig `yaml:"domains"`
}

type domainConfig map[string]recordConfig

type recordConfig struct {
	Ttl int `yaml:"ttl"`
}

func absolutePath(relativePath string) string {
	exePath, _ := os.Executable()
	exeDir := path.Dir(exePath)

	return path.Join(exeDir, relativePath)
}

func doLookup(dnsHost string, host string) (string, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Millisecond * time.Duration(10000),
			}

			return d.DialContext(ctx, "udp", fmt.Sprintf("%s:53", dnsHost))
		},
	}

	ips, err := r.LookupHost(context.Background(), host)

	if err != nil {
		return "", err
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("cannot resolve %s", host)
	}

	return ips[0], nil
}

func getEnvWithDefault(envVar, defaultValue string) string {
	envValue, ok := os.LookupEnv(envVar)

	if ok {
		return envValue
	}

	return defaultValue
}

func fetchAPIToken(privateKey *rsa.PrivateKey, login string) (string, error) {
	requestData := tokenRequest(login)
	requestJson, err := json.Marshal(requestData)

	if err != nil {
		return "", err
	}

	signature, err := signRequest(privateKey, requestJson)

	if err != nil {
		return "", err
	}

	request, err := http.NewRequest("POST", "https://api.transip.nl/v6/auth", bytes.NewReader(requestJson))

	if err != nil {
		return "", err
	}

	request.Header.Set("Signature", signature)

	response, err := http.DefaultClient.Do(request)

	if err != nil {
		return "", err
	}

	responseBody, err := io.ReadAll(response.Body)

	if err != nil {
		return "", err
	}

	tokenBody := struct {
		Token string `json:"token"`
	}{}

	err = json.Unmarshal(responseBody, &tokenBody)

	if err != nil {
		return "", err
	}

	return tokenBody.Token, nil
}

func loadConfig() (config, error) {
	fp := getEnvWithDefault("CONF_FILE", absolutePath("dynamic-dns.yml"))

	f, err := os.ReadFile(fp)

	c := config{}

	if err != nil {
		return c, fmt.Errorf("unable to load config: %s", err)
	}

	err = yaml.Unmarshal(f, &c)

	return c, err
}

func loadPrivateKey(fp string) (*rsa.PrivateKey, error) {
	keyString, err := os.ReadFile(fp)

	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyString)

	if block == nil {
		return nil, errors.New("private key file did not contain PEM formatted block")
	}

	parseResult, err := x509.ParsePKCS8PrivateKey(block.Bytes)

	if err != nil {
		return nil, err
	}

	key, ok := parseResult.(*rsa.PrivateKey)

	if !ok {
		return nil, errors.New("private key file did not contain a valid private key")
	}

	return key, nil
}

func signRequest(privateKey *rsa.PrivateKey, requestBody []byte) (string, error) {
	digest := sha512.Sum512(requestBody)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, digest[:])

	if err != nil {
		return "", fmt.Errorf("could not sign request: %w", err)
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

func tokenRequest(login string) interface{} {
	seededRand := math_rand.New(math_rand.NewSource(time.Now().UnixNano()))

	return map[string]interface{}{
		"login":           login,
		"nonce":           strconv.Itoa(seededRand.Int()),
		"read_only":       false,
		"expiration_time": "30 minutes",
		"label":           fmt.Sprintf("TransIP Dynamic DNS Client - %d", seededRand.Intn(1024)),
		"global_key":      true,
	}
}
