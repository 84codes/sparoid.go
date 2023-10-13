package main

import (
	"bytes"
	"fmt"
	"log"
	"os"

	"github.com/84codes/sparoid.go"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func main() {
	godotenv.Load()
	sparoid, err := sparoid.NewClient(os.Getenv("SPAROID_KEY"), os.Getenv("SPAROID_HMAC_KEY"))
	if err != nil {
		log.Fatal("Failed to create client check key lengths", err)
	}
	hostname := "common-01.db.elephantsql.com"
	err = sparoid.Auth(hostname, 8484)
	if err != nil {
		log.Fatal("Auth failed", err)
	}
	//var hostKey ssh.PublicKey
	// An SSH client is represented with a ClientConn.
	//
	// To authenticate with the remote server you must pass at least one
	// implementation of AuthMethod via the Auth field in ClientConfig,
	// and provide a HostKeyCallback.
	key, err := os.ReadFile(fmt.Sprintf("%s/.ssh/id_ed25519", os.Getenv("HOME")))
	if err != nil {
		log.Fatal("Failed to load private key", err)
	}

	signer, err := ssh.ParsePrivateKeyWithPassphrase(key, []byte(os.Getenv("SSH_PASS")))
	if err != nil {
		log.Fatal("Failed to parse private key", err)
	}

	publicKey, err := os.ReadFile(fmt.Sprintf("%s/.ssh/id_ed25519-cert.pub", os.Getenv("HOME")))
	if err != nil {
		log.Fatal("Failed to load public key", err)
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(publicKey)
	if err != nil {
		log.Fatal("Failed to parse public key", err)
	}
	certSigner, err := ssh.NewCertSigner(pubKey.(*ssh.Certificate), signer)
	if err != nil {
		log.Fatalf("failed to create cert signer: %v", err)
	}
	knownhostsCallback, err := knownhosts.New(fmt.Sprintf("%s/.ssh/known_hosts", os.Getenv("HOME")))
	if err != nil {
		log.Fatal("Failed to load known hosts", err)
	}
	config := &ssh.ClientConfig{
		User: "ubuntu",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(certSigner),
		},
		HostKeyCallback: knownhostsCallback,
	}
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", hostname), config)
	if err != nil {
		log.Fatal("Failed to dial: ", err)
	}
	defer client.Close()

	// Each ClientConn can support multiple interactive sessions,
	// represented by a Session.
	session, err := client.NewSession()
	if err != nil {
		log.Fatal("Failed to create session: ", err)
	}
	defer session.Close()

	// Once a Session is created, you can execute a single command on
	// the remote side using the Run method.
	var b bytes.Buffer
	session.Stdout = &b
	if err := session.Run("/usr/bin/whoami"); err != nil {
		log.Fatal("Failed to run: " + err.Error())
	}
	log.Println(b.String())
}
