package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/84codes/sparoid.go"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

func main() {
	godotenv.Load()
	sparoid, err := sparoid.NewClient(os.Getenv("SPAROID_KEY"), os.Getenv("SPAROID_HMAC_KEY"))
	if err != nil {
		log.Fatal("Failed to create client check key lengths", err)
	}
	hostname := os.Getenv("SPAROID_SERVER_HOSTNAME")
	err = sparoid.Auth(hostname, 8484)
	if err != nil {
		log.Fatal("Auth failed", err)
	}

	socket := os.Getenv("SSH_AUTH_SOCK")
	conn, err := net.Dial("unix", socket)
	if err != nil {
		log.Fatalf("Failed to open SSH_AUTH_SOCK: %v", err)
	}

	agentClient := agent.NewClient(conn)

	knownhostsCallback, err := knownhosts.New(fmt.Sprintf("%s/.ssh/known_hosts", os.Getenv("HOME")))
	if err != nil {
		log.Fatal("Failed to load known hosts", err)
	}
	config := &ssh.ClientConfig{
		User: "ubuntu",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeysCallback(agentClient.Signers),
		},
		HostKeyCallback: knownhostsCallback,
	}
	// An SSH client is represented with a ClientConn.
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
