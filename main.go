package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fsouza/go-dockerclient"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/alecthomas/kingpin.v2"
)

type Config struct {
	Hostname    *string
	Port        *string
	Username    *string
	DockerSock  *string
	KeyPath     *string
	RemotePort  *int
	LocalPort   *int
	ImageName   *string
	ContainerID *string
	SSHKeyPath  *string
	ForwardEPMD *bool
}

// configure parses the passed command line options and populates the Config
// struct.
func configure() *Config {
	var opts Config

	username := os.Getenv("USER")
	homeDir := os.Getenv("HOME")
	keyPath := filepath.Join(homeDir, ".ssh", "id_rsa")

	opts.Hostname = kingpin.Flag("hostname", "The remote hostname to connect to").Required().Short('h').String()
	opts.Port = kingpin.Flag("port", "The remote port to connect to").Default("22").Short('p').String()
	opts.Username = kingpin.Flag("username", "The ssh username on the remote host").Default(username).Short('l').String()
	opts.DockerSock = kingpin.Flag("docker-sock", "The Docker socket address on the remote host").Default("unix:///var/run/docker.sock").Short('s').String()
	opts.ImageName = kingpin.Flag("image-name", "The Docker image to match on for this application").Short('n').String()
	opts.ContainerID = kingpin.Flag("container-id", "The Docker container ID to match for this application").Short('c').String()
	opts.RemotePort = kingpin.Flag("remote-port", "The Container port to connect to").Default("80").Short('R').Int()
	opts.LocalPort = kingpin.Flag("local-port", "The local port to listen on").Default("8080").Short('L').Int()
	opts.SSHKeyPath = kingpin.Flag("ssh-key", "Path to the ssh private key to use").Default(keyPath).Short('i').String()
	opts.ForwardEPMD = kingpin.Flag("forward-epmd", "Shall we also forward the EPMD port?").Default("true").Short('e').Bool()
	kingpin.Parse()

	// We have to have gotten at least one of these
	if (len(*opts.ContainerID) < 1 && len(*opts.ImageName) < 1) || (len(*opts.ContainerID) > 0 && len(*opts.ImageName) > 0) {
		kingpin.FatalUsage("You must supply either image-name or container-id")
	}

	return &opts
}

// decrypt decodes SSH keys using the supplied passphrase
func decrypt(key []byte, passphrase []byte) []byte {
	block, rest := pem.Decode(key)
	if len(rest) > 0 {
		log.Fatalf("Extra data included in key")
	}

	if x509.IsEncryptedPEMBlock(block) {
		der, err := x509.DecryptPEMBlock(block, passphrase)
		if err != nil {
			log.Fatalf("Decrypt failed: %v", err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: der})
	}
	return key
}

// connectWithKeys connects to a remote SSH server using the supplied
// key and passphrase.
func connectWithKeys(hostAddr, username, keyPath string, passphrase []byte) (*ssh.Client, error) {
	key, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read private key: %v", err)
	}
	key = decrypt(key, passphrase)

	// Create the Signer for this private key.
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("unable to parse private key: %v", err)
	}

	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			// Use the PublicKeys method for remote authentication.
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// Connect to the remote server and perform the SSH handshake.
	client, err := ssh.Dial("tcp", hostAddr, config)
	if err != nil {
		return nil, fmt.Errorf("unable to connect: %v", err)
	}

	return client, nil
}

// sshDialer is a wrapper to let the Docker client library make calls
// over the SSH tunnel to the remote Unix socket.
type sshDialer struct {
	Client *ssh.Client
}

func (d *sshDialer) Dial(ignored, socketPath string) (net.Conn, error) {
	c, err := d.Client.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("Dial error: %s", err)
	}

	return c, nil
}

// findContainerByImageName takes a Docker container image name and looks
// for a match on the remote host. It returns the last matching container.
func findContainerByImageName(client *docker.Client, name string) (*docker.APIContainers, error) {
	containers, err := client.ListContainers(docker.ListContainersOptions{All: false})
	if err != nil {
		return nil, fmt.Errorf("Unable to find container: %s", err)
	}

	var lastContainer docker.APIContainers
	for _, cntnr := range containers {
		if strings.Contains(cntnr.Image, name) {
			lastContainer = cntnr
			log.Info("Found matching container:")
			log.Infof(" - id:    %s", cntnr.ID[0:12])
			log.Infof(" - image: %s", cntnr.Image)
			log.Infof(" - name:  %s", cntnr.Names[0])
			log.Infof(" - up:    %s", time.Now().UTC().Sub(time.Unix(cntnr.Created, 0)))
		}
	}

	if len(lastContainer.ID) > 0 {
		return &lastContainer, nil
	}

	return nil, fmt.Errorf("Unable to match container image: %s", name)
}

// findContainerByID takes either a long or short container ID and
// matches the remote container by that.
func findContainerByID(client *docker.Client, id string) (*docker.APIContainers, error) {
	containers, err := client.ListContainers(docker.ListContainersOptions{All: false})
	if err != nil {
		return nil, fmt.Errorf("Unable to find container: %s", err)
	}

	for _, cntnr := range containers {
		if cntnr.ID[0:12] == id[0:12] {
			return &cntnr, nil
		}
	}

	return nil, fmt.Errorf("Unable to match container ID: %s", id)
}

func findIPForContainer(client *docker.Client, cntnr *docker.APIContainers) (string, error) {
	container, err := client.InspectContainer(cntnr.ID)
	if err != nil {
		return "", fmt.Errorf("Unable to inspect container: %s", err)
	}

	ip := container.NetworkSettings.IPAddress
	log.Infof("Container IP address: %s", ip)

	return ip, nil
}

func proxyPort(client *ssh.Client, localPort int, ip string, remotePort int) {
	localAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: localPort}
	remoteAddr := &net.TCPAddr{IP: net.ParseIP(ip), Port: remotePort}
	proxy, err := NewTCPProxy(localAddr, remoteAddr, client)

	if err != nil {
		// OK to log Fatal here, we want to do from both goroutines
		log.Fatalf("Unable to start TCP proxy for %d -> %d: %s", localPort, remotePort, err)
	}

	proxy.Run()
}

// readPassphrase uses the SSH terminal input function to take the
// passphrase for the key from the user on the command line.
func readPassphrase(keyPath string) []byte {
	fmt.Printf("passphrase (%s): ", keyPath)
	passphrase, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalf("Unable to read passphrase: %s", err)
	}
	fmt.Println()

	return passphrase
}

func main() {
	config := configure()

	passphrase := readPassphrase(*config.SSHKeyPath)

	client, err := connectWithKeys(
		*config.Hostname+":"+*config.Port,
		*config.Username,
		*config.SSHKeyPath,
		passphrase,
	)
	if err != nil {
		log.Fatal(err.Error())
	}
	defer client.Close()

	dialer := &sshDialer{
		Client: client,
	}
	//		log.Fatalf("Error opening remote Docker socket: %s", err)

	dockerCli, err := docker.NewClient(*config.DockerSock)
	if err != nil {
		log.Fatalf("Unable to create new Docker client: %s", err)
	}

	// Override Dialer to use our SSH-proxied socket
	dockerCli.Dialer = dialer

	// Lookup a container by image name
	var cntnr *docker.APIContainers
	if len(*config.ImageName) > 0 {
		cntnr, err = findContainerByImageName(dockerCli, *config.ImageName)
	} else {
		cntnr, err = findContainerByID(dockerCli, *config.ContainerID)
	}
	if err != nil {
		log.Fatal(err.Error())
	}
	log.Infof("Using container: %s", cntnr.ID[0:12])

	// Get the internal IP on the Docker network for this container
	ip, err := findIPForContainer(dockerCli, cntnr)
	if err != nil {
		log.Fatal(err.Error())
	}

	go proxyPort(client, *config.LocalPort, ip, *config.RemotePort)
	if *config.ForwardEPMD {
		log.Info("Forwarding EPMD on 4369")
		go proxyPort(client, 4369, ip, 4369)
	}

	select {}
}
