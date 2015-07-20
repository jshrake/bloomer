package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/BurntSushi/toml"
	"github.com/docopt/docopt-go"
)

func main() {

	usage := `bloom

bloom is a command-line tool for executing tasks on groups of servers.

Usage:
  bloom [options] <task> <group>

Options:
  -f --file BLOOMFILE	    Path to bloom.toml config file
  -i --identity IDENTITY 	Path to identity file.
  -h --help     			Show this screen.
  --version     			Show version.`
	args, _ := docopt.Parse(usage, nil, true, "bloom 1.0.0", false)

	var config BloomConfig
	bloomFile := "bloom.toml"
	if args["--file"] != nil {
		bloomFile = args["--file"].(string)
	}
	if _, err := toml.DecodeFile(bloomFile, &config); err != nil {
		log.Fatal(err)
	}

	task := getTask(args["<task>"].(string), &config)
	group := getGroup(args["<group>"].(string), &config)

	keyPaths := []string{
		filepath.Join(os.Getenv("HOME"), ".ssh", "id_rsa"),
		filepath.Join(os.Getenv("HOME"), ".ssh", "id_dsa"),
		filepath.Join(os.Getenv("HOME"), ".ssh", "id_ecdsa")}
	if args["--identity"] != nil {
		keyPaths = append(keyPaths, args["--identity"].(string))
	}
	keyChain := makeKeyChain(keyPaths...)
	sshConfig := &ssh.ClientConfig{
		User: group.User,
		Auth: []ssh.AuthMethod{keyChain},
	}
	var parallelHosts sync.WaitGroup
	for _, host := range group.Hosts {
		parallelHosts.Add(1)
		go func(host string) {
			defer parallelHosts.Done()
			sf := &SessionFactory{
				host:   host + ":" + strconv.Itoa(22),
				config: sshConfig,
			}
			task.Execute(&config, sf)
		}(host)
	}
	parallelHosts.Wait()
}

// BloomGroup represents a group of remote machines
type BloomGroup struct {
	Name  string
	Hosts []string
	User  string
}

// A BloomTask is executed on a BloomGroup
type BloomTask interface {
	Execute(*BloomConfig, *SessionFactory) error
}

// BloomShellTask contains a list of shell commands to execute
type BloomShellTask struct {
	Name     string
	Commands []string
}

func (shellTask BloomShellTask) Execute(config *BloomConfig, sf *SessionFactory) error {
	for _, cmd := range shellTask.Commands {
		// The command may actually be a reference to another task
		taskName := cmd
		if strings.HasPrefix(cmd, "@") {
			taskName = strings.SplitAfter(cmd, "@")[1]
		}
		// task should resolve to a BloomRawCommand or another BloomTask
		task := getTask(taskName, config)
		err := task.Execute(config, sf)
		if err != nil {
			log.Fatalf("Failed to run: " + err.Error())
		}
	}
	return nil
}

// BloomScriptTask contains the path to a script on the local machine to execute on a BloomGroup
type BloomScriptTask struct {
	Name       string
	Path       string
	Executable string
	Sudo       bool
}

func (script BloomScriptTask) Execute(config *BloomConfig, sf *SessionFactory) error {
	// TODO(jshrake): Investigate the usage of -S
	// see: http://play.golang.org/p/7ViL3VbPoA
	sudo := ""
	if script.Sudo {
		sudo = " sudo "
	}
	// base64 encode the script
	data, err := ioutil.ReadFile(script.Path)
	if err != nil {
		log.Fatalf("Error reading script %s: %s", script.Path, err.Error())
	}
	base64Script := base64.StdEncoding.EncodeToString(data)
	/*
		From: http://serverfault.com/a/625697
		A trick I use sometimes is to use base64 to encode the commands, and pipe it to bash on the other site:

			MYCOMMAND=`base64 -w0 script.sh`
			ssh user@remotehost "echo $MYCOMMAND | base64 --decode | sudo bash"
	*/
	cmd := fmt.Sprintf("echo %s | base64 --decode | %s%s", base64Script, sudo, script.Executable)
	session := sf.NewSession()
	defer session.Close()
	log.Printf("[%s | %s %s]", sf.host, script.Executable, script.Path)
	err = session.Run(cmd)
	if err != nil {
		log.Fatalf("Failed to run: " + err.Error())
	}
	return nil
}

// BloomRawCommand is a command that was passed by the user at the command-line
type BloomRawCommand struct {
	Command string
}

func (rawCmd BloomRawCommand) Execute(config *BloomConfig, sf *SessionFactory) error {
	session := sf.NewSession()
	defer session.Close()
	log.Printf("[%s | %s]", sf.host, rawCmd.Command)
	err := session.Run(rawCmd.Command)
	if err != nil {
		log.Fatalf("Failed to run: " + err.Error())
	}
	return nil
}

// BloomConfig represents a boom.toml file
type BloomConfig struct {
	Group  []BloomGroup
	Shell  []BloomShellTask
	Script []BloomScriptTask
}

func getTask(name string, config *BloomConfig) BloomTask {
	for _, shellTask := range config.Shell {
		if shellTask.Name == name {
			return shellTask
		}
	}

	for _, scriptTask := range config.Script {
		if scriptTask.Name == name {
			return scriptTask
		}
	}
	return BloomRawCommand{name}
}

func getGroup(name string, config *BloomConfig) BloomGroup {
	// Build an array of group names (for error reporting purposes)
	// and determine if name corresponds to a valid group
	names := make([]string, len(config.Group))
	groupIdx := len(config.Group)
	for i := range config.Group {
		groupName := config.Group[i].Name
		names[i] = name
		if groupName == name {
			groupIdx = i
		}
	}
	if groupIdx >= len(config.Group) {
		log.Fatalf("Bad group name %s, available groups: %s", name, names)
	}
	return config.Group[groupIdx]
}

// SessionFactory provides all the goods for generating ssh sessions
type SessionFactory struct {
	host   string
	config *ssh.ClientConfig
}

func (sf SessionFactory) NewSession() *ssh.Session {
	client, err := ssh.Dial("tcp", sf.host, sf.config)
	if err != nil {
		log.Fatalf("Failed to dial %s: %s", sf.host, err.Error())
	}

	// Each ClientConn can support multiple interactive sessions,
	// represented by a Session.
	session, err := client.NewSession()
	if err != nil {
		log.Fatal("Failed to create session: " + err.Error())
	}
	return session
}

func makeSigner(keypath string) (signer ssh.Signer, err error) {
	keyBytes, err := ioutil.ReadFile(keypath)
	if err != nil {
		return
	}
	signer, err = ssh.ParsePrivateKey(keyBytes)
	return
}

func makeKeyChain(keyPaths ...string) ssh.AuthMethod {
	signers := []ssh.Signer{}
	for _, keyPath := range keyPaths {
		// Ensure that keyPath exists!
		if _, err := os.Stat(keyPath); err == nil {
			signer, err := makeSigner(keyPath)
			if err != nil {
				log.Fatalf("Error signing key %s: %s", keyPath, err.Error())
			}
			signers = append(signers, signer)
		}
	}
	return ssh.PublicKeys(signers...)
}
