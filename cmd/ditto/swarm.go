package main

import (
	"fmt"
	"github.com/evilsocket/islazy/str"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

func swarmWorker(cmd *exec.Cmd, domain string, waits *sync.WaitGroup) {
	defer func() {
		waits.Done()
		// fmt.Printf("(%d) %s exited.\n", cmd.Process.Pid, cmd)
	}()

	if e := cmd.Start(); e != nil {
		fmt.Printf("(%d) %s error starting: %v\n", cmd.Process.Pid, cmd, e)
		return
	}

	// fmt.Printf("(%d) %v\n", cmd.Process.Pid, cmd)

	if e := cmd.Wait(); e != nil {
		fmt.Printf("(%d) %s error running: %v\n", cmd.Process.Pid, cmd, e)
		return
	}
}

func swarmMain() {
	domains := str.Comma(url)
	waits := sync.WaitGroup{}

	for _, domain := range domains {
		var cmdLine []string

		wasDomain := false
		wasChanges := false
		for _, arg := range os.Args[1:] {
			if arg == "-swarm" {
				continue
			} else if wasDomain {
				cmdLine = append(cmdLine, domain)
			} else if wasChanges {
				cmdLine = append(cmdLine, filepath.Join(arg, domain))
			} else {
				cmdLine = append(cmdLine, arg)
			}

			wasDomain = arg == "-domain"
			wasChanges = arg == "-changes"
		}

		cmd := exec.Command(os.Args[0], cmdLine...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		waits.Add(1)

		go swarmWorker(cmd, domain, &waits)
	}

	fmt.Printf("waiting for %d processes ...\n", len(domains))

	waits.Wait()
}
