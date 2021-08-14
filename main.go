/*
TODO:	- check for OS name and version
		- do 'stealth' scan (SYN / FIN)
		- UDP scan (RFC1122 Section 4.1.3.1)
*/

package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
)

var host = flag.String("h", "localhost", "Network address to scan (ip or doman name")
var timeout = flag.Duration("t", time.Second*5, "Timeout")
var firstPort = flag.Int("fp", 1, "Begin scan from this port")
var lastPort = flag.Int("lp", 65535, "Stop scan at this port")
var banner = flag.Bool("b", false, "Show service banner")

func ulimit() int64 {
	out, err := exec.Command("ulimit", "-n").Output()
	if err != nil {
		panic(err)
	}

	i, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		panic(err)
	}

	return i
}

func scanTCP(port int) {
	conn, err := net.DialTimeout("tcp", *host+":"+strconv.Itoa(port), *timeout)
	if err != nil {
		//if strings.HasSuffix(err.Error(), "timeout") {
		//	fmt.Println(err.Error())
		//}
		// too many open files
		if strings.HasSuffix(err.Error(), "files") {
			//fmt.Println(err.Error())
			time.Sleep(*timeout)
			scanTCP(port)
		}

		return
	}

	// check for banner
	bytesRead := 0
	buffer := make([]byte, 4096)

	if *banner {
		conn.SetReadDeadline(time.Now().Add(*timeout))

		bytesRead, _ = conn.Read(buffer)
	}

	conn.Close()

	fmt.Printf("%d/tcp open", port)

	if bytesRead > 0 {
		fmt.Printf("\t%s", buffer[0:bytesRead])
	} else {
		fmt.Printf("\n")
	}
}

func main() {
	flag.Parse()

	lock := semaphore.NewWeighted(ulimit())
	wg := sync.WaitGroup{}
	defer wg.Wait()

	for port := *firstPort; port <= *lastPort; port++ {
		lock.Acquire(context.TODO(), 1)
		wg.Add(1)
		go func(port int) {
			defer lock.Release(1)
			defer wg.Done()
			scanTCP(port)
		}(port)
	}
}
