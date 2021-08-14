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

func scanTCP(host string, port int, timeout time.Duration) {
	conn, err := net.DialTimeout("tcp", host+":"+strconv.Itoa(port), timeout)

	if err != nil {
		//if strings.HasSuffix(err.Error(), "timeout") {
		//	fmt.Println(err.Error())
		//}
		// too many open files
		if strings.HasSuffix(err.Error(), "files") {
			//fmt.Println(err.Error())
			time.Sleep(timeout)
			scanTCP(host, port, timeout)
		}

		return
	}

	conn.Close()
	fmt.Printf("%d/tcp open\n", port)
}

func main() {
	host := flag.String("h", "localhost", "Network address to scan (ip or doman name")
	timeout := flag.Duration("t", time.Second*5, "Timeout")
	firstPort := flag.Int("fp", 1, "Begin scan from this port")
	lastPort := flag.Int("lp", 65535, "Stop scan at this port")
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
			scanTCP(*host, port, *timeout)
		}(port)
	}
}
