/*
TODO:	- check for OS name and version
		- add UDP
		- do 'stealth' scan
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

func Ulimit() int64 {
	out, err := exec.Command("ulimit", "-n").Output()
	if err != nil {
		panic(err)
	}

	s := strings.TrimSpace(string(out))

	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		panic(err)
	}

	return i
}

func ScanPort(ip string, port int, timeout time.Duration) {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		//if strings.HasSuffix(err.Error(), "timeout") {
		//	fmt.Println(err.Error())
		//}
		// too many open files
		if strings.HasSuffix(err.Error(), "files") {
			//fmt.Println(err.Error())
			time.Sleep(timeout)
			ScanPort(ip, port, timeout)
		}
		return
	}

	conn.Close()
	fmt.Println(port, "open")
}

func main() {
	hostname := flag.String("h", "", "Network address to scan (ip or doman name")
	timeout := flag.Duration("t", time.Second*5, "Timeout")
	firstPort := flag.Int("fp", 1, "Begin scan from this port")
	lastPort := flag.Int("lp", 65535, "Stop scan at this port")
	flag.Parse()

	lock := semaphore.NewWeighted(Ulimit())
	wg := sync.WaitGroup{}
	defer wg.Wait()

	for port := *firstPort; port <= *lastPort; port++ {
		lock.Acquire(context.TODO(), 1)
		wg.Add(1)
		go func(port int) {
			defer lock.Release(1)
			defer wg.Done()
			ScanPort(*hostname, port, *timeout)
		}(port)
	}
}
