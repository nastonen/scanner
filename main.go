/*
TODO:
		- stealth scan (FIN)
		- service scan
		- OS fingerprint
		- HW address
		- UDP scan (RFC1122 Section 4.1.3.1)
*/

package main

/*
#include <stdio.h>
#include <stdlib.h>
#cgo CFLAGS: -Wall
#cgo LDFLAGS: -lnet -lpcap
extern void scan(char *ip, int sp, int lp, int timeout);
*/
import "C"

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
	"unsafe"

	"golang.org/x/sync/semaphore"
)

var (
	host      = flag.String("h", "localhost", "Network address to scan (ip or doman name")
	timeout   = flag.Duration("t", time.Millisecond * 200, "Timeout in milliseconds")
	firstPort = flag.Int("fp", 1, "Begin scan from this port")
	lastPort  = flag.Int("lp", 65535, "Stop scan at this port")
	banner    = flag.Bool("b", false, "Show service banner")
	stealth   = flag.Bool("s", false, "Stealth scan mode (SYN)")
)

func resolveHostName() {
	// get IP address of a host
	ips, err := net.LookupIP(*host)
	if err != nil {
		fmt.Println(err.Error())
	}

	for _, ip := range ips {
		if addr := ip.To4(); addr != nil {
			*host = addr.String()
			break
		}
	}
}

func ulimit() int64 {
	out, err := exec.Command("ulimit", "-n").Output()
	if err != nil {
		//panic(err)
		return 1024
	}

	i, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		panic(err)
	}

	return i / 2
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

/*func scanSYN(port int) {
	C.scan(*host, port);
}*/

func startScan(scanFunc func(int)) {
	lock := semaphore.NewWeighted(ulimit())
	wg := sync.WaitGroup{}
	defer wg.Wait()

	for port := *firstPort; port <= *lastPort; port++ {
		lock.Acquire(context.TODO(), 1)
		wg.Add(1)
		go func(port int) {
			defer lock.Release(1)
			defer wg.Done()
			scanFunc(port)
		}(port)
	}
}

func main() {
	flag.Parse()
	resolveHostName()

	fmt.Printf("IP: %s\n", *host)

	if *stealth {
		//startScan(scanSYN)
		cstr := C.CString(*host)
		C.scan(cstr, C.int(*firstPort), C.int(*lastPort), C.int(*timeout / 1000000));
		C.free(unsafe.Pointer(cstr))
	} else {
		startScan(scanTCP)
	}
}
