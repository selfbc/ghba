// Copyright (c) 2016-2024, Blake Self and SOLDIERX
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted for use in any lawful way, provided that
// the following conditions are met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//     * Neither the names of the authors nor their contributors may be
//       used to endorse or promote products derived from this software
//       without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHORS AND CONTRIBUTORS BE LIABLE FOR
// ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// ghba.go
// PTR record scanner
// ported from ghba.c by L3gi0n 0F c0d3 Kid3zz
// Author: blake@soldierx.com
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"
)

var fRecords []string // records to write to file
var aRecords []string // found records
var wg sync.WaitGroup
var mutex sync.Mutex

func ptrDNSLookup(verbose bool, aList []string) {
	defer wg.Done()
	var tmpRecords []string // found records
	// check if there is a *.domain setup
	for _, record := range aList {
		if verbose {
			fmt.Println("checking " + record + "...")
		}
		addresses, _ := net.LookupAddr(record)
		if len(addresses) > 0 {
			for i := 0; i < len(addresses); i++ {

				fmt.Println("\t* Found " + record + " : " + addresses[i])
				tmpRecords = append(tmpRecords, "\t"+record+" : "+addresses[i])
			}
		}
	}
	if len(tmpRecords) > 0 { // we found records
		mutex.Lock()
		aRecords = append(aRecords, tmpRecords...)
		mutex.Unlock()
	}
}

// writeLines writes the lines to the given file.
func writeLines(lines []string, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return w.Flush()
}

// function ipsFromCIDR returns a list of ips given cidr notation
func ipsFromCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	// remove network address and broadcast address
	return ips[1 : len(ips)-1], nil
}

// increments an ip
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func main() {
	//fmt.Printf("GOMAXPROCS is %d\n", runtime.GOMAXPROCS(0))
	start := time.Now()
	var inList, outList string
	var threads int
	var sList []string // list to search

	flag.StringVar(&inList, "l", "192.168.0.0/24", "CIDR list of IPs to scan")
	flag.StringVar(&outList, "o", "output.txt", "File output of found records")
	flag.IntVar(&threads, "t", 32, "Number of threads to use")
	verbose := flag.Bool("v", false, "Verbose mode")
	flag.Parse()

	sList, _ = ipsFromCIDR(inList)
	fmt.Println("Starting scan on " + inList + " ...")
	fRecords = append(fRecords, "Results for scan on "+inList+":")

	splitSize := (len(sList) + threads - 1) / threads
	if len(sList) <= threads { // fix from Jerbo to prevent hanging where threads > sList
		threads = len(sList)
		splitSize = 1
	}
	if *verbose {
		fmt.Println("split: " + strconv.Itoa(splitSize))
	}
	//wg.Add(threads) // num of threads is # of processes
	for i := 0; i < len(sList); i += splitSize {
		end := i + splitSize
		if end > len(sList) {
			end = len(sList)
		}
		wg.Add(1)
		go ptrDNSLookup(*verbose, sList[i:end])
	}
	wg.Wait()
	sort.Strings(aRecords)
	fRecords = append(fRecords, aRecords...) // move aRecords to fRecords for write
	writeLines(fRecords, outList)
	elapsed := time.Since(start)
	fmt.Printf("ghba took %s to complete.\n", elapsed)
}
