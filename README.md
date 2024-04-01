# ghba

## Description

ghba is a PTR record (reverse DNS) scanner.  It is a Golang rewrite of ghba.c that runs much faster than the original ghba.c.  It can scan an entire private class C network in under a minute if 32 threads are available. 

## Requirements

Golang (go) 1.13 or newer (older version may work but haven't been tested in a long time)

## Installation

Download ghba.go

run 'go mod init ghba.go'

run 'go mod clean'

run 'go build -o ghba ghba.go'

## Usage

Usage of ./ghba:

  -l string

    	CIDR list of IPs to scan (default "192.168.0.0/24")

  -o string

    	File output of found records (default "output.txt")
  -t int

    	Number of threads to use (default 32)

  -v

      Verbose mode

Example Usage:

To scan an entire private class C, you would run './ghba -l 192.168.0.0/16'

## Authors and acknowledgment

Blake (blake@soldierx.com) is the main author with some contributions from Jerbo (jerbo@soldierx.com)

## License

BSD-2 License, see LICENSE (https://git.hardenedbsd.org/SoldierX/ghba/-/blob/main/LICENSE)

## Project status

We will fix any reported bugs but there are not any known enhancements at this time as the goal was to make a really fast port of ghba.c