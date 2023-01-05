// the entire implementation of this library was derived from this article and from reading the gopacket library
// [link] https://www.wifi-professionals.com/2019/01/4-way-handshake
package lib

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
	"net"
	"reflect"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/crypto/pbkdf2"
)

var (
	SSID        []byte
	ANonce      []byte
	SNonce      []byte
	APMac       net.HardwareAddr
	ClientMac   net.HardwareAddr
	FirstMIC    []byte
	MicData     []byte
	VerboseMode bool
)

// Message 1:
// Access point sends EAPOL message with Anonce (random number) to
// the device to generate PTK. Don’t forget client device knows Ap’s MAC
// because its connected to it. It has PMK, Snonce and its own MAC address.
// Once it receives Anonce from access point it has all the inputs to create
// the PTK.
//
// PTK = PRF (PMK + Anonce + SNonce + Mac (AA)+ Mac (SA))
//
// Mac address 9c:5d:12:5e:6c:66 is source address or mac address of the access
// point who is sending first EAPOL message to the device and d0:c5:f3:a9;16:c5
// is Mac device. In this message access point sending ANonce to the client
// device.

func FirstMsgHandler(p gopacket.Packet) {
	if dot11 := p.Layer(layers.LayerTypeDot11); dot11 != nil {
		dot11, _ := dot11.(*layers.Dot11)
		APMac = dot11.Address1
		ClientMac = dot11.Address2
	}

	if EAPOLLayer := p.Layer(layers.LayerTypeEAPOLKey); EAPOLLayer != nil {
		EAPOL, _ := EAPOLLayer.(*layers.EAPOLKey)
		ANonce = EAPOL.Nonce
	}
}

// Message 2:
// Once the device has created its PTK it sends out SNonce which is
// needed by the access point to generate PTK as well. The device sends EAPOL
// to AP message2 with MIC (message integrity check) to make sure when the
// access point can verify whether this message is corrupted or modified. Once
// SNonce is received by the AP it can generate PTK as well for unicast traffic
// encryption.
//
// This is the second message going from the client device to AP with Snonce
// and MIC field set to 1.

func SecondMsgHandler(p gopacket.Packet) {
	if EAPOLLayer := p.Layer(layers.LayerTypeEAPOLKey); EAPOLLayer != nil {
		EAPOLKeyFrame, _ := EAPOLLayer.(*layers.EAPOLKey)
		SNonce = EAPOLKeyFrame.Nonce

		tmp := EAPOLKeyFrame.MIC
		_copy := make([]byte, len(tmp))
		copy(_copy, tmp)
		FirstMIC = _copy

		if VerboseMode {
			fmt.Printf("1. MIC: %x \n", FirstMIC)
		}
	}

	if dot11 := p.Layer(layers.LayerTypeDot11); dot11 != nil {
		dot11, _ := dot11.(*layers.Dot11)
		dot11Payload := dot11.LayerPayload()[8:]
		zeroes := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		MicData = append(append(dot11Payload[:81], zeroes...), dot11Payload[97:]...)
	}
}

// Message 3:
// EAPOL message3 is sent from AP to client device containing GTK.
// AP creates GTK without the involvement of the client from GMK.
func ThirdMsgHandler(p gopacket.Packet) {
	if EAPOLLayer := p.Layer(layers.LayerTypeEAPOLKey); EAPOLLayer != nil {
		EAPOL, _ := EAPOLLayer.(*layers.EAPOLKey)

		ANonceSigned := reflect.DeepEqual(EAPOL.Nonce, ANonce)
		if !ANonceSigned {
			panic("ANonce does not match w/ the signed Nonce in the 3rd handshake")
		}
		if VerboseMode {
			fmt.Printf("2. MIC: %x \n", EAPOL.MIC)
		}
	}
}

// Message 4:
// Fourth and last EPOL message will be sent from the client to AP
// just to confirm that Keys have been installed.
func FourthMsgHandler(p gopacket.Packet) {
	if EAPOLLayer := p.Layer(layers.LayerTypeEAPOLKey); EAPOLLayer != nil {
		EAPOL, _ := EAPOLLayer.(*layers.EAPOLKey)

		if VerboseMode {
			fmt.Printf("3. MIC: %x \n", EAPOL.MIC)
		}
	}
}

func GeneratePMK(s string) []byte {
	pmk := pbkdf2.Key([]byte(s), []byte(SSID), 4096, 256, sha1.New)[:32]
	return pmk
}

func GenerateB(apMac []byte, clientMac []byte, aNonce []byte, sNonce []byte) []byte {
	//min(AA, SPA) || max(AA, SPA) || min(aNonce, sNonce) || max(aNonce, sNonce)
	res := make([]byte, 0)

	res = append(res, byteMin(apMac, clientMac)...)
	res = append(res, byteMax(apMac, clientMac)...)
	res = append(res, byteMin(aNonce, sNonce)...)
	res = append(res, byteMax(aNonce, sNonce)...)

	return res
}

func byteMin(a []byte, b []byte) []byte {
	if bytes.Compare(a, b) < 0 {
		return a
	}
	return b
}

func byteMax(a []byte, b []byte) []byte {
	if bytes.Compare(a, b) > 0 {
		return a
	}
	return b
}

// PRF-X expands the pairwise keys by a specified bit length
func PRFX(key []byte, a []byte, b []byte, x int) []byte {
	var r []byte
	byteLen := x / 8
	y := []byte{byte(0x00)}

	// HMAC-SHA-1(K, A || Y || B || i)
	limit := (x + 159) / 160
	for i := 0; i < limit; i++ {
		data := append(append(append(a, y...), b...), []byte{byte(i)}...)
		mac := hmac.New(sha1.New, key)
		mac.Write(data)
		r = append(r, mac.Sum(nil)...)
	}
	return r[:byteLen]
}
