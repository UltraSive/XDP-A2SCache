package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"net"
	"encoding/binary"

	"github.com/dropbox/goebpf"
)

type CacheMapElement struct {
	daddr    string
	dport    int
	payload []byte
}

// Struct to represent the key with 8 bytes identical to the cache map
type BPFCacheMapKey struct {
    daddr   uint32
	dport   uint16
	padding uint16
}

func main() {

	// Specify Interface Name
	interfaceName := "ens3"

	// built cache.
	data := "ÿÿÿÿIRustward: Crios - Vanilla, Monday WipeRustward.comrustRustúdl2405±omÄ´A^@mp250,cp3,ptrak,qp0,v2405,weekly,vanilla,hcd208e01,stok,born1692598503,gmrust,cs85883,oxideJÚ"

	cache := []CacheMapElement{
		{
			daddr:  "216.126.237.26",
			dport:  28017,
			payload: []byte(data),
		},
	}

	// Load XDP Into App
	bpf := goebpf.NewDefaultEbpfSystem()
	err := bpf.LoadElf("bpf/xdp.o")
	if err != nil {
		log.Fatalf("LoadELF() failed: %s", err)
	}
	cacheMap := bpf.GetMapByName("query_cache_map")
	if cacheMap == nil {
		log.Fatalf("eBPF map 'query_cache_map' not found\n")
	}
	xdp := bpf.GetProgramByName("a2s_response")
	if xdp == nil {
		log.Fatalln("Program 'a2s_response' not found in Program")
	}
	err = xdp.Load()
	if err != nil {
		fmt.Printf("xdp.Attach(): %v", err)
	}
	err = xdp.Attach(interfaceName)
	if err != nil {
		log.Fatalf("Error attaching to Interface: %s", err)
	}

	BuildCacheMap(cache, cacheMap)

	defer xdp.Detach()
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)
	log.Println("XDP Program Loaded successfuly into the Kernel.")
	log.Println("Press CTRL+C to stop.")
	<-ctrlC

}

func BuildCacheMap(cache []CacheMapElement, cacheMap goebpf.Map) error {
	for _, server := range cache {
		key := BPFCacheMapKey {
			daddr: binary.BigEndian.Uint32(net.ParseIP(server.daddr).To4()),
			dport: uint16(server.dport),
		}

		// Convert the key struct to a byte slice thats compatible with the 64 bit map
		keyBytes := make([]byte, 8)
		binary.BigEndian.PutUint32(keyBytes[:4], key.daddr)
        binary.BigEndian.PutUint16(keyBytes[4:6], key.dport)

		err := cacheMap.Insert(keyBytes, server.payload)
		if err != nil {
			return err
		}
	}
	return nil
}