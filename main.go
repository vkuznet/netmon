package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	iface     = flag.String("iface", "eth0", "Interface to capture on")
	showStats = flag.Bool("stats", true, "Show basic stats from /proc/net/dev")
	trace     = flag.Bool("trace", false, "Enable packet capture")
	pid       = flag.Int("pid", 0, "Monitor only traffic related to this PID")
	duration  = flag.Int("duration", 10, "Capture duration in seconds")
	logFile   = flag.String("logfile", "", "Log captured packets to a file")
	protocol  = flag.String("protocol", "all", "Capture only this protocol: tcp, udp, or all (default: all)")
	port      = flag.Int("port", 0, "Capture only packets from this port (0 for all ports)")
)

type connKey struct {
	localIP    string
	localPort  string
	remoteIP   string
	remotePort string
}

func main() {
	flag.Parse()

	if *showStats {
		printNetworkStats()
	}

	var trackedConns map[string]struct{}
	if *pid > 0 {
		var err error
		trackedConns, err = getPidConnections(*pid)
		if err != nil {
			log.Fatalf("Failed to get PID connections: %v", err)
		}
		fmt.Printf("Tracking %d connections for PID %d\n", len(trackedConns), *pid)
	}

	var logWriter *os.File
	if *logFile != "" {
		var err error
		logWriter, err = os.Create(*logFile)
		if err != nil {
			log.Fatalf("Failed to create log file: %v", err)
		}
		defer logWriter.Close()
		log.SetOutput(logWriter)
	}

	if *trace {
		traceTraffic(*iface, time.Duration(*duration)*time.Second, trackedConns, logWriter)
	}
}

func printNetworkStats() {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		log.Fatalf("Failed to read /proc/net/dev: %v", err)
	}
	lines := bytes.Split(data, []byte("\n"))
	fmt.Println("Interface Stats:")
	for _, line := range lines[2:] {
		fields := bytes.Fields(line)
		if len(fields) >= 10 {
			name := strings.TrimSuffix(string(fields[0]), ":")
			if name == *iface {
				fmt.Printf("%s - RX: %s bytes, TX: %s bytes\n", name, fields[1], fields[9])
			}
		}
	}
}

func traceTraffic(iface string, duration time.Duration, pidConns map[string]struct{}, logWriter *os.File) {
	handle, err := pcap.OpenLive(iface, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening device %s: %v", iface, err)
	}
	defer handle.Close()

	fmt.Printf("Capturing on %s for %v...\n", iface, duration)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	timer := time.After(duration)

	for {
		select {
		case <-timer:
			fmt.Println("Done tracing.")
			return
		case packet := <-packetSource.Packets():
			network := packet.NetworkLayer()
			transport := packet.TransportLayer()
			if network == nil || transport == nil {
				continue
			}

			srcIP, dstIP := network.NetworkFlow().Endpoints()
			srcPort, dstPort := "", ""

			// Filter by protocol (TCP/UDP)
			switch layer := transport.(type) {
			case *layers.TCP:
				if *protocol != "all" && *protocol != "tcp" {
					continue
				}
				srcPort = fmt.Sprint(layer.SrcPort)
				dstPort = fmt.Sprint(layer.DstPort)
			case *layers.UDP:
				if *protocol != "all" && *protocol != "udp" {
					continue
				}
				srcPort = fmt.Sprint(layer.SrcPort)
				dstPort = fmt.Sprint(layer.DstPort)
			default:
				continue
			}

			// Filter by port
			filterPort := fmt.Sprintf("%d", *port)
			if filterPort != "" && (filterPort != srcPort && filterPort != dstPort &&
				filterPort != srcPort && filterPort != dstPort) {
				continue
			}

			key1 := fmt.Sprintf("%s:%s-%s:%s", srcIP, srcPort, dstIP, dstPort)
			key2 := fmt.Sprintf("%s:%s-%s:%s", dstIP, dstPort, srcIP, srcPort)

			if pidConns != nil {
				_, ok1 := pidConns[key1]
				_, ok2 := pidConns[key2]
				if !ok1 && !ok2 {
					continue
				}
			}

			packetInfo := fmt.Sprintf("Packet: %s:%s -> %s:%s\n", srcIP, srcPort, dstIP, dstPort)
			fmt.Print(packetInfo)
			if logWriter != nil {
				log.Println(packetInfo)
			}
		}
	}
}

func getPidConnections(pid int) (map[string]struct{}, error) {
	conns := make(map[string]struct{})
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)

	files, err := os.ReadDir(fdDir)
	if err != nil {
		return nil, fmt.Errorf("read fd dir: %w", err)
	}

	inodes := make(map[string]bool)
	for _, f := range files {
		link, err := os.Readlink(filepath.Join(fdDir, f.Name()))
		if err != nil || !strings.HasPrefix(link, "socket:[") {
			continue
		}
		inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
		inodes[inode] = true
	}

	// Check TCP
	parseProcNet("/proc/net/tcp", inodes, conns)
	parseProcNet("/proc/net/udp", inodes, conns)
	return conns, nil
}

func parseProcNet(file string, inodeMap map[string]bool, out map[string]struct{}) {
	data, _ := os.ReadFile(file)
	lines := strings.Split(string(data), "\n")

	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		localHex := strings.Split(fields[1], ":")
		remoteHex := strings.Split(fields[2], ":")
		inode := fields[9]

		if !inodeMap[inode] {
			continue
		}

		localIP := hexToIP(localHex[0])
		localPort := hexToPort(localHex[1])
		remoteIP := hexToIP(remoteHex[0])
		remotePort := hexToPort(remoteHex[1])

		key := fmt.Sprintf("%s:%s-%s:%s", localIP, localPort, remoteIP, remotePort)
		out[key] = struct{}{}
	}
}

func hexToIP(hexIP string) string {
	b, _ := hex.DecodeString(fmt.Sprintf("%08s", hexIP))
	return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0])
}

func hexToPort(hexPort string) string {
	p, _ := strconv.ParseInt(hexPort, 16, 32)
	return strconv.Itoa(int(p))
}
