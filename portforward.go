package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	// We need to import libp2p's libraries that we use in this project.
	"github.com/elazarl/goproxy"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/routing"
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	"github.com/phayes/freeport"
)

// For better security, accept connections only from known peers.
// Accepted peers stored in this array
var AcceptedPeers []string

type ForwardService struct {
	host                host.Host
	localForwardPort    int
	remoteListeningPort int
	kadDHT              *dht.IpfsDHT
}

// Protocol string to identify our application streams
const Protocol = "/port-forward/0.0.1"

func NewForwardService(localForwardPort int, remoteListeningPort int, libp2pPort int) *ForwardService {

	// Keeping same peer id always. Create a cert & store it.
	if _, err := os.Stat("peerid.key"); os.IsNotExist(err) {
		//host, _ := libp2p.New()
		priv, _, err := crypto.GenerateKeyPair(
			crypto.Ed25519, // Select your key type. Ed25519 are nice short
			-1,             // Select key length when possible (i.e. RSA).
		)
		if err != nil {
			panic(err)
		}
		// Get Node's Private Key
		keyBytes, _ := crypto.MarshalPrivateKey(priv)
		// save to disk
		f, _ := os.Create("peerid.key")
		f.WriteString(string(keyBytes))
		f.Close()
		//host.Close()
	}

	// Reload the existing keys
	filedata, _ := os.ReadFile("peerid.key")
	privateKey, err := crypto.UnmarshalPrivateKey([]byte(filedata))
	if err != nil {
		log.Fatalln(err)
	}

	connmgr, err := connmgr.NewConnManager(
		100, // Lowwater
		400, // HighWater,
		connmgr.WithGracePeriod(time.Minute),
	)
	if err != nil {
		panic(err)
	}

	// Create a resource manager configuration
	cfg := rcmgr.PartialLimitConfig{
		System: rcmgr.ResourceLimits{
			StreamsOutbound: rcmgr.DefaultLimit, // Allow unlimited outbound streams
			StreamsInbound:  rcmgr.Unlimited,
			Conns:           4000,
			ConnsInbound:    500,
			ConnsOutbound:   500,
			FD:              10000,
		},
	}
	if len(AcceptedPeers) > 0 {
		cfg.Peer = make(map[peer.ID]rcmgr.ResourceLimits, 0)
		for _, acceptedPeer := range AcceptedPeers {
			id, _ := peer.Decode(acceptedPeer)
			cfg.Peer[id] = rcmgr.ResourceLimits{
				// Allow inbound connections from this peer
				ConnsInbound: rcmgr.Unlimited,
				// Allow outbound connections to this peer
				ConnsOutbound: rcmgr.Unlimited,
			}
		}
	}
	limiter := rcmgr.NewFixedLimiter(cfg.Build(rcmgr.DefaultLimits.AutoScale()))
	rm, err := rcmgr.NewResourceManager(limiter, rcmgr.WithMetricsDisabled())
	if err != nil {
		panic(err)
	}

	var idht *dht.IpfsDHT
	host, err := libp2p.New(
		libp2p.ListenAddrStrings(
			fmt.Sprintf("/ip4/0.0.0.0/udp/%d/quic-v1", libp2pPort),
			fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", libp2pPort),
			//fmt.Sprintf("/ip4/0.0.0.0/tcp/%d/ws", libp2pPort),
			//fmt.Sprintf("/ip6/::/udp/%d/quic-v1", libp2pPort),
			//fmt.Sprintf("/ip6/::/tcp/%d", libp2pPort),
		),
		libp2p.ResourceManager(rm),
		libp2p.Identity(privateKey),
		// support TLS connections
		libp2p.Security(libp2ptls.ID, libp2ptls.New),
		// support noise connections
		libp2p.Security(noise.ID, noise.New),
		libp2p.NATPortMap(),
		libp2p.DefaultMuxers,
		libp2p.DefaultTransports,
		libp2p.ConnectionManager(connmgr),
		libp2p.FallbackDefaults,
		libp2p.Routing(func(h host.Host) (routing.PeerRouting, error) {
			idht, err = dht.New(context.Background(), h)
			return idht, err
		}),
	)
	if err != nil {
		log.Fatalln(err)
	}

	// Set up a channel to receive notifications about identity updates
	identityChan := make(chan struct{})
	host.SetStreamHandler("/ipfs/id/push/1.0.0", func(stream network.Stream) {
		if hasPublicAddress(host) {
			identityChan <- struct{}{}
		}
	})

	// This connects to public bootstrappers
	for _, addr := range dht.DefaultBootstrapPeers {
		pi, _ := peer.AddrInfoFromP2pAddr(addr)
		err := host.Connect(context.Background(), *pi)
		if err != nil {
			fmt.Println("Boot strap connection failed:", err)
			continue
		}
	}

	// Wait for identity information to be received
	select {
	case <-identityChan:
		fmt.Println("Identity information received for this host")
	case <-time.After(30 * time.Second):
		fmt.Println("Timeout: Identity information not received within 30 seconds")
	}

	host.RemoveStreamHandler("/ipfs/id/push/1.0.0")

	if hasPublicAddress(host) {
		fmt.Println("This host proxy server accessible over internet using peer ID :\n", host.ID())
	} else {
		fmt.Println("This host  proxy server accessible only over LAN using peer ID:\n", host.ID())
	}
	fmt.Println("Add firewall rule to allow : ", libp2pPort, " udp/tcp port")

	return &ForwardService{
		host:                host,
		localForwardPort:    localForwardPort,
		remoteListeningPort: remoteListeningPort,
		kadDHT:              idht,
	}
}

// check if the host has public address
func hasPublicAddress(host host.Host) bool {
	for _, a := range host.Addrs() {
		str := a.String()
		if !strings.Contains(str, "127.0.0") &&
			!strings.Contains(str, "/ip4/10.") &&
			!strings.Contains(str, "/ip4/172.16.") &&
			!strings.Contains(str, "/ip4/192.168.") {
			return true
		}
	}
	return false
}

// Second machine(remote) listens on a proxy port to forward http, https traffic
// to the first machine over libp2p streams.
func (f *ForwardService) RemoteListener(destPeer string) {

	destPeerID, err := peer.Decode(destPeer)
	if err != nil {
		log.Fatal("Destination peer decode failed :", err)
		return
	}

	// Setup localListener (type net.Listener)
	localListener, err := net.Listen("tcp", "0.0.0.0:"+strconv.Itoa(f.remoteListeningPort))
	if err != nil {
		log.Fatalf("net.Listen failed: %v", err)
	}

	for {
		// Setup localConn (type net.Conn)
		localConn, err := localListener.Accept()
		if err != nil {
			log.Fatalf("listen.Accept failed: %v", err)
		}

		stream, err := f.host.NewStream(context.Background(), destPeerID, Protocol)
		if err != nil {
			log.Printf("Failed to contact remote stream: %v", err)
			localConn.Close()
			continue
		}
		// now relay the data between the local socket & stream
		go func() {
			defer localConn.Close()
			_, err = io.Copy(localConn, stream)
			if err != nil {
				log.Println("Local connection to stream failed:", err)
			}
		}()
		go func() {
			defer stream.Close()
			_, err = io.Copy(stream, localConn)
			if err != nil {
				log.Println("Stream to local connection failed:", err)
			}
		}()
	}
}

// Forward the incoming stream connections to the local proxy server.
func (f *ForwardService) localStreamForwarder(stream network.Stream) {

	// Accept connection only from specified peers
	if len(AcceptedPeers) > 0 {
		var accepted bool = false
		for _, peer := range AcceptedPeers {
			if peer == stream.Conn().RemotePeer().String() {
				accepted = true
				fmt.Println("Accepting connection from first peer", stream.Conn().RemotePeer().String())
			}
		}

		if !accepted {
			fmt.Println("Blocking connection from peer", stream.Conn().RemotePeer().String())
			// silently drop the connection
			stream.Close()
			return
		}
	}

	target, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(f.localForwardPort))
	if err != nil {
		log.Println("could not connect to target", err)
		stream.Close()
		return
	}
	// Relay data between the stream & socket
	go func() {
		defer target.Close()
		_, err = io.Copy(target, stream)
		if err != nil {
			log.Println("Stream connection closed with proxy failed:", err)
		}
	}()
	go func() {
		defer stream.Close()
		_, err = io.Copy(stream, target)
		if err != nil {
			log.Println("Proxy connection closed with stream failed: ", err)
		}
	}()
}

const help = `
This program tunnels HTTP/HTTPS traffic over libp2p between two machines.
First machine is the sharer to which the HTTP/HTTPS traffic is sent from
second machine. First is called as local & second one as the remote here.
Local machine will acts as proxy server to the remote machine.

Usage: 1) Run the program in first machine (local) with:   ./portforward
       2) Then start it in second machine (remote) with: ./portforward -d <local-peer-multiaddress>
      First step will print the <local-peer-multiaddress> which is reachable over internet

Now, you can set your second machine browser proxy setting to 127.0.0.1:8080.
After that all the browser request will be sent to the first machine.`

func main() {
	flag.Usage = func() {
		fmt.Println(help)
		flag.PrintDefaults()
	}

	// Parse command line flags
	destPeer := flag.String("d", "", "destination peer address sharing internet over proxy server")
	proxyPort := flag.Int("p", 8080, "proxy port")
	p2pport := flag.Int("l", 12007, "libp2p listen port")
	acceptedPeerList := flag.String("a", "", "Accepted peer IDs")
	printOnly := flag.Bool("i", false, "Print peer ID information")

	flag.Parse()
	if *acceptedPeerList != "" {
		AcceptedPeers = strings.Split(*acceptedPeerList, ",")
	}
	freeTCPPort, _ := freeport.GetFreePort()
	forwarder := NewForwardService(freeTCPPort, *proxyPort, *p2pport)
	if *printOnly {
		return
	}

	// Identify first & second machine using the destPeer command line options
	if *destPeer == "" {
		// First machine
		forwarder.host.SetStreamHandler(Protocol, forwarder.localStreamForwarder)
		proxy := goproxy.NewProxyHttpServer()
		proxy.Verbose = true
		// Run a local proxy server to pass the HTTP/HTTPS traffic from the second machine
		log.Fatal(http.ListenAndServe("127.0.0.1:"+strconv.Itoa(freeTCPPort), proxy))
	} else {
		// Second machine
		fmt.Println("Change Browser proxy setting to 127.0.0.1:", *proxyPort)
		// Use the forwarder to send the HTTP/HTTPS request to the first machine
		forwarder.RemoteListener(*destPeer)
	}
}
