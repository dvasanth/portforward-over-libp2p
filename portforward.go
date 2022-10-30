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

	// We need to import libp2p's libraries that we use in this project.
	"github.com/elazarl/goproxy"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	libp2pquic "github.com/libp2p/go-libp2p-quic-transport"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-tcp-transport"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/phayes/freeport"
)

// For better security, accept connections only from known peers.
// Accepted peers stored in this array
var AcceptedPeers []string

type ForwardService struct {
	host                host.Host
	localForwardPort    int
	remoteListeningPort int
}

// Protocol string to identify our application streams
const Protocol = "/port-forward/0.0.1"

func NewForwardService(localForwardPort int, remoteListeningPort int, libp2pPort int) *ForwardService {

	// Keeping same peer id always. Create a cert & store it.
	if _, err := os.Stat("peerid.key"); os.IsNotExist(err) {
		host, _ := libp2p.New()
		// Get Node's Private Key
		keyBytes, _ := crypto.MarshalPrivateKey(host.Peerstore().PrivKey(host.ID()))
		// save to disk
		f, _ := os.Create("peerid.key")
		f.WriteString(string(keyBytes))
		f.Close()
		host.Close()
	}

	// Reload the existing keys
	filedata, _ := os.ReadFile("peerid.key")
	privateKey, err := crypto.UnmarshalPrivateKey([]byte(filedata))
	if err != nil {
		log.Fatalln(err)
	}

	// Only quic for slight advantage over TCP
	ip4quic := fmt.Sprintf("/ip4/0.0.0.0/udp/%d/quic", libp2pPort)

	host, err := libp2p.New(
		libp2p.ListenAddrStrings(ip4quic),
		libp2p.Identity(privateKey),
		libp2p.DefaultSecurity,
		libp2p.NATPortMap(),
		libp2p.DefaultMuxers,
		libp2p.Transport(libp2pquic.NewTransport),
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.FallbackDefaults,
	)
	if err != nil {
		log.Fatalln(err)
	}

	// This connects to public bootstrappers
	for _, addr := range dht.DefaultBootstrapPeers {
		pi, _ := peer.AddrInfoFromP2pAddr(addr)
		host.Connect(context.Background(), *pi)
	}

	var publicAddresses string = ""
	var privateAddresses string = ""
	for _, a := range host.Addrs() {
		if !strings.Contains(a.String(), "127.0.0") &&
			!strings.Contains(a.String(), "/ip4/10.") &&
			!strings.Contains(a.String(), "/ip4/172.16.") &&
			!strings.Contains(a.String(), "/ip4/192.168.") {
			publicAddresses += fmt.Sprintf("%s/ipfs/%s\n", a, host.ID())
		} else {
			privateAddresses += fmt.Sprintf("%s/ipfs/%s\n", a, host.ID())
		}
	}

	fmt.Println("libp2p-peer public addresses:\n", publicAddresses)
	fmt.Println("libp2p-peer private addresses:\n", privateAddresses)

	return &ForwardService{
		host:                host,
		localForwardPort:    localForwardPort,
		remoteListeningPort: remoteListeningPort,
	}
}

// Second machine(remote) listens on a proxy port to forward http, https traffic
// to the first machine over libp2p streams.
func (f *ForwardService) RemoteListener(destPeer string) {

	destPeerID := addAddrToPeerstore(f.host, destPeer)

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
			log.Fatalf("Failed to contact remote stream: %v", err)
		}
		// now relay the data between the local socket & stream
		go func() {
			defer localConn.Close()
			_, err = io.Copy(localConn, stream)
			if err != nil {
				log.Println("Local connection to stream failed: %v", err)
			}
		}()
		go func() {
			defer stream.Close()
			_, err = io.Copy(stream, localConn)
			if err != nil {
				log.Println("Stream to local connection failed: %v", err)
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
			if peer == stream.Conn().RemotePeer().Pretty() {
				accepted = true
				fmt.Println("Accepting connection from first peer", stream.Conn().RemotePeer().Pretty())
			}
		}

		if !accepted {
			fmt.Println("Blocking connection from peer", stream.Conn().RemotePeer().Pretty())
			// silently drop the connection
			stream.Close()
			return
		}
	}

	target, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(f.localForwardPort))
	if err != nil {
		log.Fatal("could not connect to target", err)
		stream.Close()
	}
	// Relay data between the stream & socket
	go func() {
		defer target.Close()
		_, err = io.Copy(target, stream)
		if err != nil {
			log.Println("Stream connection closed with proxy failed: %v", err)
		}
	}()
	go func() {
		defer stream.Close()
		_, err = io.Copy(stream, target)
		if err != nil {
			log.Println("Proxy connection closed with stream failed: %v", err)
		}
	}()
}

// addAddrToPeerstore parses a peer multiaddress and adds
// it to the given host's peerstore, so it knows how to
// contact it. It returns the peer ID of the remote peer.
func addAddrToPeerstore(h host.Host, addr string) peer.ID {
	// The following code extracts target's the peer ID from the
	// given multiaddress
	ipfsaddr, err := ma.NewMultiaddr(addr)
	if err != nil {
		log.Fatalln(err)
	}
	pid, err := ipfsaddr.ValueForProtocol(ma.P_IPFS)
	if err != nil {
		log.Fatalln(err)
	}

	peerid, err := peer.Decode(pid)
	if err != nil {
		log.Fatalln(err)
	}

	// Decapsulate the /ipfs/<peerID> part from the target
	// /ip4/<a.b.c.d>/ipfs/<peer> becomes /ip4/<a.b.c.d>
	targetPeerAddr, _ := ma.NewMultiaddr(fmt.Sprintf("/ipfs/%s", peerid))
	targetAddr := ipfsaddr.Decapsulate(targetPeerAddr)

	// We have a peer ID and a targetAddr so we add
	// it to the peerstore so LibP2P knows how to contact it
	h.Peerstore().AddAddr(peerid, targetAddr, peerstore.PermanentAddrTTL)
	return peerid
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
	destPeer := flag.String("d", "", "destination peer address")
	proxyPort := flag.Int("p", 8080, "proxy port")
	p2pport := flag.Int("l", 12000, "libp2p listen port")
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
