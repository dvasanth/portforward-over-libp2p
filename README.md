# Simple Portforward  over libp2p (supports HTTP/HTTPS tunneling)

This example is extension over the original libp2p http-proxy sample to support HTTP/HTTPS tunneling over internet:

![p2pproxy](https://user-images.githubusercontent.com/9625669/198875277-c957ac53-d8f4-4fa7-919c-e0659e6fc9ca.png)


This program tunnels HTTP/HTTPS traffic over libp2p between two machines. First machine is the sharer to which the HTTP/HTTPS traffic is sent from
second machine. First is called as local & second one as the remote here. Local machine will acts as proxy server to the remote machine.
Using this program, you can access your home HTTP servers from a remote machine. You can also access internet using your hosted VPS server.

## Build

From the  directory run the following:

```
> go build
```

## Usage

First run the program as follows to the machine where you need to run the proxy server (first machine). You may need to allow udp port 12000 to make this peer reachable over internet.

```sh
> ./portforward
libp2p-peer public addresses:
 /ip4/<public-address>/udp/12000/quic/ipfs/<first-machine-peer-id>

libp2p-peer private addresses:
 /ip4/127.0.0.1/udp/12000/quic/ipfs/<first-machine-local-peer-id>
```

Then run the program in second machine which will need to use the proxy server in above program.

```
> .\portforward.exe -d /ip4/<public-address>/udp/12000/quic/ipfs/<first-machine-peer-id-reacable-over internet>
libp2p-peer public addresses:
 /ip4/171.50.208.188/udp/12000/quic/ipfs/<second-machine-peer-id>

libp2p-peer private addresses:
 /ip4/127.0.0.1/udp/12000/quic/ipfs/<second-machine-local-peer-id>
Change Browser proxy setting to 127.0.0.1: 8080
```

Now you can see the proxy setting of your browser to 127.0.0.1:8080. All the requests will be sent to first machine & it will send back the response.

## Security
Above steps will make the proxy server exposed to the p2p network. To allow the proxy server to be accessed by only known peers. You can add the second machine peer id to the accepted peer list. Here is the command to be run in first machine to accept only from selected peers:

> ./portforward -a <second-machine-peer-id>
libp2p-peer public addresses:
 /ip4/<public-address>/udp/12000/quic/ipfs/<first-machine-peer-id>

libp2p-peer private addresses:
 /ip4/127.0.0.1/udp/12000/quic/ipfs/<first-machine-local-peer-id>
```
