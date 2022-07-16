# GoEgressCheck
A concurrent egress testing utility written in Golang, including both client and server utilities bundled into one binary. GoEgressCheck is fully self-contained and does not rely on external network connection utilities.

## Usage
Runs follow a simple format, regardless of the mode you choose. You can also use the argument '-h' for help.

```
./go_egress_check -mode [CLIENT/SEVER] -protocol [TCP/UDP/HTTP/DNS] -ip [IP ADDRESS] -domain [DOMAIN] -ports [PORTS_CSV]
```

Server infrastructure should be setup to run the server portion of the utility, which catches the (possible) outbound connection from the client and reports the details to stdout in a clean format. The client will also print output indicating the results, where possible.

**Server utility**  
In this example, the server is running on a host with IP address 192.168.1.1.

```
./go_egress_check -mode 'server' -protocol 'tcp' -ip '0.0.0.0' -ports '80,443,8080'
```

> Note: the 'ports' argument takes a single port, or CSV list of ports and concurrently opens servers on all of the provided ports, where possible. This works in client mode as well.

**Client utility**  
This client is checking the egress-ability of ports 80,443,8080 over TCP to the server hosted on IP 192.168.1.1 above.

```
./go_egress_check -mode 'client' -protocol 'tcp' -ip '192.168.1.1' -ports '80,443,8080'
```

**Output**  
Results are written to stdout in a clean JSON format, and are straightforward to interpret.

```
{"level":"info","msg":"Egress possible on port 443 from 127.0.0.1:51450","time":"2022-07-16T10:11:39-04:00"}
{"level":"info","msg":"Egress possible on port 80 from 127.0.0.1:38800","time":"2022-07-16T10:11:39-04:00"}
{"level":"info","msg":"Egress possible on port 8080 from 127.0.0.1:56306","time":"2022-07-16T10:11:39-04:00"}
```
