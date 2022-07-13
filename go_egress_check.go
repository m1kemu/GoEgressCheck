package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

func ParseQuery(m *dns.Msg) {
	for _, q := range m.Question {
		switch q.Qtype {
		case dns.TypeA:
			log.Info("DNS query received: " + q.Name)

			response_string := "what.a.shite.domain. A 0.0.0.0"


			if strings.Split(q.Name, ".")[0] == "check" {
				log.Info("Egress possible using DNS")

				response_string = q.Name + " A 1.1.1.1"
			}

			rr, err := dns.NewRR(response_string)

			if err == nil {
				m.Answer = append(m.Answer, rr)
			}
		}
	}
}

func HandleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
		case dns.OpcodeQuery:
			ParseQuery(m)
	}

	w.WriteMsg(m)
}

func DNSServerGenerator(domain string, port string, wg *sync.WaitGroup) {
	port_int, _ := strconv.Atoi(port)

	dns.HandleFunc(domain + ".", HandleDnsRequest)

	server := &dns.Server{Addr: ":" + strconv.Itoa(port_int), Net: "udp"}

	log.Info("DNS server started on port " + port)

	err := server.ListenAndServe()

	defer server.Shutdown()
	if err != nil {
		log.Error(err)
	}
}

func DNSServer(domain string, ports []string) {
	var wg sync.WaitGroup

	for i := range ports {
		log.Debug("Attempting to start DNS server on port " + ports[i])

		wg.Add(1)

		go DNSServerGenerator(domain, ports[i], &wg)

		log.Debug("Started DNS server")
	}

	wg.Wait()
}

func TestPortDNS(domain string, port string, dest_ip string, wg *sync.WaitGroup) {
	defer wg.Done()

	m := new(dns.Msg)
	m.SetQuestion( "check." + domain + ".", dns.TypeA)

	c := new(dns.Client)
	in, _, err := c.Exchange(m, dest_ip + ":" + port)
	if err != nil {
		log.Error(err)
	} else {
		log.Debug("DNS response: " + string(in.Answer[0].String()))

		if strings.Split(in.Answer[0].String(), "\t")[4] == "1.1.1.1" {
			log.Info("Egress possible using DNS on port " + port + " and ip " + dest_ip)
		}
	}
}

func DNSClient(domain string, ports []string, dest_ip string) {
	var wg sync.WaitGroup

	for i := range ports {
		wg.Add(1)

		log.Debug("Attempting to check " + domain + " using nameserver " + dest_ip + ":" + ports[i])

		go TestPortDNS(domain, ports[i], dest_ip, &wg)

		log.Info("DNS data sent")
	}

	wg.Wait()
}

func HandleTCPConn(conn net.Conn, src_port string) {
	log.Debug("Connection received from " + conn.RemoteAddr().String() + " destination port " + src_port)

	for {
		data, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			log.Error("Error reading from connection")
			return
		}

		data_cleaned := strings.TrimSpace(string(data))

		if data_cleaned == "CHECK" {
			log.Info("Egress possible on port " + src_port + " from " + conn.RemoteAddr().String())
			break
		} else {
			log.Debug("Received invalid data on port " + src_port + " from " + conn.RemoteAddr().String())
		}
	}

	conn.Close()
}

func TCPServerGenerator(src_port string, src_ip string) {
	l, err := net.Listen("tcp4", src_ip+":"+src_port)
	if err != nil {
		log.Info("Error starting TCP server on " + src_ip + ":" + src_port)
		log.Error(err)
		return
	}

	defer l.Close()

	log.Debug("Started TCP server on " + src_ip + ":" + src_port)

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Error("Error accepting connection")
			return
		}

		go HandleTCPConn(conn, src_port)
	}
}

func TCPServer(ports []string, src_ip string) {
	var wg sync.WaitGroup

	for i := range ports {
		log.Debug("Attempting to start TCP server on port " + ports[i])

		wg.Add(1)

		go TCPServerGenerator(ports[i], src_ip)
	}

	wg.Wait()
}

func UDPServerGenerator(src_port string, src_ip string) {
	port_int, _ := strconv.Atoi(src_port)

	addr := net.UDPAddr{
		Port: port_int,
		IP:   net.ParseIP(src_ip),
	}

	l, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Error("Error starting UDP listener " + src_ip + ":" + src_port)
		log.Error(err)
		return
	}

	defer l.Close()

	log.Debug("Started UDP server on " + src_ip + ":" + src_port)

	buffer := make([]byte, 1024)

	for {
		num_bytes, addr, err := l.ReadFromUDP(buffer)
		if err != nil {
			log.Error("Error reading UDP data")
			log.Error(err)
		}

		data_cleaned := strings.TrimSpace(string(buffer[0:num_bytes]))

		log.Debug("Received data: " + data_cleaned)

		if data_cleaned == "CHECK" {
			log.Info("Egress possible on port " + src_port + " from " + addr.String())
			break
		} else {
			log.Debug("Received invalid data on port " + src_port + " from " + addr.String())
		}
	}
}

func UDPServer(ports []string, src_ip string) {
	var wg sync.WaitGroup

	for i := range ports {
		log.Debug("Attempting to start UDP server on port " + ports[i])

		wg.Add(1)

		go UDPServerGenerator(ports[i], src_ip)
	}

	wg.Wait()
}

func TestPortUDP(dest_port string, dest_ip string, wg *sync.WaitGroup) {
	defer wg.Done()

	log.SetFormatter(&log.JSONFormatter{})

	s, err := net.ResolveUDPAddr("udp4", dest_ip+":"+dest_port)
	if err != nil {
		log.Error("Error resolving UDP address")
		log.Error(err)
	}

	conn, err := net.DialUDP("udp4", nil, s)
	if err != nil {
		log.Error("Error dialing UDP connection")
		log.Error(err)
		return
	}

	defer conn.Close()

	fmt.Fprintf(conn, "CHECK\n")

	log.Info("UDP data sent to " + dest_ip + ":" + dest_port)
}

func UDPClient(ports []string, dest_ip string) {
	var wg sync.WaitGroup

	for i := range ports {
		wg.Add(1)

		log.Debug("Attempting to check " + dest_ip + ":" + ports[i])

		go TestPortUDP(ports[i], dest_ip, &wg)
	}

	wg.Wait()
}

func TestPortTCP(dest_port string, dest_ip string, wg *sync.WaitGroup) {
	defer wg.Done()

	log.SetFormatter(&log.JSONFormatter{})

	conn, err := net.Dial("tcp", dest_ip+":"+dest_port)
	if err != nil {
		log.Error("Error dialing connection " + dest_ip + ":" + dest_port)
		return
	}

	log.Debug("TCP connection established to " + dest_ip + ":" + dest_port)

	_, err = conn.Write([]byte("CHECK\n"))
	if err != nil {
		log.Error("Error writing data")
		return
	}

	log.Info("TCP data sent to " + dest_ip + ":" + dest_port)
}

func TCPClient(ports []string, dest_ip string) {
	var wg sync.WaitGroup

	for i := range ports {
		wg.Add(1)

		log.Debug("Attempting to check " + dest_ip + ":" + ports[i])

		go TestPortTCP(ports[i], dest_ip, &wg)
	}

	wg.Wait()
}

func HTTPHandler(writer http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/check" {
		http.Error(writer, "404 not found.", http.StatusNotFound)
		return
	}

	http.ServeFile(writer, req, "index.html")

	port := req.URL.Query().Get("port")

	log.Info("Egress possible on port " + port + " from " + req.RemoteAddr)
}

func HTTPServer(ports []string, dest_ip string) {
	http.HandleFunc("/check", HTTPHandler)

	var wg sync.WaitGroup

	for i := range ports {
		log.Debug("Attempting to start HTTP server on port " + ports[i])

		wg.Add(1)

		go http.ListenAndServe(dest_ip+":"+ports[i], nil)

		log.Debug("Started HTTP server on " + dest_ip + ":" + ports[i])
	}

	wg.Wait()
}

func TestPortHTTP(dest_ip string, dest_port string, wg *sync.WaitGroup) {
	defer wg.Done()

	client := http.Client{
		Timeout: time.Duration(1) * time.Second,
	}

	u, err := url.Parse("http://" + dest_ip + ":" + dest_port + "/check")
	if err != nil {
		log.Error("Error parsing URL")
		log.Error(err)
		return
	}

	u.Scheme = "http"
	u.Host = dest_ip + ":" + dest_port
	u.Path = "/check"
	q := u.Query()
	q.Add("port", dest_port)
	u.RawQuery = q.Encode()

	resp, err := client.Get(u.String())
	if err != nil {
		log.Error("Error sending HTTP request")
		log.Error(err)
		return
	}

	defer resp.Body.Close()
}

func HTTPClient(ports []string, dest_ip string) {
	var wg sync.WaitGroup

	for i := range ports {
		wg.Add(1)

		log.Debug("Attempting to check " + dest_ip + ":" + ports[i])

		go TestPortHTTP(dest_ip, ports[i], &wg)

		log.Info("HTTP data sent to " + dest_ip + ":" + ports[i])
	}

	wg.Wait()
}

func main() {
	var ports_csv string
	var ip string
	var mode string
	var protocol string
	var domain string

	flag.StringVar(&ports_csv, "ports", "", "A comma-seperated list of ports to test for egress access")
	flag.StringVar(&ip, "ip", "", "The IP address to serve on in server mode, or the target IP address to test egress to in client mode")
	flag.StringVar(&mode, "mode", "", "Server or client mode (case insensitive)")
	flag.StringVar(&protocol, "protocol", "", "Protocol to test: tcp, udp, http, dns")
	flag.StringVar(&domain, "domain", "", "The domain name to respond/query if in DNS server/client mode")

	flag.Parse()

	mode = strings.ToLower(mode)
	protocol = strings.ToLower(protocol)

	log.SetFormatter(&log.JSONFormatter{})
	log.SetLevel(log.DebugLevel)

	ports := strings.Split(ports_csv, ",")

	for i := range ports {
		ports[i] = strings.TrimSpace(ports[i])
	}

	switch {
	case mode == "client" && protocol == "tcp" && len(ports) != 0 && ip != "":
		log.Info("Running in TCP client mode")
		TCPClient(ports, ip)
	case mode == "server" && protocol == "tcp" && len(ports) != 0 && ip != "":
		log.Info("Running in TCP server mode")
		TCPServer(ports, ip)
	case mode == "server" && protocol == "udp" && len(ports) != 0 && ip != "":
		log.Info("Running in UDP server mode")
		UDPServer(ports, ip)
	case mode == "client" && protocol == "udp" && len(ports) != 0 && ip != "":
		log.Info("Running in UDP client mode")
		UDPClient(ports, ip)
	case mode == "server" && protocol == "http" && len(ports) != 0 && ip != "":
		log.Info("Running in HTTP server mode")
		HTTPServer(ports, ip)
	case mode == "client" && protocol == "http" && len(ports) != 0 && ip != "":
		log.Info("Running in HTTP client mode")
		HTTPClient(ports, ip)
	case mode == "server" && protocol == "dns" && len(ports) != 0 && domain != "" && ip != "":
		log.Info("Running in DNS server mode")
		DNSServer(domain, ports)
	case mode == "client" && protocol == "dns" && len(ports) != 0 && domain != "" && ip != "":
		log.Info("Running in DNS client mode")
		DNSClient(domain, ports, ip)
	default:
		log.Info("No correct combination of arguments provided")
	}
}
