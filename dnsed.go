/*
Answer rewriting DNS Proxy
*/
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/miekg/dns"
)

type flagStringList []string

func (i *flagStringList) String() string {
	return fmt.Sprint(*i)
}

func (i *flagStringList) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var (
	verbose = flag.Bool("verbose", false, "verbose output")
	address = flag.String("address", ":53", "Address to listen to (TCP and UDP)")

	uplink = flag.String("uplink", "", "host:port of uplink to send the queries")

	ipfile       = flag.String("ipfile", "", "file with IP IP mappings to replace\nmay contain only partial mappings like 10 11 or 192.168 10.168")
	ipmap        []map[string]string
	ipmapToCheck = [4]int{0, 0, 0, 0}

	namefile = flag.String("namefile", "", "zonefile with named 'NAME TTL IN A IP' names to replace")
	namemap  map[string][]dns.RR
)

func check(err error, msg string) {
	if err != nil {
		log.Fatalf(msg+" %s", err)
		// panic(e)
	}
}

func init() {
	//rand.Seed(time.Now().Unix())
}

func main() {
	flag.Parse()
	fmt.Println("dnsed V1.2 - christof@chen.de")
	fmt.Println("rewrite DNS responses based on name/ip mappings")
	// Read the translation list IP -> IP

	if *ipfile != "" {

		file, err := os.Open(*ipfile)
		check(err, "can't read ipfile:")

		scanner := bufio.NewScanner(file)
		scanner.Split(bufio.ScanLines)

		ipmap = make([]map[string]string, 4)
		for i := 0; i < 4; i++ {
			ipmap[i] = make(map[string]string)
			//ipmapToCheck[i] = 0
		}
		nn := 0
		for scanner.Scan() {
			words := strings.Fields(scanner.Text())
			if len(words) > 1 {
				if words[0][0] == '#' || words[0][0] == ';' {
					continue
				}

				dots := strings.Count(words[0], ".")
				if dots != strings.Count(words[1], ".") {
					log.Printf("skip malformed IP rule %+v to %+v\n", words[0], words[1])
					continue
				}
				ipmap[dots][words[0]] = words[1]
				ipmapToCheck[dots] = 1
				nn++
			}
		}
		log.Printf("read %+v IP mappings from %+v\n", nn, *ipfile)
		file.Close()
	}
	// Read the translation list NAME -> IP
	// Format: zone file...
	if *namefile != "" {
		file, err := os.Open(*namefile)
		check(err, "can't read namefile:")

		namemap = make(map[string][]dns.RR)
		nn := 0

		zp := dns.NewZoneParser(file, "", "")

		for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
			//if _, ok := rr.(*dns.A); ok {
			label := string(rr.Header().Name)
			namemap[label] = append(namemap[label], rr)
			nn++
			//}
		}

		if err := zp.Err(); err != nil {
			log.Println(err)
		}

		log.Printf("read %+v name mappings from %+v\n", nn, *namefile)

		file.Close()
	}
	udpServer := &dns.Server{Addr: *address, Net: "udp"}
	tcpServer := &dns.Server{Addr: *address, Net: "tcp"}

	log.Printf("server ready\n")

	dns.HandleFunc(".", myhandler)

	go func() {
		if err := udpServer.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()
	go func() {
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()

	// Wait for SIGINT or SIGTERM
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	udpServer.Shutdown()
	tcpServer.Shutdown()
}

func validHostPort(s string) bool {
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" || port == "" {
		return false
	}
	return true
}

func myhandler(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		dns.HandleFailed(w, req)
		return
	}

	if *uplink == "" {
		dns.HandleFailed(w, req)
		return
	}

	transport := "udp"
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		transport = "tcp"
	}

	c := &dns.Client{Net: transport}
	resp, _, err := c.Exchange(req, *uplink)
	if err != nil {
		dns.HandleFailed(w, req)
		return
	}

	// rewrite based on the IP
	// 1:1 inline replace of the IP(s) in the packet
	// check most specific first
	var replace string = ""
	for _, rr := range resp.Answer {
		if _, ok := rr.(*dns.A); ok {
			// Rewrite the IP in the Answer section
			ip := string(rr.(*dns.A).A.String())
			var octets []string
			octets = strings.Split(ip, ".")
			//fmt.Printf("DEBUG check IP %+v \n", octets)
			for ii := 3; ii > -1; ii-- {
				//fmt.Printf("DEBUG ipmapToCheck[%+v] %+v \n", ii, ipmapToCheck[ii])
				if ipmapToCheck[ii] == 1 {
					var checkip = strings.Join(octets[0:ii+1], ".")
					//fmt.Printf("DEBUG check IP match %+v in run %+v as %+v\n", ip, ii, checkip)
					replace = ipmap[ii][checkip]
					if replace != "" {
						replace = replace + "." + strings.Join(octets[ii+1:4], ".")
						log.Printf("IP based rewrite %+v to %+v\n", rr, replace)
						rr.(*dns.A).A = net.ParseIP(replace)
						break
					}
				}
			}
		}
	}

	// try to rewrite based on the Name
	// remove the original answer section, replace with the new answer

	var newanswer []dns.RR
	skipover := make(map[string]int)

	doreplace := false
	for _, rr := range resp.Answer {
		// rewrite A records only :-)
		if _, ok := rr.(*dns.A); ok {
			name := string(rr.Header().Name)

			if _, ok := skipover[name]; !ok {
				// only if NOT processed this "label A" already
				replacerr := namemap[name]

				for _, rrr := range replacerr {
					if _, ok := rrr.(*dns.A); ok {
						log.Printf("name based rewrite %+v to %+v\n", rr, rrr)
						newanswer = append(newanswer, rrr)
						doreplace = true
						skipover[name] = 1
					}
				}
			}

		} else {
			newanswer = append(newanswer, rr)
		}

	}
	if doreplace {
		resp.Answer = newanswer
		//log.Printf("debug doreplace  %+v\n", resp.Answer)
	}

	w.WriteMsg(resp)
}
