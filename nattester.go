// nattester is a tool to quickly test ICE traversal when you have ssh working:
//
// scp nattester do.not.leak.hostnames.google.com:
// nattester --initiator=hostname.example.com
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"google3/third_party/golang/nat/nat"
	"google3/third_party/golang/nat/stun/stun"
)

var (
	responder  = flag.String("responder", "", "hostname of responder; nattester will ssh to the responder and run nattester")
	initiator  bool
	testString = flag.String("test_string",
		"The quick UDP packet jumped over the lazy TCP stream",
		"String to test echo on")
	bindAddress   = flag.String("bind_address", "", "Bind to a local IP address")
	useInterfaces = flag.String("use_interfaces", "", "Comma separated list of interfaces to use. "+
		"If not defined use all the suitable ones")
	blacklistAddresses = flag.String("blacklist_addresses", "0::/0", "Comma separated list of IP ranges "+
		"(in CIDR format) to avoid using as possible candidates")
	remoteBlacklist = flag.String("remote_blacklist", "0::/0", "Comma separated list of IP ranges"+
		"(in CIDR format) for remote host to avoid using as candidates")
	remotePath = flag.String("remote_path", "./nattester", "Path to nattester binary on remote host")
	probeTime  = flag.Duration("probe_time", 1000*time.Millisecond, "Duration between sending probes")
	probeRetry = flag.Int("retry", 0, "DecisionTime (0 implies default)")
	verbose2   = flag.Bool("verbose2", false, "log more details of ice/connector status")
	usage      = flag.Bool("usage", false, "explain what nattester does")
	cmd        *exec.Cmd
)

func openSSH() (io.Writer, io.Reader) {
	rt := "--retry=" + fmt.Sprintf("%d", (*probeRetry))
	ptms := "--probe_time=" + fmt.Sprintf("%dms", (*probeTime).Nanoseconds()/1000000)
	vb2 := "--verbose2=" + strconv.FormatBool(*verbose2)
	log.Printf("ssh %s %s %s \"%s\" %s %s %s", *responder, *remotePath,
		"--blacklist_addresses", *remoteBlacklist, rt, ptms, vb2)
	cmd = exec.Command("ssh", *responder, *remotePath,
		"--blacklist_addresses", *remoteBlacklist, rt, ptms, vb2)
	sshin, err := cmd.StdinPipe()
	if err != nil {
		log.Fatal("cmd.StdinPipe: ", err)
	}
	sshout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal("cmd.StdoutPipe: ", err)
	}
	if err := cmd.Start(); err != nil {
		log.Fatal("ssh start: ", err)
	}
	return sshin, sshout
}

func xchangeCandidates(mine []byte) []byte {
	var sshin io.Writer
	var sshout io.Reader
	candidates := fmt.Sprintf("%s\n", mine)
	if initiator {
		log.Printf("Sending Candidates: %s\n", mine)
		sshin, sshout = openSSH()
		// initiator to responder: io.Copy to sshin (Candidates only)
		io.Copy(sshin, strings.NewReader(candidates))
	} else {
		// responder to initiator: Printf to os.Stdin (Candidates, and "log" messages)
		sshout = os.Stdin
		fmt.Printf(candidates)
	}
	scanner := bufio.NewScanner(sshout)
	var ret []byte
	if scanner.Scan() {
		// first bytes must be the Candidate list:
		ret = scanner.Bytes()
		// local initiator reads remote Candidates, and logs the rest
		if initiator {
			log.Printf("Received Candidates: %s", ret) // the actual candidate list.
			go func() {
				for scanner.Scan() {
					fmt.Printf("\033[0;31m %s\033[0;0m\n", string(scanner.Bytes()))
				}
			}()
		}
		return ret
	}

	// Could not Scan remote Candidates; see what happened to ssh command.
	if initiator {
		if err := cmd.Wait(); err != nil {
			log.Fatal("ssh: ", err)
		}
	}
	// Ok, maybe the scanned data was bad:
	if err := scanner.Err(); err != nil {
		log.Fatal("scanner failed: ", err)
	}
	log.Fatal("failed to get candidates")
	return nil
}

func listize(str string) []string {
	var ret []string
	for _, s := range strings.Split(str, ",") {
		ret = append(ret, strings.TrimSpace(s))
	}
	return ret
}

func main() {
	log.SetOutput(os.Stdout)
	flag.Parse()
	if *usage {
		fmt.Fprintf(os.Stderr, usageText)
		os.Exit(0)
	}
	initiator = *responder != ""
	cfg := nat.DefaultConfig()
	cfg.Verbose = true
	cfg.Verbose2 = *verbose2
	cfg.ProbeTimeout = *probeTime
	if *probeRetry > 0 {
		cfg.ProbeRetry = *probeRetry
	}
	if *bindAddress != "" {
		addr, err := net.ResolveUDPAddr("udp", *bindAddress)
		if err != nil {
			log.Fatalf("Cannot resolve %q as an UDP address: %v", *bindAddress, err)
		}
		cfg.BindAddress = addr
	}
	if *useInterfaces != "" {
		cfg.UseInterfaces = listize(*useInterfaces)
	}
	if initiator {
		log.Printf("Blacklisting: %s", *blacklistAddresses)
		log.Printf("Remote Blacklisting: %s", *remoteBlacklist)
	}
	if *blacklistAddresses != "" {
		stringAddrs := listize(*blacklistAddresses)
		var addrs []*net.IPNet
		for _, a := range stringAddrs {
			_, ipNet, err := net.ParseCIDR(a)
			if err != nil {
				log.Fatalf("Malformed addess %q : %v", a, err)
			}
			addrs = append(addrs, ipNet)
		}
		cfg.BlacklistAddresses = addrs
	}
	conn, err := nat.ConnectOpt(xchangeCandidates, initiator, cfg)
	if err == nil {
		log.Printf("CONNECT: LocalAddr=%s RemoteAddr=%s",
			conn.LocalAddr().String(), conn.RemoteAddr().String())
	}
	if err != nil {
		log.Fatalf("Connect Failed: %v\n", err)
	}
	ret := echoMessage(conn, testString, cfg.ProbeTimeout)
	cmd.Process.Kill()
	os.Exit(ret)
}

// send some bytes over the data conn, verify they come back.
func echoMessage(conn *nat.Conn, testString *string, sleepTime time.Duration) int {
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if !initiator {
		io.Copy(conn, conn) // Poor man's echo sever; runs until cmd.Process.Kill() or conn.Close()
		return 0
	}
	time.Sleep(sleepTime) // some time for responder to catch up
	for {
		log.Printf("Tx testString: \"%s\"", *testString)
		if _, err := conn.Write([]byte(*testString)); err != nil {
			log.Printf("Write Failed: %v\n", err)
			return 1
		}
		// read a message from UDP datacnx:
		buf := make([]byte, 512)
		n, from, err1 := conn.GetConn().ReadFromUDP(buf)
		if err1 != nil {
			log.Printf("Read Failed: %v\n", err1)
			return 2
		}
		recv := (buf[:n])
		packet, err := stun.ParsePacket(recv, nil)
		if err == nil {
			log.Printf("Rx residual %s from %v", stunToString(packet), from)
			time.Sleep(*probeTime)
			continue
		}
		log.Printf("Rx testString: \"%s\"\n", string(recv))
		if bytes.Compare(recv, []byte(*testString)) == 0 {
			log.Print("Success!\n")
			return 0
		}
	}
}

// const (
// 	ClassRequest = iota
// 	ClassIndication
// 	ClassSuccess
// 	ClassError
// 	MethodBinding = 1
// )

func stunToString(packet *stun.Packet) string {
	classNames := map[int]string{
		stun.ClassRequest:    "ClassRequest",
		stun.ClassIndication: "ClassIndication",
		stun.ClassSuccess:    "ClassSuccess",
		stun.ClassError:      "ClassError",
	}
	methNames := map[int]string{
		stun.MethodBinding: "MethodBinding",
	}

	//var cls string
	//var meth string
	//var tid []byte
	//var addr *net.UDPAddr
	cls := classNames[int(packet.Class)]
	meth := methNames[int(packet.Method)]
	return fmt.Sprintf("Tid %x (use candidate %v) Addr=%v Class=%s Method=%s",
		packet.Tid, packet.UseCandidate, packet.Addr, cls, meth)
}

var mytextt = `more text`
var usageText = `
The local/initiator machine makes an SSH connection to the remote/responder machine.
  and runs ./nattester (or --remote_path) in responder mode on that machine.

The two machines exchange IP address Candidates over the SSH connection.
That is: the public IP of their respective Internet/NAT gateways (as obtained from a STUN server)
  Also the host's LAN address (unless blacklisted, which reduces noise in the logs)

Then each host sends a packet that is logged as [TX probe hex_id],
    when the packet is received it is logged as [RX/TX hex_id ClassRequest (use Candidate true/false)]
  and a reply is transmitted back to the sender (the /TX part of RX/TX hex_id)
  if that reply is received by, it is logged as [RX hex_id ClassSuccess]
  (ClassSuccess meaning that hex_id made the complete circuit: [TX]->[RX/TX]->[RX] )

The two side repeat sending packets at --probe_time interval until --decide time.

It is expected that the first packet transmitted (typically by the remote side) will not be received
  because the stateful-UDP Firewall has not yet seen the reciprocal 5-tuple

There is a sequence chart for the ICE/Stateful-UDP packet flow in go/icepick-anatomy
  See also: https://tools.ietf.org/html/rfc8445

The logs from the remote host are sent over the SSH connection and printed by the local host.
  Those lines are indented by a space [" "] (in actual usage, they also appear in RED ink)
  Note: because they are relayed from remote to local, they appear later, out of temporal sequence.

`
