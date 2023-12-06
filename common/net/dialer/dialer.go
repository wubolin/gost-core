package dialer

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	xnet "github.com/go-gost/core/common/net"
	"github.com/go-gost/core/logger"
)

const (
	DefaultTimeout = 10 * time.Second
)

var (
	DefaultNetDialer = &NetDialer{}
)

type NetDialer struct {
	Interface string
	Mark      int
	Timeout   time.Duration
	DialFunc  func(ctx context.Context, network, addr string) (net.Conn, error)
	Logger    logger.Logger
}

func (d *NetDialer) Dial(ctx context.Context, network, addr string) (conn net.Conn, err error) {
	if d == nil {
		d = DefaultNetDialer
	}

	timeout := d.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	if d.DialFunc != nil {
		return d.DialFunc(ctx, network, addr)
	}

	log := d.Logger
	if log == nil {
		log = logger.Default()
	}

	deadline := time.Now().Add(timeout)
	ifces := strings.Split(d.Interface, ",")
	for _, ifce := range ifces {
		strict := strings.HasSuffix(ifce, "!")
		ifce = strings.TrimSuffix(ifce, "!")
		var ifceName string
		var ifAddrs []net.Addr
		ifceName, ifAddrs, err = xnet.ParseInterfaceAddr(ifce, network)
		if err != nil && strict {
			return
		}

		for _, ifAddr := range ifAddrs {
			conn, err = d.dialOnce(ctx, network, addr, ifceName, ifAddr, deadline, log)
			if err == nil {
				return
			}

			log.Debugf("dial %s %v@%s failed: %s", network, ifAddr, ifceName, err)

			if strict &&
				!strings.Contains(err.Error(), "no suitable address found") &&
				!strings.Contains(err.Error(), "mismatched local address type") {
				return
			}

			if time.Until(deadline) < 0 {
				return
			}
		}
	}

	return
}

func (d *NetDialer) dialOnce(ctx context.Context, network, addr, ifceName string, ifAddr net.Addr, deadline time.Time, log logger.Logger) (net.Conn, error) {
	if ifceName != "" {
		log.Debugf("interface: %s %v/%s", ifceName, ifAddr, network)
	}

	switch network {
	case "udp", "udp4", "udp6":
		if addr == "" {
			var laddr *net.UDPAddr
			if ifAddr != nil {
				laddr, _ = ifAddr.(*net.UDPAddr)
			}

			c, err := net.ListenUDP(network, laddr)
			if err != nil {
				return nil, err
			}
			sc, err := c.SyscallConn()
			if err != nil {
				log.Error(err)
				return nil, err
			}
			err = sc.Control(func(fd uintptr) {
				if ifceName != "" {
					if err := bindDevice(fd, ifceName); err != nil {
						log.Warnf("bind device: %v", err)
					}
				}
				if d.Mark != 0 {
					if err := setMark(fd, d.Mark); err != nil {
						log.Warnf("set mark: %v", err)
					}
				}
			})
			if err != nil {
				log.Error(err)
			}
			return c, nil
		}
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("dial: unsupported network %s", network)
	}
	netd := net.Dialer{
		Deadline:  deadline,
		LocalAddr: ifAddr,
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if ifceName != "" {
					if err := bindDevice(fd, ifceName); err != nil {
						log.Warnf("bind device: %v", err)
					}
				}
				if d.Mark != 0 {
					if err := setMark(fd, d.Mark); err != nil {
						log.Warnf("set mark: %v", err)
					}
				}

				_, portStr, _ := net.SplitHostPort(address)
				// a := strings.Split(address, ":")
				// var port int
				// if len(a) > 1 {
				// 	port, _ = strconv.Atoi(a[1])
				// }
				port, _ := strconv.Atoi(portStr)

				ttl := 63 + 64*(1+port%3)
				var err error
				switch network {
				case "tcp6":
					// Level: iana.ProtocolIPv6, Name: unix.IPV6_UNICAST_HOPS
					// 	"golang.org/x/net/internal/iana"
					// "golang.org/x/net/internal/socket"
					// ProtocolIPv6 is 41, unix.IPV6_UNICAST_HOPS is 4
					err = syscall.SetsockoptInt(syscall.Handle(fd), 41, 4, ttl)
					// err = syscall.SetsockoptInt(int(fd), 41, 4, ttl)
				default:
					err = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
					// err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
				}

				if err != nil {
					log.Warnf("ttl error: %v", err)
				}

			})
		},
	}
	return netd.DialContext(ctx, network, addr)
}
