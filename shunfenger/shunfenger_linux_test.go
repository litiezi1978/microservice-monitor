package main

import (
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/testutils"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/vishvananda/netlink"
	"fmt"
	"syscall"
)

var (
	targetNs ns.NetNS
)

func bridgeByName(name string) (*netlink.Bridge, error) {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("could not lookup %q: %v", name, err)
	}
	br, ok := l.(*netlink.Bridge)
	if !ok {
		return nil, fmt.Errorf("%q already exists but is not a bridge", name)
	}
	return br, nil
}

func setupVeth() error{
	contIface := &current.Interface{}
	hostIface := &current.Interface{}
	err := targetNs.Do(func(hostNS ns.NetNS) error {
		//SetupVeth设置一堆虚拟网卡
		//从容器的netns调用SetupVeth,会创建两头的veth, 把宿主机端的veth放到hostNS命名空间
		hostVeth, containerVeth, err := ip.SetupVeth("eth0", 1500, hostNS)
		if err != nil {
			return err
		}
		contIface.Name = containerVeth.Name
		contIface.Mac = containerVeth.HardwareAddr.String()
		contIface.Sandbox = targetNs.Path()

		hostIface.Name = hostVeth.Name

		containerVethLink, err := netlink.LinkByName(containerVeth.Name)
		if err != nil {
			return err
		}

		ipn, err := netlink.ParseIPNet("172.17.100.234/16")
		if err != nil {
			return err
		}

		addr := &netlink.Addr{IPNet: ipn, Label: ""}
		if err := netlink.AddrAdd(containerVethLink, addr); err != nil && err != syscall.EEXIST {
			return fmt.Errorf("could not add IP address to %q: %v", containerVethLink.Attrs().Name, err)
		}

		return nil
	})
	if err!= nil {
		return err
	}

	hostVeth, err := netlink.LinkByName(hostIface.Name)
	if err != nil {
		return fmt.Errorf("failed to lookup %q: %v", hostIface.Name, err)
	}
	hostIface.Mac = hostVeth.Attrs().HardwareAddr.String()

	br, err := bridgeByName("docker0")
	if err!= nil {
		return fmt.Errorf("failed to find docker0: %v", err)
	}

	// connect host veth end to the bridge
	if err := netlink.LinkSetMaster(hostVeth, br); err != nil {
		return fmt.Errorf("failed to connect %q to bridge %v: %v", hostVeth.Attrs().Name, br.Attrs().Name, err)
	}

	return err
}


var _ = Describe("container_monitor test", func() {

	BeforeEach(func() {
		var err error

		targetNs, err = testutils.NewNS()
		Expect(err).NotTo(HaveOccurred())

		err = setupVeth()
		Expect(err).NotTo(HaveOccurred())

		err = setupIP()
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		targetNs.Close()
	})

	It("works with a 0.2.0 config", func() {
		conf := `{
			"cniVersion": "0.2.0",
			"name": "cni-plugin-container_monitor-test",
			"type": "container_monitor",
			"prevResult": {
				"cniVersion":"0.2.0",
                "ip4": {
					"ip": "10.0.0.2/24",
					"gateway": "10.0.0.1",
					"routes": []
				}
			}
		}`

		args := &skel.CmdArgs{
			ContainerID: "dummy",
			Netns:       targetNs.Path(),
			IfName:      "eth0",
			StdinData:   []byte(conf),
		}
		_, _, err := testutils.CmdAddWithArgs(args, func() error { return cmdAdd(args) })
		Expect(err).NotTo(HaveOccurred())
	})
})
