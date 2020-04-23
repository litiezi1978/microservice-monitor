package main

import (
	"log"
	"os"
	"fmt"
	"strings"
	"encoding/json"
	"os/exec"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/cni/pkg/types/current"
)

var trace *log.Logger

func init(){
	traceFile, err := os.OpenFile("/var/log/bpfloader.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Failed to open %v", err)
	}
	trace = log.New(traceFile, "", log.Ldate|log.Ltime|log.Lshortfile)
}

/*
{
	"cniVersion":"0.2.0",
	"name":"cbr0",
	"type":"loader"
	"prevResult":{
		"cniVersion":"0.2.0",
		"ip4":{
			"ip":"10.244.1.142/24",
			"gateway":"10.244.1.1",
			"routes":[
				{"dst":"10.244.0.0/16","gw":"10.244.1.1"},
				{"dst":"0.0.0.0/0","gw":"10.244.1.1"}
			]
		},
		"dns":{}
	}
}
 */
type CNIConf struct {
	types.NetConf
	PrevResult *map[string]interface{} `json:"prevResult"`
	FinalResult *current.Result
}

func parseConfigFromStdin(stdin []byte) (*CNIConf, error){
	conf := CNIConf{}

	if err:= json.Unmarshal(stdin, &conf); err!=nil{
		return nil, fmt.Errorf("Failed to parse config from STDIN: %v", err)
	}

	if conf.PrevResult != nil{
		prevResultBytes, err := json.Marshal(conf.PrevResult)
		if err != nil {
			return nil, fmt.Errorf("Could not serialize prevResult: %v", err)
		}

		// 找到一个与请求的版本匹配的Result对象,请求这个对象来解析这个插件的结果字符串
		prevResultObj, err := version.NewResult(conf.CNIVersion, prevResultBytes)
		if err != nil {
			return nil, fmt.Errorf("Could not parse prevResult: %v", err)
		}

		//转换成当前版本
		conf.FinalResult, err = current.NewResultFromResult(prevResultObj)
		if err != nil {
			return nil, fmt.Errorf("Could not convert result to current version: %v", err)
		}
	}

	return &conf, nil
}

func getIpFromPrevResult(conf *CNIConf) (ip, mask, gw string, error error){
	ips := conf.FinalResult.IPs
	if ips == nil || len(ips) == 0 {
		return "", "", "", fmt.Errorf("No IP record from previous result")
	}
	ip = ips[0].Address.IP.String()
	mask = ips[0].Address.Mask.String()
	gw = ips[0].Gateway.String()
	return ip, mask, gw, nil
}

type PodInfo struct {
	podName string
	podNamespace string
	containerID string
	netnsPath string
	pid string
	ifname string
	ipv4 string
	mask string
	gw string
}

//Args:IgnoreUnknown=1;K8S_POD_NAMESPACE=hotel;K8S_POD_NAME=user-5565949d46-zm87m;K8S_POD_INFRA_CONTAINER_ID=04c3...
func parseArgs(args string)(string, string, error){
	kvs := strings.Split(args, ";")
	if kvs == nil && len(kvs)==0 {
		return "", "", fmt.Errorf("No parameters in Args")
	}

	var(
		podName string
		podNamespace string
	)
	for i:=0; i<len(kvs); i++ {
		kv := strings.Split(kvs[i], "=")
		if kv[0] == "K8S_POD_NAME"{
			podName = kv[1]
		}
		if kv[0] == "K8S_POD_NAMESPACE" {
			podNamespace = kv[1]
		}
	}
	return podName, podNamespace, nil
}

//从netns路径中取pid, 路径形如: /proc/10834/ns/net
func parsePidFromNetns(netns string)(string, error){
	folder_names := strings.Split(netns, "/")
	if folder_names == nil && len(folder_names)==0 {
		return "", fmt.Errorf("netns path wrong: %v", netns)
	}

	var pid string
	for i:=0; i<len(folder_names); i++ {
		if folder_names[i] == "proc" {
			pid = folder_names[i+1]
			break
		}
	}
	return pid, nil
}

/*
containerID: 04c3...
Netns: /proc/10834/ns/net
IfName: eth0
Args:IgnoreUnknown=1;K8S_POD_NAMESPACE=hotel;K8S_POD_NAME=user-5565949d46-zm87m;K8S_POD_INFRA_CONTAINER_ID=04c3...
Path:/opt/cni/bin
 */
func cmdAdd(args *skel.CmdArgs) error {
	trace.Printf("CmdAdd with:\ncontainerID: %s\nNetns: %s\nIfName: %s\nArgs:%s\nPath:%s\nstdin: %s\n",
		args.ContainerID, args.Netns, args.IfName, args.Args, args.Path, args.StdinData)

	conf, err := parseConfigFromStdin(args.StdinData)
	if err != nil {
		trace.Printf("error parse config %v", err)
		return err
	}

	if conf.FinalResult == nil {
		return fmt.Errorf("must be called as chained plugin\n")
	}

	var podInfo *PodInfo;

	podInfo.containerID = args.ContainerID
	podInfo.netnsPath = args.Netns
	if podInfo.containerID == "" || podInfo.netnsPath == "" {
		return fmt.Errorf("no conatinerID or netnsPath")
	}
	trace.Printf("podInfo.containerId=%s, podInfo.netns=%s", podInfo.containerID, podInfo.netnsPath)

	podInfo.podName, podInfo.podNamespace, err = parseArgs(args.Args)
	if err!= nil {
		return err
	}
	trace.Printf("podInfo.podName=%s, podInfo.podNamespace=%s", podInfo.podName, podInfo.podNamespace)

	podInfo.pid, err = parsePidFromNetns(args.Netns)
	if err!= nil {
		return err
	}
	trace.Printf("podInfo.pid=%s", podInfo.pid)

	podInfo.ifname = args.IfName
	if podInfo.ifname == "" {
		return fmt.Errorf("no ifname")
	}
	trace.Printf("podInfo.ifname=%s", podInfo.ifname)

	podInfo.ipv4, podInfo.mask, podInfo.gw, err = getIpFromPrevResult(conf)
	if err!= nil {
		return err
	}
	trace.Printf("podInfo.ipv4=%s, podInfo.mask=%s, podInfo.gw=%s", podInfo.ipv4, podInfo.mask, podInfo.gw)

	netNs, err := ns.GetNS(podInfo.netnsPath)
	if err != nil {
		err = fmt.Errorf("failed to open netns %q: %s", podInfo.netnsPath, err)
	}
	defer netNs.Close()

	err = netNs.Do(func (hostNS ns.NetNS) error{
		cmd1 := exec.Command("tc", "qdisc", "add", "dev", podInfo.ifname, "clsact")
		err = cmd1.Run()
		if err!= nil {
			return err
		}

		cmd2 := exec.Command("tc", "filter", "add", "dev", podInfo.ifname, "ingress",
			"bpf", "da", "obj", "lxc_traffic.o", "sec", "ingress")
		err = cmd2.Run()
		if err!= nil {
			return err
		}

		cmd3 := exec.Command("tc", "filter", "add", "dev", podInfo.ifname, "egress",
			"bpf", "da", "obj", "lxc_traffic.o", "sec", "egress")
		err = cmd3.Run()
		if err!= nil {
			return err
		}

		return err
	})

	err = types.PrintResult(conf.FinalResult, conf.CNIVersion)
	return err
}

/*
	containerID: 8fd61...
	Netns: /proc/9399/ns/net
	IfName: eth0
	Args:IgnoreUnknown=1;K8S_POD_NAMESPACE=hotel;K8S_POD_NAME=rate-6b5b6f6b-mkrhv;K8S_POD_INFRA_CONTAINER_ID=8fd6...
	Path:/opt/cni/bin
	stdin: {"cniVersion":"0.2.0","name":"cbr0","type":"loader"}
 */
func cmdDel(args *skel.CmdArgs) error {
	trace.Printf("CmdDel with:\ncontainerID: %s\nNetns: %s\nIfName: %s\nArgs:%s\nPath:%s\nstdin: %s\n",
		args.ContainerID, args.Netns, args.IfName, args.Args, args.Path, args.StdinData)

	return nil
}

func main(){
	skel.PluginMain(cmdAdd, nil, cmdDel, version.All, "container_monitor")
}
