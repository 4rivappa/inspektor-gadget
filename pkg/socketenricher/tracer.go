// Copyright 2022 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package socketenricher

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	log "github.com/sirupsen/logrus"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/btfgen"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/btfhelpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/kallsyms"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/kallsyms/symscache"
	bpfiterns "github.com/inspektor-gadget/inspektor-gadget/pkg/utils/bpf-iter-ns"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang -cflags ${CFLAGS} socketenricher ./bpf/socket-enricher.bpf.c -- -I./bpf/

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang -cflags ${CFLAGS} socketsiter ./bpf/sockets-iter.bpf.c -- -I./bpf/

func init() {
	spec, err := loadSocketsiter()
	if err != nil {
		panic(err)
	}
	symscache.RegisterSymbolsFromSpec(spec)

	spec, err = loadSocketenricher()
	if err != nil {
		panic(err)
	}
	symscache.RegisterSymbolsFromSpec(spec)
}

const (
	SocketsMapName          = "gadget_sockets"
	SocketsValueName        = "gadget_socket_value"
	optionalFieldsStartName = "optional_fields_start"
)

// SocketEnricher creates a map exposing processes owning each socket.
//
// This makes it possible for network gadgets to access that information and
// display it directly from the BPF code. Example of such code in the dns and
// sni gadgets.
type SocketEnricher struct {
	spec     *ebpf.CollectionSpec
	objs     socketenricherObjects
	objsIter socketsiterObjects
	links    []link.Link

	closeOnce sync.Once
	done      chan bool
	config    Config

	valueBtfStruct *btf.Struct
	btfSpec        *btf.Spec
}

func (se *SocketEnricher) SocketsMap() *ebpf.Map {
	return se.objs.GadgetSockets
}

type FieldConfig struct {
	Enabled bool
	Size    uint32
}

type Config struct {
	Cwd     FieldConfig
	Exepath FieldConfig
}

func isPowerOfTwo(n uint32) bool {
	return n > 0 && (n&(n-1)) == 0
}

func validateFieldConfig(config FieldConfig) error {
	if config.Enabled {
		if !isPowerOfTwo(config.Size) {
			return fmt.Errorf("size must be a power of two, got %d", config.Size)
		}
		if config.Size > 4096 {
			return fmt.Errorf("size must be <= 4096, got %d", config.Size)
		}
	}
	return nil
}

func NewSocketEnricher(config Config) (*SocketEnricher, error) {
	var errs []error
	errs = append(errs, validateFieldConfig(config.Cwd))
	errs = append(errs, validateFieldConfig(config.Exepath))
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("invalid field configuration: %w", err)
	}

	se := &SocketEnricher{
		config: config,
	}

	if err := se.start(); err != nil {
		se.Close()
		return nil, err
	}

	return se, nil
}

// BTFSpec returns the BTF Spec and the BTF struct for the sockets_value map
func (se *SocketEnricher) BTFSpec() (*btf.Spec, *btf.Struct, error) {
	return se.btfSpec, se.valueBtfStruct, nil
}

func (se *SocketEnricher) generateBTFSpec() error {
	uint32T := &btf.Int{
		Size:     4,
		Encoding: btf.Unsigned,
	}
	charT := &btf.Int{
		Size:     1,
		Encoding: btf.Char,
	}

	types := []btf.Type{uint32T, charT}

	// Look for the sockets_val btf structure to fill fixed members
	srcBtfStruct := &btf.Struct{}
	if err := se.spec.Types.TypeByName(SocketsValueName, &srcBtfStruct); err != nil {
		return fmt.Errorf("getting BTF struct %q: %w", SocketsValueName, err)
	}

	members := []btf.Member{}
	currentOffset := uint32(0)
	for _, member := range srcBtfStruct.Members {
		// stop when we find the optional fields
		if member.Name == optionalFieldsStartName {
			currentOffset = member.Offset.Bytes()
			break
		}
		members = append(members, member)
	}

	addMember := func(name string, size uint32, typ btf.Type) {
		member := btf.Member{
			Name:   name,
			Type:   typ,
			Offset: btf.Bits(currentOffset * 8),
		}
		members = append(members, member)
		types = append(types, typ)
		currentOffset += size
	}

	if se.config.Cwd.Enabled {
		typ := &btf.Array{
			Index:  uint32T,
			Type:   charT,
			Nelems: se.config.Cwd.Size,
		}
		addMember("cwd", se.config.Cwd.Size, typ)
	}
	if se.config.Exepath.Enabled {
		typ := &btf.Array{
			Index:  uint32T,
			Type:   charT,
			Nelems: se.config.Exepath.Size,
		}
		addMember("exepath", se.config.Exepath.Size, typ)
	}

	btfStruct := &btf.Struct{
		Name:    SocketsValueName,
		Size:    currentOffset,
		Members: members,
	}
	types = append(types, btfStruct)

	btfSpec, err := btfhelpers.BuildSpec(types)
	if err != nil {
		return fmt.Errorf("creating socket enricher BTF spec: %w", err)
	}

	se.btfSpec = btfSpec
	se.valueBtfStruct = btfStruct

	return nil
}

func (se *SocketEnricher) start() error {
	symscache.PopulateKallsymsCache()
	specIter, err := loadSocketsiter()
	if err != nil {
		return fmt.Errorf("loading socketsiter asset: %w", err)
	}

	err = kallsyms.SpecUpdateAddresses(specIter, []string{"socket_file_ops"})
	if err != nil {
		// Being unable to access to /proc/kallsyms can be caused by not having
		// CAP_SYSLOG.
		log.Warnf("updating socket_file_ops address with ksyms: %v\nEither you cannot access /proc/kallsyms or this file does not contain socket_file_ops", err)
	}

	se.spec, err = loadSocketenricher()
	if err != nil {
		return fmt.Errorf("loading socket enricher asset: %w", err)
	}

	if err := se.generateBTFSpec(); err != nil {
		return fmt.Errorf("getting BTF spec: %w", err)
	}

	opts := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			KernelTypes:            btfgen.GetBTFSpec(),
			ExtraRelocationTargets: []*btf.Spec{se.btfSpec},
		},
	}

	// update size of the sockets_map according to the fields configured by the
	// user. This works because CO-RE ensures programs will access the optional
	// fields at the right offset in this structure.
	mapSpecIter := specIter.Maps[SocketsMapName]
	mapSpecIter.ValueSize = se.valueBtfStruct.Size
	mapSpecIter.Value = se.valueBtfStruct
	mapSpec := se.spec.Maps[SocketsMapName]
	mapSpec.ValueSize = se.valueBtfStruct.Size
	mapSpec.Value = se.valueBtfStruct

	disableBPFIterators := false
	if err := specIter.LoadAndAssign(&se.objsIter, &opts); err != nil {
		disableBPFIterators = true
		log.Warnf("Socket enricher: skip loading iterators: %v", err)
	}

	if disableBPFIterators {
		socketSpec := &socketenricherSpecs{}
		if err := se.spec.Assign(socketSpec); err != nil {
			return err
		}
		if err := socketSpec.DisableBpfIterators.Set(true); err != nil {
			return err
		}
	} else {
		opts.MapReplacements = map[string]*ebpf.Map{
			SocketsMapName: se.objsIter.GadgetSockets,
		}
	}

	if err := se.spec.LoadAndAssign(&se.objs, &opts); err != nil {
		return fmt.Errorf("loading ebpf program: %w", err)
	}

	var l link.Link

	// bind
	l, err = link.Kprobe("inet_bind", se.objs.IgBindIpv4E, nil)
	if err != nil {
		return fmt.Errorf("attaching ipv4 kprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kretprobe("inet_bind", se.objs.IgBindIpv4X, nil)
	if err != nil {
		return fmt.Errorf("attaching ipv4 kretprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kprobe("inet6_bind", se.objs.IgBindIpv6E, nil)
	if err != nil {
		return fmt.Errorf("attaching ipv6 kprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kretprobe("inet6_bind", se.objs.IgBindIpv6X, nil)
	if err != nil {
		return fmt.Errorf("attaching ipv6 kretprobe: %w", err)
	}
	se.links = append(se.links, l)

	// connect
	l, err = link.Kprobe("tcp_connect", se.objs.IgTcpCoE, nil)
	if err != nil {
		return fmt.Errorf("attaching connect kprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kretprobe("tcp_connect", se.objs.IgTcpCoX, nil)
	if err != nil {
		return fmt.Errorf("attaching connect kretprobe: %w", err)
	}
	se.links = append(se.links, l)

	// udp_sendmsg
	l, err = link.Kprobe("udp_sendmsg", se.objs.IgUdpSendmsg, nil)
	if err != nil {
		return fmt.Errorf("attaching udp_sendmsg ipv4 kprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kprobe("udpv6_sendmsg", se.objs.IgUdp6Sendmsg, nil)
	if err != nil {
		return fmt.Errorf("attaching udpv6_sendmsg ipv6 kprobe: %w", err)
	}
	se.links = append(se.links, l)

	// release
	l, err = link.Kprobe("inet_release", se.objs.IgFreeIpv4E, nil)
	if err != nil {
		return fmt.Errorf("attaching ipv4 release kprobe: %w", err)
	}
	se.links = append(se.links, l)

	l, err = link.Kprobe("inet6_release", se.objs.IgFreeIpv6E, nil)
	if err != nil {
		return fmt.Errorf("attaching ipv6 release kprobe: %w", err)
	}
	se.links = append(se.links, l)

	if !disableBPFIterators {
		// get initial sockets
		socketsIter, err := link.AttachIter(link.IterOptions{
			Program: se.objsIter.IgSocketsIt,
		})
		if err != nil {
			return fmt.Errorf("attach BPF iterator: %w", err)
		}
		defer socketsIter.Close()

		_, err = bpfiterns.Read(socketsIter)
		if err != nil {
			return fmt.Errorf("read BPF iterator: %w", err)
		}

		// Schedule socket cleanup
		cleanupIter, err := link.AttachIter(link.IterOptions{
			Program: se.objsIter.IgSkCleanup,
			Map:     se.objsIter.GadgetSockets,
		})
		if err != nil {
			return fmt.Errorf("attach BPF iterator for cleanups: %w", err)
		}
		se.links = append(se.links, cleanupIter)

		se.done = make(chan bool)
		go se.cleanupDeletedSockets(cleanupIter)
	}

	return nil
}

func (se *SocketEnricher) cleanupDeletedSockets(cleanupIter *link.Iter) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-se.done:
			return
		case <-ticker.C:
			err := se.cleanupDeletedSocketsNow(cleanupIter)
			if err != nil {
				fmt.Printf("socket enricher: %v\n", err)
			}
		}
	}
}

func (se *SocketEnricher) cleanupDeletedSocketsNow(cleanupIter *link.Iter) error {
	// No need to change pidns for this iterator because cleanupIter is an
	// iterator on a map, not on tasks.
	_, err := bpfiterns.ReadOnCurrentPidNs(cleanupIter)
	return err
}

func (se *SocketEnricher) Close() {
	se.closeOnce.Do(func() {
		if se.done != nil {
			close(se.done)
		}
	})

	for _, l := range se.links {
		gadgets.CloseLink(l)
	}
	se.links = nil
	se.objs.Close()
	se.objsIter.Close()
}
