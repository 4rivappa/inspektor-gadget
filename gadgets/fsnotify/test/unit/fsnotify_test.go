// Copyright 2024 The Inspektor Gadget authors
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

package tests

import (
	"fmt"
	"os"
	"path"
	"syscall"
	"strings"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	// ebpftypes "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

const TASK_COMM_LEN = 16

type Process struct {
	PPid  uint32    `json:"ppid"`
	Pid   uint32    `json:"pid"`
	Tid   uint32    `json:"tid"`
	Comm  [TASK_COMM_LEN]byte `json:"comm"`
	PComm [TASK_COMM_LEN]byte `json:"pcomm"`
};

func (p *Process) Print(extraInfo string) {
	commStr := strings.TrimRight(string(p.Comm[:]), "\x00")
	pcommStr := strings.TrimRight(string(p.PComm[:]), "\x00")

	// Print all the fields in a formatted manner
	fmt.Printf("%s Process Info:\n", extraInfo)
	fmt.Printf("  PPid:  %d\n", p.PPid)
	fmt.Printf("  Pid:   %d\n", p.Pid)
	fmt.Printf("  Tid:   %d\n", p.Tid)
	fmt.Printf("  Comm:  %s\n", commStr)
	fmt.Printf("  PComm: %s\n", pcommStr)
}

type EventDetails struct {
	FileName string
	Ino      uint32
	InoDir   uint32
}

// func (r *utilstest.RunnerInfo) Print() {
// 	fmt.Printf("Test RunnerInfo *** :\n")
// 	fmt.Printf("  Pid:         %d\n", r.Pid)
// 	fmt.Printf("  Tid:         %d\n", r.Tid)
// 	fmt.Printf("  Comm:        %s\n", r.Comm)
// 	fmt.Printf("  Uid:         %d\n", r.Uid)
// 	fmt.Printf("  Gid:         %d\n", r.Gid)
// 	fmt.Printf("  MountNsID:   %d\n", r.MountNsID)
// 	fmt.Printf("  NetworkNsID: %d\n", r.NetworkNsID)
// 	fmt.Printf("  UserNsID:    %d\n", r.UserNsID)
// }

type ExpectedFsnotifyEvent struct {
	Timestamp string `json:"timestamp"`

	Type string `json:"type"`

	TraceeProc Process `json:"tracee_proc"`
	TracerProc Process `json:"tracer_proc"`

	TraceeMntnsId uint64 `json:"tracee_mntns_id"`
	TracerMntnsId uint64 `json:"tracer_mntns_id"`

	TraceeUId uint32 `json:"tracee_uid"`
	TraceeGId uint32 `json:"tracee_gid"`
	TracerUId uint32 `json:"tracer_uid"`
	TracerGId uint32 `json:"tracer_gid"`

	Prio uint32 `json:"prio"`

	FaMask uint32 `json:"fa_mask"`
	IMask  uint32 `json:"i_mask"`

	FaType     string `json:"fa_type"`
	FaPId      uint32 `json:"fa_pid"`
	FaFlags    uint32 `json:"fa_flags"`
	FaFFlags   uint32 `json:"fa_f_flags"`
	FaResponse string `json:"fa_response"`

	IWd     int32  `json:"i_wd"`
	ICookie uint32 `json:"i_cookie"`
	IIno    uint32 `json:"i_ino"`
	IInoDir uint32 `json:"i_ino_dir"`

	Name string `json:"name"`
}

func (e ExpectedFsnotifyEvent) Print() {
	fmt.Printf("Timestamp: %s\n", e.Timestamp)
	fmt.Printf("Type: %s\n", e.Type)

	e.TraceeProc.Print("Tracee")
	e.TracerProc.Print("Tracer")
	
	fmt.Printf("TraceeMntnsId: %d\n", e.TraceeMntnsId)
	fmt.Printf("TracerMntnsId: %d\n", e.TracerMntnsId)
	fmt.Printf("TraceeUId: %d\n", e.TraceeUId)
	fmt.Printf("TraceeGId: %d\n", e.TraceeGId)
	fmt.Printf("TracerUId: %d\n", e.TracerUId)
	fmt.Printf("TracerGId: %d\n", e.TracerGId)
	fmt.Printf("Prio: %d\n", e.Prio)
	fmt.Printf("FaMask: %d\n", e.FaMask)
	fmt.Printf("IMask: %d\n", e.IMask)
	fmt.Printf("FaType: %s\n", e.FaType)
	fmt.Printf("FaPId: %d\n", e.FaPId)
	fmt.Printf("FaFlags: %d\n", e.FaFlags)
	fmt.Printf("FaFFlags: %d\n", e.FaFFlags)
	fmt.Printf("FaResponse: %s\n", e.FaResponse)
	fmt.Printf("IWd: %d\n", e.IWd)
	fmt.Printf("ICookie: %d\n", e.ICookie)
	fmt.Printf("IIno: %d\n", e.IIno)
	fmt.Printf("IInoDir: %d\n", e.IInoDir)
	fmt.Printf("Name: %s\n", e.Name)
}

type testDef struct {
	runnerConfig  *utilstest.RunnerConfig
	generateEvent func() (string, error)
	validateEvent func(t *testing.T, info *utilstest.RunnerInfo, eventDetails EventDetails, events []ExpectedFsnotifyEvent)
}

func TestFsnotifyGadget(t *testing.T) {
	gadgettesting.InitUnitTest(t)
	runnerConfig := &utilstest.RunnerConfig{}

	testCases := map[string]testDef{
		"captures_inotify_event": {
			runnerConfig:  runnerConfig,
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, eventDetails EventDetails, events []ExpectedFsnotifyEvent) {

				fmt.Println("Length of events:", len(events))

				fmt.Printf("--------------------------------------------------\n")
				fmt.Printf("YOU ARE LOOKING FOR THIS SECTION\n")
				fmt.Printf("--------------------------------------------------\n")
				for _, event := range events {
					event.Print()
					fmt.Printf("--------------------------------------------------\n")
				}

				info.Print()
				fmt.Printf("runnerInfo proc command: %s\n", info.Proc.Comm)
				fmt.Printf("runnerInfo proc pid: %d\n", info.Proc.Pid)
				fmt.Printf("runnerInfo proc tid: %d\n", info.Proc.Tid)
				fmt.Printf("--------------------------------------------------\n")

				// expectedEvent := ExpectedFsnotifyEvent{
				// 	Type: "inotify",

				// 	IMask: 0x08000002, // FS_MODIFY | FS_EVENT_ON_CHILD
				// 	Name:  filename,

				// 	Timestamp: utils.NormalizedStr,

				// 	TraceeMntnsId: utils.NormalizedInt,
				// 	TracerMntnsId: utils.NormalizedInt,

				// 	FaType:     utils.NormalizedStr,
				// 	FaResponse: utils.NormalizedStr,

				// 	IWd:     utils.NormalizedInt,

				// 	IIno:    eventDetails.Ino,
				// 	IInoDir: eventDetails.InoDir,
				// }
				// fmt.Printf("EXPECTED -----------------------------------------\n")
				// expectedEvent.Print()
				// fmt.Printf("EXPECTED -----------------------------------------\n")
			
				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, pid int) *ExpectedFsnotifyEvent {
					return &ExpectedFsnotifyEvent{
						Type: "inotify",

						IMask: 0x08000002, // FS_MODIFY | FS_EVENT_ON_CHILD
						Name:  eventDetails.FileName,

						Timestamp: utils.NormalizedStr,

						TraceeMntnsId: info.MountNsID,
						TracerMntnsId: utils.NormalizedInt,

						FaType:     utils.NormalizedStr,
						FaResponse: utils.NormalizedStr,

						IWd:     utils.NormalizedInt,

						IIno:    eventDetails.Ino,
						IInoDir: eventDetails.InoDir,
					}
				})(t, info, 0, events)
			},
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var eventDetails EventDetails
			runner := utilstest.NewRunnerWithTest(t, testCase.runnerConfig)

			normalizeEvent := func(event *ExpectedFsnotifyEvent) {
				utils.NormalizeString(&event.Timestamp)

				// // utils.NormalizeProc(&event.TraceeProc)
				// // utils.NormalizeProc(&event.TracerProc)
				// utils.NormalizeInt(&event.TraceeMntnsId)

				utils.NormalizeInt(&event.TracerMntnsId)

				// utils.NormalizeInt(&event.TraceeUId)
				// utils.NormalizeInt(&event.TraceeGId)
				// utils.NormalizeInt(&event.TracerUId)
				// utils.NormalizeInt(&event.TracerGId)

				// utils.NormalizeInt(&event.Prio)
				// utils.NormalizeInt(&event.FaMask)

				utils.NormalizeString(&event.FaType)
				// utils.NormalizeInt(&event.FaPId)
				// utils.NormalizeInt(&event.FaFlags)
				// utils.NormalizeInt(&event.FaFFlags)
				utils.NormalizeString(&event.FaResponse)
			}
			onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
				utilstest.RunWithRunner(t, runner, func() error {
					var err error
					eventDetails, err = testCase.generateEvent()
					if err != nil {
						return err
					}
					return nil
				})
				return nil
			}
			opts := gadgetrunner.GadgetRunnerOpts[ExpectedFsnotifyEvent]{
				Image:          "fsnotify",
				Timeout:        10 * time.Second,
				OnGadgetRun:    onGadgetRun,
				NormalizeEvent: normalizeEvent,
			}

			gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)

			gadgetRunner.RunGadget()

			testCase.validateEvent(t, runner.Info, eventDetails, gadgetRunner.CapturedEvents)
		})
	}
}

func generateEvent() (EventDetails, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return EventDetails{}, err
	}
	defer watcher.Close()

	err = watcher.Add(os.TempDir())
	if err != nil {
		return EventDetails{}, err
	}

	// event 1
	newFile, err := os.CreateTemp(os.TempDir(), "test-*.txt")
	if err != nil {
		return EventDetails{}, err
	}
	defer newFile.Close()

	// event 2
	_, err = newFile.WriteString("Hello, fsnotify!")
	if err != nil {
		return EventDetails{}, err
	}

	inode, dirInode, err := calculateInodeValues(newFile.Name())
	if err != nil {
		return EventDetails{}, err
	}
	
	fileName := path.Base(newFile.Name())
	eventDetails := EventDetails{
		FileName: fileName,
		Ino:      uint32(inode),
		InoDir:   uint32(dirInode),
	}
	return eventDetails, nil
}

func calculateInodeValues(fileName string) (uint64, uint64, error) {
	// collect Inode information about file
	fileInfo, err := os.Stat(fileName)
	if err != nil {
		return 0, 0, err
	}
	fileSys := fileInfo.Sys()
	var inode uint64
	if stat, ok := fileSys.(*syscall.Stat_t); ok {
		inode = uint64(stat.Ino)
	}
	fmt.Printf("Inode of File: %d\n", inode)

	// collect Inode information about directory
	dirInfo, err := os.Stat(path.Dir(fileName))
	if err != nil {
		return 0, 0, err
	}
	dirSys := dirInfo.Sys()
	var dirInode uint64
	if dirStat, ok := dirSys.(*syscall.Stat_t); ok {
		dirInode = uint64(dirStat.Ino)
	}
	fmt.Printf("Inode of Directory: %d\n", dirInode)

	return inode, dirInode, nil
}
