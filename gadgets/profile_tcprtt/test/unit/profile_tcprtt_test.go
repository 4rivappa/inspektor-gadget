// Copyright 2025 The Inspektor Gadget authors
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
	"io"
	"log"
	"net"
	"testing"
	"time"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"

	tcprtt_types "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/tcprtt/types"
)

type EventDetails struct {
	SourcePort uint32
	TargetPort uint32
}

type testDef struct {
	runnerConfig  *utilstest.RunnerConfig
	generateEvent func() (EventDetails, error)
	validateEvent func(t *testing.T, info *utilstest.RunnerInfo, eventDetails EventDetails, events []tcprtt_types.Report)
}

func TestProfileTCPRTTGadget(t *testing.T) {
	gadgettesting.InitUnitTest(t)
	runnerConfig := &utilstest.RunnerConfig{}

	testCases := map[string]testDef{
		"captures_tcp_rtt_histogram": {
			runnerConfig:  runnerConfig,
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, eventDetails EventDetails, events []tcprtt_types.Report) {
				fmt.Println("DEBUG: Length of events: ", len(events))

				if len(events) > 0 {
					for _, hist := range events[0].Histograms {
						fmt.Println("Address:", hist.Address)
						fmt.Println("Address Type:", hist.AddressType)
						fmt.Println("Average:", hist.Average)
						fmt.Println("Local Port:", hist.LocalPort)
						fmt.Println("Remote Port:", hist.RemotePort)
					}
				}

				// utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, pid int) *tcprtt_types.Report {
				// 	return &tcprtt_types.Report{
				// 	}
				// })(t, info, 0, events)
			},
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var eventDetails EventDetails
			runner := utilstest.NewRunnerWithTest(t, testCase.runnerConfig)

			normalizeEvent := func(event *tcprtt_types.Report) {
				fmt.Println("DEBUG: inside normalize event method")
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

			params := map[string]string{
				"targ_dport": "8080",
				"targ_ms":    "true",
			}

			opts := gadgetrunner.GadgetRunnerOpts[tcprtt_types.Report]{
				Image:          "profile_tcprtt",
				Timeout:        10 * time.Second,
				ParamValues:    params,
				OnGadgetRun:    onGadgetRun,
				NormalizeEvent: normalizeEvent,
			}

			gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)

			gadgetRunner.RunGadget()
			fmt.Printf("%+v\n", gadgetRunner)

			testCase.validateEvent(t, runner.Info, eventDetails, gadgetRunner.CapturedEvents)
		})
	}
}

func generateEvent() (EventDetails, error) {
	go startServer()
	time.Sleep(1 * time.Second)

	startTime := time.Now()
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		return EventDetails{}, fmt.Errorf("could not connect to server: %v", err)
	}
	defer conn.Close()
	message := []byte("ping")
	_, err = conn.Write(message)
	if err != nil {
		return EventDetails{}, fmt.Errorf("could not send message: %v", err)
	}
	buffer := make([]byte, len(message))
	_, err = conn.Read(buffer)
	if err != nil {
		return EventDetails{}, fmt.Errorf("could not read response: %v", err)
	}
	rtt := time.Since(startTime)

	fmt.Printf("DEBUG: TCP RTT: %v\n", rtt)

	return EventDetails{}, nil
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	buffer := make([]byte, 1024)
	_, err := conn.Read(buffer)
	if err != nil {
		if err != io.EOF {
			log.Println("Error reading:", err)
		}
		return
	}

	time.Sleep(2 * time.Second)

	_, err = conn.Write(buffer)
	if err != nil {
		log.Println("Error writing:", err)
	}
}

func startServer() {
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	fmt.Println("Server listening on port 8080...")
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handleConnection(conn)
	}
}