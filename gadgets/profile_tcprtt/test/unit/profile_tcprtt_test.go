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
	"errors"
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"

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

func TestFsnotifyGadget(t *testing.T) {
	gadgettesting.InitUnitTest(t)
	runnerConfig := &utilstest.RunnerConfig{}

	testCases := map[string]testDef{
		"captures_tcp_rtt_histogram": {
			runnerConfig:  runnerConfig,
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, eventDetails EventDetails, events []tcprtt_types.Report) {
				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, pid int) *tcprtt_types.Report {
					return &tcprtt_types.Report{
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
			opts := gadgetrunner.GadgetRunnerOpts[tcprtt_types.Report]{
				Image:          "profile_tcprtt",
				Timeout:        5 * time.Second,
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
	return EventDetails{}, nil
}
