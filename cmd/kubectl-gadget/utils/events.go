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

package utils

import (
	"fmt"
	"os"

	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

func ManageSpecialEvent(e eventtypes.Event, verbose bool) {
	switch e.Type {
	case eventtypes.READY:
		// TODO
		return
	case eventtypes.DEBUG:
		if !verbose {
			return
		}
		fallthrough
	case eventtypes.ERR:
		fallthrough
	case eventtypes.WARN:
		fallthrough
	case eventtypes.INFO:
		podMsgSuffix := ""
		if e.Namespace != "" && e.Pod != "" {
			podMsgSuffix = ", pod " + e.Namespace + "/" + e.Pod
		}

		fmt.Fprintf(os.Stderr, "%s: node %s%s: %s\n", e.Type, e.Node, podMsgSuffix, e.Message)
	}
}