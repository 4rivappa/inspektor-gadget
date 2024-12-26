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

package inode

import (
	"fmt"
	"os"
	"path"
	"syscall"
)

// ExtractFileAndDirInodes extracts the inode values for a given file and its parent directory
func ExtractFileAndDirInodes(fileName string) (uint64, uint64, error) {
	// Extract inode info about the file
	fileInfo, err := os.Stat(fileName)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to stat file %s: %w", fileName, err)
	}

	fileSys := fileInfo.Sys()
	var inode uint64
	if stat, ok := fileSys.(*syscall.Stat_t); ok {
		inode = uint64(stat.Ino)
	} else {
		return 0, 0, fmt.Errorf("failed to assert file sys as *syscall.Stat_t")
	}

	// Extract inode info about the parent directory
	dirInfo, err := os.Stat(path.Dir(fileName))
	if err != nil {
		return 0, 0, fmt.Errorf("failed to stat directory of %s: %w", fileName, err)
	}

	dirSys := dirInfo.Sys()
	var dirInode uint64
	if dirStat, ok := dirSys.(*syscall.Stat_t); ok {
		dirInode = uint64(dirStat.Ino)
	} else {
		return 0, 0, fmt.Errorf("failed to assert directory sys as *syscall.Stat_t")
	}

	return inode, dirInode, nil
}
