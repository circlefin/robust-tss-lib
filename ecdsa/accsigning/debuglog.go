// Copyright (c) 2023, Circle Internet Financial, LTD. All rights reserved.
//
//  SPDX-License-Identifier: Apache-2.0
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

package accsigning

import (
	"fmt"
	"os"
)

const logfile = "accountablelog.txt"

func Logf(format string, a ...any) (n int, err error) {
	msg := fmt.Sprintf(format, a...)
	msg = fmt.Sprintf("%s\n", msg)
	f, err := os.OpenFile(logfile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		n = 0
		return
	}
	defer f.Close()
	n, err = f.WriteString(msg)
	return
}
