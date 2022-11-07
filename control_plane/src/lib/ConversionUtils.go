/*
# Copyright 2022-present Ralf Kundel
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
*/

package lib

import (
	"encoding/hex"
	"net"
	"strings"
)

func Uint16ToByte(val uint16) []byte {
	r := make([]byte, 2)
	for i := uint32(0); i < 2; i++ {
		r[2-1-i] = byte((val >> (8 * i)) & 0xff)
	}
	return r
}

func Uint32ToByte(val uint32) []byte {
	r := make([]byte, 4)
	for i := uint32(0); i < 4; i++ {
		r[4-1-i] = byte((val >> (8 * i)) & 0xff)
	}
	return r
}

func MacStringToByte(val string) []byte {
	val = strings.ReplaceAll(val, ":", "")
	res, _ := hex.DecodeString(val)
	return res
}

func ByteToMac(val []byte) string {
	return net.HardwareAddr(val).String()
}

// fills 0 at beginning (!) of byte slice
func PaddingByteSliceSize(sl *[]byte, size int) {
	for len(*sl) < size {
		*sl = append([]byte{0}, *sl...)
	}
}
