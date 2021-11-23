// Copyright (c) 2016-present Cloud <cloud@txthinking.com>
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of version 3 of the GNU General Public
// License as published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package brook

import (
	"log"
	"testing"
)

func TestTest(t *testing.T) {
	log.Println(Link("brookwsserver", "ws://1.2.3.4:9999", "", "hello"))
	k, a, b, c, _ := ParseLink(Link("brookwsserver", "ws://1.2.3.4:9999", "", "hello"))
	log.Println(k, a, b, c)
}
