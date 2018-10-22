// Copyright 2018 Authors of Cilium
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

package main

import (
	"fmt"
	"testing"

	_ "github.com/cilium/cilium/proxylib/mysql"
	"github.com/cilium/cilium/proxylib/proxylib"
	"github.com/cilium/cilium/proxylib/test"

	_ "gopkg.in/check.v1"
)

func TestMysql(t *testing.T) {
	for _, tc := range mysqlTestCases {
		t.Run(tc.name, func(t *testing.T) {

			logServer := test.StartAccessLogServer("access_log.sock", 10)
			defer logServer.Close()

			mod := OpenModule([][2]string{{"access-log-path", logServer.Path}}, true)
			if mod == 0 {
				t.Errorf("OpenModule() with access log path %s failed", logServer.Path)
			} else {
				defer CloseModule(mod)
			}

			insertPolicyText(t, mod, "1", []string{fmt.Sprintf(`
		name: "bm1"
		policy: 2
		ingress_per_port_policies: <
		  port: 80
		  rules: <
		    remote_policies: 1
		    remote_policies: 3
		    remote_policies: 4
            l7_proto: "mysql"
		    l7_rules: <
		      l7_rules: <
%s
		      >
		    >
		  >
		>
		`, tc.policy)})

			buf := CheckOnNewConnection(t, mod, "mysql", 1, true, 1, 2, "1.1.1.1:34567", "2.2.2.2:80", "bm1",
				30, proxylib.OK, 1)

			tc.onDataChecks(t)

			CheckClose(t, 1, buf, 1)
		})
	}
}

var greeting = []byte{
	0x34, 0x00, 0x00, 0x00, 0x0a, 0x35, 0x2e, 0x30,
	0x2e, 0x35, 0x34, 0x00, 0x5e, 0x00, 0x00, 0x00,
	0x3e, 0x7e, 0x24, 0x34, 0x75, 0x74, 0x68, 0x2c,
	0x00, 0x2c, 0xa2, 0x21, 0x02, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x3e, 0x36, 0x31, 0x32, 0x49,
	0x57, 0x5a, 0x3e, 0x66, 0x68, 0x57, 0x58, 0x00,
}

var login = []byte{
	0x3e, 0x00, 0x00, 0x01, 0x85, 0xa6, 0x03, 0x00,
	0x00, 0x00, 0x00, 0x01, 0x21, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x74, 0x66, 0x6f, 0x65,
	0x72, 0x73, 0x74, 0x65, 0x00, 0x14, 0xee, 0xfd,
	0x6d, 0x55, 0x62, 0x85, 0x1b, 0xc5, 0x96, 0x6a,
	0x0b, 0x41, 0x23, 0x6a, 0xe3, 0xf2, 0x31, 0x5e,
	0xfc, 0xc4,
}

var ok = []byte{
	0x07, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02,
	0x00, 0x00, 0x00,
}

var sel = []byte{
	0x21, 0x00, 0x00, 0x00, 0x03, 0x73, 0x65, 0x6c,
	0x65, 0x63, 0x74, 0x20, 0x40, 0x40, 0x76, 0x65,
	0x72, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x63, 0x6f,
	0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x6c, 0x69,
	0x6d, 0x69, 0x74, 0x20, 0x31,
}

var del = []byte{
	0x27, 0x00, 0x00, 0x00, 0x03, 0x64, 0x65, 0x6c,
	0x65, 0x74, 0x65, 0x20, 0x66, 0x72, 0x6f, 0x6d,
	0x20, 0x66, 0x6f, 0x6f, 0x20, 0x77, 0x68, 0x65,
	0x72, 0x65, 0x20, 0x6e, 0x61, 0x6d, 0x65, 0x20,
	0x6c, 0x69, 0x6b, 0x65, 0x20, 0x27, 0x25, 0x6f,
	0x6f, 0x25, 0x27,
}

var ins = []byte{
	0x3a, 0x00, 0x00, 0x00, 0x03, 0x69, 0x6e, 0x73,
	0x65, 0x72, 0x74, 0x20, 0x69, 0x6e, 0x74, 0x6f,
	0x20, 0x66, 0x6f, 0x6f, 0x20, 0x28, 0x61, 0x6e,
	0x69, 0x6d, 0x61, 0x6c, 0x2c, 0x20, 0x6e, 0x61,
	0x6d, 0x65, 0x29, 0x20, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x73, 0x20, 0x28, 0x22, 0x63, 0x61, 0x74,
	0x22, 0x2c, 0x20, 0x22, 0x47, 0x61, 0x72, 0x66,
	0x69, 0x65, 0x6c, 0x64, 0x22, 0x29,
}

var upd = []byte{
	0x7b, 0x00, 0x00, 0x00, 0x03, 0x55, 0x50, 0x44,
	0x41, 0x54, 0x45, 0x20, 0x60, 0x6d, 0x65, 0x6d,
	0x62, 0x65, 0x72, 0x73, 0x60, 0x20, 0x53, 0x45,
	0x54, 0x20, 0x60, 0x66, 0x75, 0x6c, 0x6c, 0x5f,
	0x6e, 0x61, 0x6d, 0x65, 0x73, 0x60, 0x20, 0x3d,
	0x20, 0x27, 0x4a, 0x61, 0x6e, 0x65, 0x74, 0x20,
	0x53, 0x6d, 0x69, 0x74, 0x68, 0x20, 0x4a, 0x6f,
	0x6e, 0x65, 0x73, 0x27, 0x2c, 0x20, 0x60, 0x70,
	0x68, 0x79, 0x73, 0x69, 0x63, 0x61, 0x6c, 0x5f,
	0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x60,
	0x20, 0x3d, 0x20, 0x27, 0x4d, 0x65, 0x6c, 0x72,
	0x6f, 0x73, 0x65, 0x20, 0x31, 0x32, 0x33, 0x27,
	0x20, 0x57, 0x48, 0x45, 0x52, 0x45, 0x20, 0x60,
	0x6d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x73, 0x68,
	0x69, 0x70, 0x5f, 0x6e, 0x75, 0x6d, 0x62, 0x65,
	0x72, 0x60, 0x20, 0x3d, 0x20, 0x32, 0x3b,
}

var mysqlTestCases = []testCase{
	{
		"mysql normal flow",
		"",
		func(t *testing.T) {
			CheckOnData(t, 1, true, false, &[][]byte{greeting}, []ExpFilterOp{
				{proxylib.PASS, len(greeting)},
			}, proxylib.OK, "")

			CheckOnData(t, 1, false, false, &[][]byte{login}, []ExpFilterOp{
				{proxylib.PASS, len(login)},
			}, proxylib.OK, "")

			CheckOnData(t, 1, true, false, &[][]byte{ok}, []ExpFilterOp{
				{proxylib.PASS, len(ok)},
			}, proxylib.OK, "")

			//select
			CheckOnData(t, 1, false, false, &[][]byte{sel}, []ExpFilterOp{
				{proxylib.PASS, len(sel)},
			}, proxylib.OK, "")

			CheckOnData(t, 1, true, false, &[][]byte{ok}, []ExpFilterOp{
				{proxylib.PASS, len(ok)},
			}, proxylib.OK, "")

			//delete
			CheckOnData(t, 1, false, false, &[][]byte{del}, []ExpFilterOp{
				{proxylib.PASS, len(del)},
			}, proxylib.OK, "")

			CheckOnData(t, 1, true, false, &[][]byte{ok}, []ExpFilterOp{
				{proxylib.PASS, len(ok)},
			}, proxylib.OK, "")

			//insert
			CheckOnData(t, 1, false, false, &[][]byte{ins}, []ExpFilterOp{
				{proxylib.PASS, len(ins)},
			}, proxylib.OK, "")

			CheckOnData(t, 1, true, false, &[][]byte{ok}, []ExpFilterOp{
				{proxylib.PASS, len(ok)},
			}, proxylib.OK, "")

			//update
			CheckOnData(t, 1, false, false, &[][]byte{upd}, []ExpFilterOp{
				{proxylib.PASS, len(upd)},
			}, proxylib.OK, "")

			CheckOnData(t, 1, true, false, &[][]byte{ok}, []ExpFilterOp{
				{proxylib.PASS, len(ok)},
			}, proxylib.OK, "")
		},
	},
}
