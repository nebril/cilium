// Copyright 2016-2017 Authors of Cilium
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

package api

// PortRuleMemcache is a list of Memcache protocol constraints. All fields are
// optional, if all fields are empty or missing, the rule will match all
// Memcache messages.
// NOTE: this struct is used for both binary and text memcache protocols
type PortRuleMemcache struct {
	// OpCode is a case-insensitive string matched against the op-code of a
	// request, e.g. "get", "set", "add", et al
	// Reference: https://github.com/couchbase/memcached/blob/master/docs/BinaryProtocol.md
	//
	// If omitted or empty then all op-codes are allowed.
	//
	// +optional
	OpCode string `json:"opCode,omitempty"`

	// Key is a memcache key which the rule applies to
	// If Key is empty, the rule applies to all requests
	//
	// +optional
	Key string `json:"key,omitempty"`
}

var MemcacheOpCodeMap = map[string]byte{
	"get":                  0,
	"set":                  1,
	"add":                  2,
	"replace":              3,
	"delete":               4,
	"increment":            5,
	"decrement":            6,
	"quit":                 7,
	"flush":                8,
	"getq":                 9,
	"noop":                 10,
	"version":              11,
	"getk":                 12,
	"getkq":                13,
	"append":               14,
	"prepend":              15,
	"stat":                 16,
	"setq":                 17,
	"addq":                 18,
	"replaceq":             19,
	"deleteq":              20,
	"incrementq":           21,
	"decrementq":           22,
	"quiteq":               23,
	"flushq":               24,
	"appendq":              25,
	"prependq":             26,
	"verbosity":            27,
	"touch":                28,
	"gat":                  29,
	"gatq":                 30,
	"helo":                 31,
	"sasl-list-mechs":      32,
	"sasl-auth":            33,
	"sasl-step":            34,
	"rget":                 48,
	"rset":                 49,
	"rsetq":                50,
	"rappend":              51,
	"rappendq":             52,
	"rprepend":             53,
	"rprependq":            54,
	"rdelete":              55,
	"rdeleteq":             56,
	"rincr":                57,
	"rincrq":               58,
	"rdecr":                59,
	"rdecrq":               60,
	"set-vbucket":          61,
	"get-vbucket":          62,
	"del-vbucket":          63,
	"tap-connect":          64,
	"tap-mutation":         65,
	"tap-delete":           66,
	"tap-flush":            67,
	"tap-opaque":           68,
	"tap-vbucket-set":      69,
	"tap-checkpoint-start": 70,
	"tap-checkpoint-end":   71,
}
