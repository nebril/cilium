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

package mysql

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/cilium/cilium/pkg/envoy/cilium"
	"github.com/cilium/cilium/proxylib/proxylib"

	log "github.com/sirupsen/logrus"
	"github.com/xwb1989/sqlparser"
)

// Mysql Parser
//
// Spec: https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_PROTOCOL.html

type ParserFactory struct{}

var mysqlParserFactory *ParserFactory

var parserName = "mysql"

func init() {
	log.Info("init(): Registering mysqlParserFactory")
	proxylib.RegisterParserFactory(parserName, mysqlParserFactory)
	proxylib.RegisterL7RuleParser(parserName, MysqlRuleParser)
}

type MysqlRule struct{}

func (rule MysqlRule) Matches(data interface{}) bool {
	return true
}

// MysqlRuleParser parses protobuf L7 rules to enforcement objects
// May panic
func MysqlRuleParser(rule *cilium.PortNetworkPolicyRule) []proxylib.L7NetworkPolicyRule {
	l7Rules := rule.GetL7Rules()
	if l7Rules == nil {
		proxylib.ParseError("Can't get L7 rules.", rule)
	}
	var rules []proxylib.L7NetworkPolicyRule
	for _, l7Rule := range l7Rules.GetL7Rules() {
		var mr MysqlRule
		for k := range l7Rule.Rule {
			switch k {
			default:
				proxylib.ParseError(fmt.Sprintf("Unsupported key: %s", k), rule)
			}
		}

		log.Debugf("Parsed Mysql pair: %v", mr)
		rules = append(rules, &mr)
	}
	return rules
}

type mysqlState int

const (
	connectionState  mysqlState = iota
	commandState     mysqlState = iota
	replicationState mysqlState = iota
)

type Parser struct {
	connection *proxylib.Connection

	state mysqlState
}

func (pf *ParserFactory) Create(connection *proxylib.Connection) proxylib.Parser {
	log.Debugf("ParserFactory: Create: %v", connection)

	p := Parser{connection: connection, state: connectionState}
	return &p
}

const payloadLenLength = 3
const headerLength = 4
const packetTypeHeaderOffset = 0

var minNeededBytes = headerLength + packetTypeHeaderOffset

func (p *Parser) OnData(reply, endStream bool, dataBuffers [][]byte) (proxylib.OpType, int) {

	if len(dataBuffers) == 0 {
		return proxylib.NOP, 0
	}
	data := bytes.Join(dataBuffers, []byte{})
	log.Debug("Mysql OnData called with %v", data)

	if len(data) < minNeededBytes {
		return proxylib.MORE, minNeededBytes - len(data)
	}

	payloadLength := int(binary.LittleEndian.Uint32(append(data[:payloadLenLength], 0))) + headerLength

	if p.state == connectionState && reply {
		// OK packet from server changes parser state to command
		if data[headerLength] == 0 || data[headerLength] == 0xFE {
			log.Debugf("mysql parser changing connection state to command")
			p.state = commandState
		}
	}

	if p.state == connectionState || p.state == replicationState || reply {
		// don't parse responses, also let everything in connection and replication phase through
		return proxylib.PASS, payloadLength
	}

	// parse client requests from command phase

	command := data[headerLength]

	if command == 3 {
		if len(data) < payloadLength {
			return proxylib.MORE, payloadLength - len(data)
		}

		return p.parseQuery(data[5:])
	}

	return proxylib.PASS, payloadLength
}

func (p *Parser) parseQuery(data []byte) (proxylib.OpType, int) {
	reader := bytes.NewReader(data)

	tokens := sqlparser.NewTokenizer(reader)
	for {
		stmt, err := sqlparser.ParseNext(tokens)
		if err == io.EOF {
			break
		}

		if err != nil {
			log.Errorf("parser error: %v", err.Error())
		}

		var logFields map[string]string
		switch stmt := stmt.(type) {
		case *sqlparser.Select:
			sel := (*sqlparser.Select)(stmt)
			logFields = p.selectVisibility(sel)
		case *sqlparser.Delete:
			del := (*sqlparser.Delete)(stmt)
			logFields = p.deleteVisibility(del)
		case *sqlparser.Insert:
			ins := (*sqlparser.Insert)(stmt)
			logFields = p.insertVisibility(ins)
		case *sqlparser.Update:
			upd := (*sqlparser.Update)(stmt)
			logFields = p.updateVisibility(upd)
		}

		log.Debugf("%v", logFields)

		p.connection.Log(cilium.EntryType_Request,
			&cilium.LogEntry_GenericL7{
				&cilium.L7LogEntry{
					Proto:  "mysql",
					Fields: logFields,
				},
			})
	}

	return proxylib.PASS, len(data) + headerLength + 1
}

func (p *Parser) selectVisibility(sel *sqlparser.Select) map[string]string {
	logFields := map[string]string{}
	buffer := sqlparser.NewTrackedBuffer(nil)

	logFields["action"] = "select"

	logFields["cache"] = sel.Cache
	logFields["distinct"] = sel.Distinct
	logFields["hints"] = sel.Hints
	logFields["lock"] = sel.Lock
	sel.SelectExprs.Format(buffer)
	logFields["select"] = buffer.String()
	buffer.Reset()

	sel.From.Format(buffer)
	logFields["from"] = buffer.String()
	buffer.Reset()
	if sel.Where != nil {
		sel.Where.Expr.Format(buffer)
		logFields["where"] = buffer.String()
		buffer.Reset()
	}
	sel.GroupBy.Format(buffer)
	logFields["group_by"] = buffer.String()
	buffer.Reset()

	if sel.Having != nil {
		sel.Having.Expr.Format(buffer)
		logFields["having"] = buffer.String()
		buffer.Reset()
	}

	if sel.Limit != nil {
		sel.Limit.Format(buffer)
		logFields["limit"] = buffer.String()
		buffer.Reset()
	}

	sel.OrderBy.Format(buffer)
	logFields["order_by"] = buffer.String()

	return logFields
}

func (p *Parser) deleteVisibility(del *sqlparser.Delete) map[string]string {
	logFields := map[string]string{}
	buffer := sqlparser.NewTrackedBuffer(nil)

	logFields["action"] = "delete"

	del.Targets.Format(buffer)
	logFields["targets"] = buffer.String()
	buffer.Reset()

	del.TableExprs.Format(buffer)
	logFields["table_expr"] = buffer.String()
	buffer.Reset()

	del.Partitions.Format(buffer)
	logFields["columns"] = buffer.String()
	buffer.Reset()

	if del.Where != nil {
		del.Where.Expr.Format(buffer)
		logFields["where"] = buffer.String()
		buffer.Reset()
	}

	if del.Limit != nil {
		del.Limit.Format(buffer)
		logFields["limit"] = buffer.String()
		buffer.Reset()
	}

	del.OrderBy.Format(buffer)
	logFields["order_by"] = buffer.String()

	return logFields
}

func (p *Parser) insertVisibility(ins *sqlparser.Insert) map[string]string {
	logFields := map[string]string{}
	buffer := sqlparser.NewTrackedBuffer(nil)

	logFields["action"] = ins.Action
	logFields["ignore"] = ins.Ignore

	ins.Table.Format(buffer)
	logFields["table"] = buffer.String()
	buffer.Reset()

	ins.Columns.Format(buffer)
	logFields["columns"] = buffer.String()
	buffer.Reset()

	ins.OnDup.Format(buffer)
	logFields["on_duplicate"] = buffer.String()

	return logFields
}

func (p *Parser) updateVisibility(upd *sqlparser.Update) map[string]string {
	logFields := map[string]string{}
	buffer := sqlparser.NewTrackedBuffer(nil)

	logFields["action"] = "update"

	upd.TableExprs.Format(buffer)
	logFields["table"] = buffer.String()
	buffer.Reset()

	upd.Exprs.Format(buffer)
	logFields["set"] = buffer.String()
	buffer.Reset()

	if upd.Where != nil {
		upd.Where.Format(buffer)
		logFields["where"] = buffer.String()
		buffer.Reset()
	}

	if upd.Limit != nil {
		upd.Limit.Format(buffer)
		logFields["limit"] = buffer.String()
		buffer.Reset()
	}

	upd.OrderBy.Format(buffer)
	logFields["order_by"] = buffer.String()

	return logFields
}

//type mysqlProtocolCommand int

// source: https://github.com/mysql/mysql-server/blob/mysql-8.0.13/include/my_command.h#L47
// docs: https://dev.mysql.com/doc/dev/mysql-server/latest/my__command_8h.html#ae2ff1badf13d2b8099af8b47831281e1
/*
const (
	sleep               mysqlProtocolCommand = iota
	quit                mysqlProtocolCommand = iota
	init_db             mysqlProtocolCommand = iota
	query               mysqlProtocolCommand = iota
	field_list          mysqlProtocolCommand = iota
	create_db           mysqlProtocolCommand = iota
	drop_db             mysqlProtocolCommand = iota
	refresh             mysqlProtocolCommand = iota
	deprecated_1        mysqlProtocolCommand = iota
	statistics          mysqlProtocolCommand = iota
	process_info        mysqlProtocolCommand = iota
	connect             mysqlProtocolCommand = iota
	process_kill        mysqlProtocolCommand = iota
	debug               mysqlProtocolCommand = iota
	ping                mysqlProtocolCommand = iota
	time                mysqlProtocolCommand = iota
	delayed_insert      mysqlProtocolCommand = iota
	change_user         mysqlProtocolCommand = iota
	binlog_dump         mysqlProtocolCommand = iota
	table_dump          mysqlProtocolCommand = iota
	connect_out         mysqlProtocolCommand = iota
	register_slave      mysqlProtocolCommand = iota
	stmt_prepare        mysqlProtocolCommand = iota
	stmt_execute        mysqlProtocolCommand = iota
	stmt_send_long_data mysqlProtocolCommand = iota
	stmt_close          mysqlProtocolCommand = iota
	stmt_reset          mysqlProtocolCommand = iota
	set_option          mysqlProtocolCommand = iota
	stmt_fetch          mysqlProtocolCommand = iota
	daemon              mysqlProtocolCommand = iota
	binlog_dump_gtid    mysqlProtocolCommand = iota
	reset_connection    mysqlProtocolCommand = iota
	end                 mysqlProtocolCommand = iota
)
*/
