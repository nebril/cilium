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

package RuntimeTest

import (
	"fmt"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	"time"

	. "github.com/onsi/gomega"
)

var _ = Describe("RuntimeMysql", func() {

	var (
		vm            *helpers.SSHMeta
		mysqlIP       string
		mysqlPassword = "trololo"
		mysqlDatabase = "testdatabase"
	)

	containers := func(mode string) {

		switch mode {
		case "create":
			res := vm.ContainerCreate("mysql-server", "mysql:5.7", helpers.CiliumDockerNetwork, "-e MYSQL_ROOT_PASSWORD="+mysqlPassword+" -l mysql-server", "mysqld", "--disable-ssl")
			res.ExpectSuccess("failed to create container mysql")

			res = vm.ContainerCreate("mysql-client", "mysql:5.7", helpers.CiliumDockerNetwork, "-l mysql-client", "sleep", "10000")
			res.ExpectSuccess("failed to create container mysql-client")

			mysql, err := vm.ContainerInspectNet("mysql-server")
			Expect(err).Should(BeNil(), "Could not get memcache network")
			mysqlIP = mysql["IPv4"]

			Eventually(func() *helpers.CmdRes {
				return vm.ContainerExec("mysql-server", fmt.Sprintf(`mysql -p%s -e "create database %s;"`, mysqlPassword, mysqlDatabase))
			}, 5*time.Minute, 2*time.Second).Should(helpers.CMDSuccess(), "failed to create test database")

		case "delete":
			vm.ContainerRm("mysql-server")
			vm.ContainerRm("mysql-client")
		}
	}

	BeforeAll(func() {
		vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)

		ExpectCiliumReady(vm)

		containers("create")
		epsReady := vm.WaitEndpointsReady()
		Expect(epsReady).Should(BeTrue(), "Endpoints are not ready after timeout")
	})

	AfterEach(func() {
		vm.PolicyDelAll()
	})

	AfterAll(func() {
		containers("delete")
	})

	JustAfterEach(func() {
		vm.ValidateNoErrorsOnLogs(CurrentGinkgoTestDescription().Duration)
	})

	AfterFailed(func() {
		containers("delete")
		vm.ReportFailed("cilium policy get")
	})

	runQuery := func(query string) *helpers.CmdRes {
		return vm.ContainerExec("mysql-client",
			fmt.Sprintf(
				`mysql --ssl-mode=DISABLED -uroot -p%s -D %s -h%s -e "%s"`,
				mysqlPassword, mysqlDatabase, mysqlIP, query))
	}

	It("Tests basic mysql operation", func() {
		_, err := vm.PolicyImportAndWait(vm.GetFullPath("Policies-mysql-visibility.json"), 300)
		Expect(err).Should(BeNil(), "Failed to import policy")

		query := "CREATE TABLE t (c CHAR(20) CHARACTER SET utf8 COLLATE utf8_bin);SELECT * from t;"

		runQuery(query).ExpectSuccess("Failed to create table")
		runQuery("SELECT * FROM t;").ExpectSuccess("Failed to select from table")
		runQuery("DROP TABLE t;").ExpectSuccess("Failed to select from table")
	})
})
