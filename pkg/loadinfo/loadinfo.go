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

package loadinfo

import (
	"time"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/shirou/gopsutil/load"
	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/process"
	"github.com/sirupsen/logrus"
)

const (
	// backgroundInterval is the interval in which system load information is logged
	backgroundInterval = 5 * time.Second

	// cpuWatermark is the minimum percentage of CPU to have a process
	// listed in the log
	cpuWatermark = 1.0
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "loadinfo")

// LogFunc is the function to used to log the system load
type LogFunc func(format string, args ...interface{})

// CloseChan is the channel to close to stop periodic system load logging
type CloseChan chan struct{}

func toMB(total uint64) uint64 {
	return total / 1024 / 1024
}

// LogCurrentSystemLoad logs the current system load and lists all processes
// consuming more than cpuWatermark of the CPU
func LogCurrentSystemLoad(logFunc LogFunc) {
	loadInfo, err := load.Avg()
	if err == nil {
		logFunc("Load 1-min: %.2f 5-min: %.2f 15min: %.2f",
			loadInfo.Load1, loadInfo.Load5, loadInfo.Load15)
	}

	memInfo, err := mem.VirtualMemory()
	if err == nil {
		logFunc("Memory: Total: %d Used: %d (%.2f%%) Free: %d Buffers: %d Cached: %d",
			toMB(memInfo.Total), toMB(memInfo.Used), memInfo.UsedPercent, toMB(memInfo.Free), toMB(memInfo.Buffers), toMB(memInfo.Cached))
	}

	swapInfo, err := mem.SwapMemory()
	if err == nil {
		logFunc("Swap: Total: %d Used: %d (%.2f%%) Free: %d",
			toMB(swapInfo.Total), toMB(swapInfo.Used), swapInfo.UsedPercent, toMB(swapInfo.Free))
	}

	procs, err := process.Processes()
	if err == nil {
		for _, p := range procs {
			cpuPercent, _ := p.CPUPercent()
			if cpuPercent > cpuWatermark {
				name, _ := p.Name()
				status, _ := p.Status()
				memPercent, _ := p.MemoryPercent()
				memInfo, _ := p.MemoryInfo()

				logFunc("NAME %s STATUS %s PID %d CPU: %.2f%% MEM: %.2f%% RSS: %d VMS: %d Data: %d Stack: %d Locked: %d Swap: %d",
					name, status, p.Pid, cpuPercent, memPercent,
					toMB(memInfo.RSS), toMB(memInfo.VMS), toMB(memInfo.Data),
					toMB(memInfo.Stack), toMB(memInfo.Locked), toMB(memInfo.Swap))
			}
		}
	}
}

// LogPeriodicSystemLoad logs the system load in the interval specified until
// the channel is closed
func LogPeriodicSystemLoad(logFunc LogFunc, interval time.Duration) CloseChan {
	closeChan := make(CloseChan)
	go func() {
		for {
			LogCurrentSystemLoad(logFunc)

			select {
			case <-closeChan:
				return
			default:
			}

			time.Sleep(interval)
		}
	}()

	return closeChan
}

// StartBackgroundLogger starts background logging
func StartBackgroundLogger() {
	LogPeriodicSystemLoad(log.WithFields(logrus.Fields{"type": "background"}).Debugf, backgroundInterval)
}
