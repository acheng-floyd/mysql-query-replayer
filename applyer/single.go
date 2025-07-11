package main

import (
	"database/sql"
	"fmt"
	"github.com/garyburd/redigo/redis"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type singleApplyer struct {
	cpuLimit     int
	m            sync.Mutex
	q            []commandData
	hostProgress sync.Map
}

func (a *singleApplyer) prepare() error {
	cpus = runtime.NumCPU()
	a.cpuLimit = cpus * 3
	a.q = []commandData{}
	a.m = sync.Mutex{}
	return nil
}

func (a *singleApplyer) start() {
	keyMap := make(map[string]int)
	hostCnt := 0

	go a.retrieveLoop()
	go a.applyLoop()

	for {
		keys, err := checkKeys(name)
		if err != nil {
			fmt.Printf("%v\n", err)
		}
		for _, k := range keys {
			if _, ok := keyMap[k]; !ok {
				keyMap[k] = 0
				ips := strings.Split(k, ":")
				if isIgnoreHosts(ips[1], ignoreHosts) {
					fmt.Println(ips[1] + " is specified as ignoring host")
					continue
				}
				if ignoreConnectionLimit || hostCnt <= a.cpuLimit {
					a.hostProgress.Store(k, "0")
					hostCnt += 1
				} else {
					fmt.Println("Too many hosts, ignore " + k)
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (a *singleApplyer) retrieveLoop() {
	pMap := map[string]string{}

	for {
		a.hostProgress.Range(func(k, v interface{}) bool {
			pMap[k.(string)] = v.(string)
			return true
		})
		for k := range pMap {
			for { // wait until queue(a.q) length is less than 10000
				a.m.Lock()
				ll := len(a.q)
				a.m.Unlock()
				if ll > 10000 {
					time.Sleep(50 * time.Millisecond)
					continue
				}
				break
			}

			r := rpool.Get()
			queries, err := redis.Strings(r.Do("LRANGE", k, 0, 199))
			r.Close()
			if err != nil {
				fmt.Println(err)
			}
			l := len(queries)
			if l < 1 {
				// 如果 key 已经空了，从 hostProgress 删除，不再消费
				a.hostProgress.Delete(k)
				continue
			}
			r = rpool.Get()
			_, err = r.Do("LTRIM", k, l, -1)
			if err != nil {
				fmt.Println(err)
			}
			r.Close()

			tmp := []commandData{}
			for i := 0; i < l; i++ {
				val := queries[i]
				// 支持新格式：Q;时间戳;db;sql
				parts := strings.SplitN(val, ";", 4)
				if len(parts) < 4 {
					continue // 跳过老格式
				}
				capturedTime, err := strconv.Atoi(parts[1])
				if err != nil {
					fmt.Println(err)
					continue
				}
				st := commandData{
					ctype:        parts[0],
					capturedTime: capturedTime,
					query:        val, // 直接全量保存，worker里解析
				}
				tmp = append(tmp, st)
			}
			a.m.Lock()
			a.q = append(a.q, tmp...)
			a.m.Unlock()
		}
	}
}

func (a *singleApplyer) applyLoop() {
	mysqlHost := mUser + ":" + mPassword + "@tcp(" + mHost + ":" + strconv.Itoa(mPort) + ")/" + mdb + "?loc=Local&parseTime=true"
	if mSocket != "" {
		mysqlHost = mUser + ":" + mPassword + "@unix(" + mSocket + ")/" + mdb + "?loc=Local&parseTime=true"
	}

	db, err := sql.Open("mysql", mysqlHost)
	if err != nil {
		fmt.Println("Connection to MySQL fail.", err)
		return
	}
	defer db.Close()

	var (
		concurrency = 64 // 可调整
		workerChan  = make(chan commandData, 1000)
		wg          sync.WaitGroup
	)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			var lastDB string
			for cmd := range workerChan {
				if cmd.ctype == "Q" {
					parts := strings.SplitN(cmd.query, ";", 4)
					if len(parts) < 4 {
						continue // 跳过不带db的老格式
					}
					dbName := parts[2]
					sqlStr := parts[3]
					if dbName != "" && dbName != lastDB {
						_, err := db.Exec("USE " + dbName)
						if err != nil {
							fmt.Printf("[Worker %d][ERROR] change db to %s failed: %v\n", workerID, dbName, err)
							continue
						}
						lastDB = dbName
					}
					if _, err := db.Exec(sqlStr); err != nil {
						fmt.Printf("[Worker %d][ERROR] mysql exec failed: %v\nSQL: %s\n", workerID, err, sqlStr)
					}
				}
			}
		}(i)
	}

	for {
		a.m.Lock()
		ll := len(a.q)
		if ll == 0 {
			a.m.Unlock()
			time.Sleep(10 * time.Millisecond)
			continue
		}
		queries := make([]commandData, ll)
		copy(queries, a.q)
		a.q = []commandData{}
		a.m.Unlock()
		for _, q := range queries {
			workerChan <- q
		}
	}

	// 下面这两行理论上执行不到，但保留更规范
	// close(workerChan)
	// wg.Wait()
}

