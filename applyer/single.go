package main

import (
    "database/sql"
    "fmt"
    "github.com/garyburd/redigo/redis"
    _ "github.com/go-sql-driver/mysql"
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
            for {
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
                val := strings.SplitN(queries[i], ";", 3)
                capturedTime, err := strconv.Atoi(val[1])
                if err != nil {
                    fmt.Println(err)
                    continue
                }
                st := commandData{
                    ctype:        val[0],
                    capturedTime: capturedTime,
                    query:        val[2],
                }
                tmp = append(tmp, st)
            }
            a.m.Lock()
            a.q = append(a.q, tmp...)
            a.m.Unlock()
        }
    }
}

func buildMySQLDSN(db string) string {
    if mSocket != "" {
        return fmt.Sprintf("%s:%s@unix(%s)/%s?loc=Local&parseTime=true",
            mUser, mPassword, mSocket, db)
    }
    return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?loc=Local&parseTime=true",
        mUser, mPassword, mHost, mPort, db)
}

func (a *singleApplyer) applyLoop() {
    dbNames := strings.Split(mdb, ",")
    dbPools := make(map[string]*sql.DB)
    for _, dbname := range dbNames {
        dbname = strings.TrimSpace(dbname)
        if dbname == "" {
            continue
        }
        dsn := buildMySQLDSN(dbname)
        db, err := sql.Open("mysql", dsn)
        if err != nil {
            fmt.Printf("连接MySQL数据库 %s 失败: %v\n", dbname, err)
            continue
        }
        db.SetMaxOpenConns(50)
        db.SetMaxIdleConns(10)
        db.SetConnMaxLifetime(30 * time.Minute)
        if err := db.Ping(); err != nil {
            fmt.Printf("Ping MySQL数据库 %s 失败: %v\n", dbname, err)
            db.Close()
            continue
        }
        dbPools[dbname] = db
    }
    defer func() {
        for _, db := range dbPools {
            db.Close()
        }
    }()

    var (
        concurrency = 64
        workerChan  = make(chan commandData, 1000)
        wg          sync.WaitGroup
    )

    // worker 池
    for i := 0; i < concurrency; i++ {
        wg.Add(1)
        go func(workerID int) {
            defer wg.Done()
            for cmd := range workerChan {
                if cmd.ctype == "Q" {
                    for _, dbname := range dbNames {
                        dbname = strings.TrimSpace(dbname)
                        db := dbPools[dbname]
                        if db == nil {
                            fmt.Printf("[Worker %d][ERROR] db pool nil: %s\n", workerID, dbname)
                            continue
                        }
                        if _, err := db.Exec(cmd.query); err != nil {
                            fmt.Printf("[Worker %d][ERROR] mysql exec failed: %v\nDB: %s\nSQL: %s\n", workerID, err, dbname, cmd.query)
                        }
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
    // close(workerChan)
    // wg.Wait()
}

