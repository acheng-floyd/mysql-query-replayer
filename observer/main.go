package main

import (
    "errors"
    "flag"
    "fmt"
    "github.com/garyburd/redigo/redis"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    mp "github.com/tom--bo/mysql-packet-deserializer"
    "log"
    "runtime"
    "strconv"
    "strings"
    "sync"
    "time"
)

const (
    ChannelCapacity = 100000
    BatchSize       = 2000
    BatchInterval   = 5 * time.Millisecond
)

var (
    debug      bool
    name       string
    device      string
    snapshotLen int
    promiscuous bool
    handle      *pcap.Handle
    packetCount int

    ignoreHostStr string
    ignoreHosts   []string
    mPort         int

    rHost     string
    rPort     int
    rPassword string
    pcapfile  string

    rpool   *redis.Pool
    redisCmdChan = make(chan [2]string, ChannelCapacity)

    connDBMap     = make(map[string]string) // 连接对应的数据库名
    connDBMapLock sync.Mutex
)

type MySQLPacketInfo struct {
    srcIP        string
    srcPort      int
    dstIP        string
    dstPort      int
    mysqlPacket  []mp.IMySQLPacket
    capturedTime time.Time
}

func parseOptions() {
    flag.BoolVar(&debug, "debug", false, "debug")
    flag.StringVar(&pcapfile, "f", "", "pcap file. this option invalid packet capture from devices.")
    flag.IntVar(&packetCount, "c", -1, "Limit processing packets count (only enable when -debug is also specified)")
    flag.StringVar(&name, "name", "", "process name which is used as prefix of redis key")
    flag.StringVar(&device, "d", "en0", "device name to capture.")
    flag.IntVar(&snapshotLen, "s", 1024, "snapshot length for gopacket")
    flag.BoolVar(&promiscuous, "pr", false, "promiscuous for gopacket")
    flag.StringVar(&ignoreHostStr, "ih", "localhost", "ignore mysql hosts, specify only one ip address")
    flag.IntVar(&mPort, "mP", 3306, "mysql port")
    flag.StringVar(&rHost, "rh", "localhost", "redis host")
    flag.IntVar(&rPort, "rP", 6379, "redis port")
    flag.StringVar(&rPassword, "rp", "", "redis password")
    flag.Parse()
}

func newPool(addr string, cpus int) *redis.Pool {
    if rPassword != "" {
        return &redis.Pool{
            MaxIdle:     cpus,
            IdleTimeout: 10 * time.Second,
            Dial:        func() (redis.Conn, error) { return redis.Dial("tcp", addr, redis.DialPassword(rPassword)) },
        }
    }
    return &redis.Pool{
        MaxIdle:     cpus,
        IdleTimeout: 10 * time.Second,
        Dial:        func() (redis.Conn, error) { return redis.Dial("tcp", addr) },
    }
}

func getMySQLPacketInfo(packet gopacket.Packet) (MySQLPacketInfo, error) {
    applicationLayer := packet.ApplicationLayer()
    if applicationLayer == nil {
        return MySQLPacketInfo{}, errors.New("invalid packets")
    }
    frame := packet.Metadata()
    ipLayer := packet.Layer(layers.LayerTypeIPv4)
    tcpLayer := packet.Layer(layers.LayerTypeTCP)
    if ipLayer == nil || tcpLayer == nil {
        return MySQLPacketInfo{}, errors.New("Invalid_Packet")
    }
    ip, _ := ipLayer.(*layers.IPv4)
    tcp, _ := tcpLayer.(*layers.TCP)
    mcmd := mp.DeserializePacket(applicationLayer.Payload())
    if len(mcmd) == 0 {
        return MySQLPacketInfo{}, errors.New("Not_MySQL_Packet")
    }
    return MySQLPacketInfo{ip.SrcIP.String(), int(tcp.SrcPort), ip.DstIP.String(), int(tcp.DstPort), mcmd, frame.CaptureInfo.Timestamp}, nil
}

func isIgnoreHosts(ip string, ignoreHosts []string) bool {
    for _, h := range ignoreHosts {
        if ip == h {
            return true
        }
    }
    return false
}

func makeOneLine(q string) string {
    q = strings.ReplaceAll(q, "\"", "'")
    q = strings.ReplaceAll(q, "\n", " ")
    return q
}

func isSelectQuery(q string) bool {
    q = strings.TrimSpace(q)
    return strings.HasPrefix(strings.ToLower(q), "select")
}

// 解析mysql handshake response包中 dbname（标准mysql协议）
func parseHandshakeDB(payload []byte) (string, bool) {
    // MySQL handshake response packet格式，db在末尾，0x00结尾，前面auth-data和用户名也都是0x00分隔
    // 具体格式详见：https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeResponse
    if len(payload) < 36+4 { // 至少要有基本长度
        return "", false
    }
    // 协议特征字节（mysql官方说明4.1+协议），client capability flag
    capability := int(payload[0]) | int(payload[1])<<8 | int(payload[2])<<16 | int(payload[3])<<24
    hasDB := capability&0x08 > 0 // CLIENT_CONNECT_WITH_DB flag
    if !hasDB {
        return "", false
    }
    // username部分
    pos := 36 // 跳过header
    for pos < len(payload) && payload[pos] != 0x00 {
        pos++
    }
    pos++ // skip username \0
    // password部分
    if pos >= len(payload) {
        return "", false
    }
    authlen := int(payload[pos])
    pos++
    pos += authlen // skip auth-data
    if pos >= len(payload) {
        return "", false
    }
    // dbname是下一个null结尾字符串
    dbStart := pos
    for pos < len(payload) && payload[pos] != 0x00 {
        pos++
    }
    if pos > dbStart {
        db := string(payload[dbStart:pos])
        return db, true
    }
    return "", false
}

func sendQuery(packet gopacket.Packet) {
    applicationLayer := packet.ApplicationLayer()
    if applicationLayer == nil {
        return
    }

    // handshake response包判定（MySQL客户端首次连接后发送的包）
    payload := applicationLayer.Payload()
    if len(payload) > 40 && (payload[4] == 0x01 || payload[4] == 0x10 || payload[4] == 0x09 || payload[4] == 0x13) {
        db, ok := parseHandshakeDB(payload[4:])
        if ok && db != "" {
            net := packet.NetworkLayer()
            trans := packet.TransportLayer()
            srcIP, srcPort := "", 0
            if net != nil && trans != nil {
                srcIP = net.NetworkFlow().Src().String()
                srcPortStr := trans.TransportFlow().Src().String()
                srcPort, _ = strconv.Atoi(srcPortStr)
            }
            key := name + ":" + srcIP + ":" + strconv.Itoa(srcPort)
            connDBMapLock.Lock()
            connDBMap[key] = db
            connDBMapLock.Unlock()
            fmt.Printf("[HandshakeDB] %s:%d  Database: %s\n", srcIP, srcPort, db)
        }
        return
    }

    // 其余包，尝试按sql解包
    pInfo, err := getMySQLPacketInfo(packet)
    if err != nil {
        return
    }
    if isIgnoreHosts(pInfo.srcIP, ignoreHosts) {
        return
    }

    key := name + ":" + pInfo.srcIP + ":" + strconv.Itoa(pInfo.srcPort)
    capturedTime := strconv.Itoa(int(pInfo.capturedTime.UnixNano() / 1000))

    if pInfo.mysqlPacket[0].GetCommandType() == mp.COM_QUERY {
        cmd := pInfo.mysqlPacket[0].(mp.ComQuery)
        q := makeOneLine(cmd.Query)
        lowerQ := strings.ToLower(strings.TrimSpace(q))
        if strings.HasPrefix(lowerQ, "use ") && len(lowerQ) > 4 {
            db := strings.Fields(q)[1]
            connDBMapLock.Lock()
            connDBMap[key] = db
            connDBMapLock.Unlock()
            fmt.Printf("[USE DB] %s update db: %s\n", key, db)
            return
        }
        if !isSelectQuery(q) {
            return
        }
        connDBMapLock.Lock()
        db := connDBMap[key]
        connDBMapLock.Unlock()

        if db == "" {
            fmt.Printf("[Warning] No DB found for conn: %s, SQL: %s\n", key, q)
        }

        val := "Q;" + capturedTime + ";" + db + ";" + q
        select {
        case redisCmdChan <- [2]string{key, val}:
        default:
            fmt.Println("[Warning] Redis channel full, dropping query")
        }
    }
}

func redisBatchWorker() {
    conn := rpool.Get()
    defer conn.Close()
    cmds := make([][2]string, 0, BatchSize)
    ticker := time.NewTicker(BatchInterval)
    defer ticker.Stop()
    for {
        select {
        case cmd := <-redisCmdChan:
            cmds = append(cmds, cmd)
            if len(cmds) >= BatchSize {
                sendBatch(conn, cmds)
                cmds = cmds[:0]
            }
        case <-ticker.C:
            if len(cmds) > 0 {
                sendBatch(conn, cmds)
                cmds = cmds[:0]
            }
        }
    }
}

func sendBatch(conn redis.Conn, cmds [][2]string) {
    for _, cmd := range cmds {
        conn.Send("RPUSH", cmd[0], cmd[1])
    }
    conn.Flush()
    for range cmds {
        conn.Receive()
    }
}

func main() {
    parseOptions()
    ignoreHosts = strings.Split(ignoreHostStr, ",")
    cpus := runtime.NumCPU() * 2
    redisHost := rHost + ":" + strconv.Itoa(rPort)
    rpool = newPool(redisHost, cpus)
    go redisBatchWorker()

    var err error
    if pcapfile != "" {
        handle, err = pcap.OpenOffline(pcapfile)
    } else {
        ihandler, _ := pcap.NewInactiveHandle(device)
        ihandler.SetBufferSize(2147483648)
        ihandler.SetSnapLen(snapshotLen)
        ihandler.SetTimeout(pcap.BlockForever)
        ihandler.SetPromisc(promiscuous)
        handle, err = ihandler.Activate()
    }
    if err != nil {
        log.Fatal(err)
    }
    defer handle.Close()

    filter := "tcp and tcp[13] & 8 != 0"
    if mPort != 0 {
        filter += " and port " + strconv.Itoa(mPort)
    }
    err = handle.SetBPFFilter(filter)
    if err != nil {
        log.Fatal(err)
    }

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    semaphore := make(chan bool, runtime.NumCPU()*2)
    cnt := 0
    for {
        packet, err := packetSource.NextPacket()
        if err != nil {
            break
        }
        semaphore <- true
        go func() {
            defer func() { <-semaphore }()
            sendQuery(packet)
        }()
        if packetCount != -1 {
            if cnt > packetCount {
                break
            }
            cnt++
        }
    }
}

