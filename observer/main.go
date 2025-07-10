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
    "time"
)

const (
    ChannelCapacity = 100000      // 通道容量
    BatchSize       = 2000        // pipeline每批发送条数
    BatchInterval   = 5 * time.Millisecond
)

var (
    debug      bool
    cpuRate    int
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

    // gopacket
    flag.StringVar(&device, "d", "en0", "device name to capture.")
    flag.IntVar(&snapshotLen, "s", 1024, "snapshot length for gopacket")
    flag.BoolVar(&promiscuous, "pr", false, "promiscuous for gopacket")

    // MySQL
    flag.StringVar(&ignoreHostStr, "ih", "localhost", "ignore mysql hosts, specify only one ip address")
    flag.IntVar(&mPort, "mP", 3306, "mysql port")

    // Redis
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
    q = strings.ReplaceAll(q, "\"", "'",)
    q = strings.ReplaceAll(q, "\n", " ")
    return q
}

func sendQuery(packet gopacket.Packet) {
    applicationLayer := packet.ApplicationLayer()
    if applicationLayer == nil {
        return
    }
    pInfo, err := getMySQLPacketInfo(packet)
    if err != nil {
        return
    }
    if isIgnoreHosts(pInfo.srcIP, ignoreHosts) {
        return
    }

    key := name + ":" + pInfo.srcIP + ":" + strconv.Itoa(pInfo.srcPort)
    capturedTime := strconv.Itoa(int(pInfo.capturedTime.UnixNano() / 1000))
    val := ""

    if pInfo.mysqlPacket[0].GetCommandType() == mp.COM_QUERY {
        cmd := pInfo.mysqlPacket[0].(mp.ComQuery)
        q := makeOneLine(cmd.Query)
        val = "Q;" + capturedTime + ";" + q
    } else {
        return
    }
    select {
    case redisCmdChan <- [2]string{key, val}:
    default:
        fmt.Println("[Warning] Redis command channel is full, dropping query")
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

