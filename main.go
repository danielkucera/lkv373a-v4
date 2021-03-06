package main

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"time"
)

const (
	srvAddr         = "239.255.42.42:7777"
	maxDatagramSize = 1024 * 1024
)

var magic = []byte{0x74, 0x47, 0x74}

var encrypt_key = []byte{0x1f, 0xea, 0x56, 0x25, 0x13, 0x45, 0x89, 0x56, 0x33, 0xac, 0xaa, 0x34, 0x55, 0x22, 0x23, 0x45}
//var encrypt_key = []byte{0x1e, 0xea, 0x56, 0x25, 0x13, 0x45, 0x89, 0x56, 0x33, 0xac, 0xaa, 0x34, 0x55, 0x22, 0x23, 0x45}

var devices map[string]*Device

type Device struct {
	Frame          *Frame
	LastFrameTime  time.Time
	LastFragmented bool
	LastFragment   []byte `json:"-"`
	RxBytes        int
	RxBytesLast    int
	RxFrames       int
	RxFramesLast   int
	ChunksLost     int
	FPS            float32
	BPS            float32
}

type Frame struct {
	Number   int
	Complete bool
	Damaged  bool
	AData    *[]byte // `json:"-"`
	VData    *[]byte //`json:"-"`
	Next     *Frame
}

func NewFrame(frame_n int) *Frame {
	return &Frame{
		Number: frame_n,
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	dolog, _ := strconv.ParseBool(os.Getenv("GOLKV_LOG"))
	listen_string, listen_ok := os.LookupEnv("GOLKV_LISTEN")
	if !listen_ok {
		listen_string = ":8080"
	}

	if dolog {
		t := time.Now()
		logName := fmt.Sprintf("log-%d_%02d_%02d-%02d_%02d_%02d.txt",
			t.Year(), t.Month(), t.Day(),
			t.Hour(), t.Minute(), t.Second())
		logFile, err := os.OpenFile(logName, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
		if err != nil {
			panic(err)
		}

		mw := io.MultiWriter(os.Stdout, logFile)
		log.SetOutput(mw)
		gin.DefaultWriter = mw
	}

	log.Println("Program started as: ", os.Args)

	devices = make(map[string]*Device)
	go serveMulticastUDP(srvAddr, msgHandler)
	go statistics()

	router := gin.Default()

	dev := router.Group("/src/:IP", func(c *gin.Context) {
		IP := c.Param("IP")

		if IP == "default" {
			log.Println("Handling default")
			for key := range devices {
				IP = key
				log.Println("Setting to ", key)
				break
			}
		}

		if _, ok := devices[IP]; ok {
			c.Set("IP", IP)
		} else {
			c.String(404, "Device not found")
			c.Abort()
		}
	})

	{
		dev.GET("/video.mp4", func(c *gin.Context) {
			IP := c.MustGet("IP").(string)
			frame := devices[IP].Frame
			if frame == nil {
				c.String(404, "No frames received")
				c.Abort()
				return
			}

			_, rw, err := c.Writer.Hijack()

			if err != nil {
				log.Printf("unable to hijack http writer")
			}

			rw.Write([]byte("HTTP/1.1 200 OK\r\n"))
			rw.Write([]byte("Content-Type: video/mp4\r\n\r\n"))

			log.Printf("%v+", frame)

			started := false

			for true {

				if frame.Next != nil {
					if frame.VData != nil {
						if !started {
							if isSPS(*frame.VData) {
								started = true
							} else {
								frame = frame.Next
								continue
							}
						}
						rw.Write(*frame.VData)
					}
					frame = frame.Next
				} else {
					time.Sleep(time.Millisecond)
				}

			}

			return
		})

		dev.GET("/audio.mp2", func(c *gin.Context) {
			IP := c.MustGet("IP").(string)
			frame := devices[IP].Frame
			if frame == nil {
				c.String(404, "No frames received")
				c.Abort()
				return
			}

			_, rw, err := c.Writer.Hijack()

			if err != nil {
				log.Printf("unable to hijack http writer")
			}

			rw.Write([]byte("HTTP/1.1 200 OK\r\n"))
			rw.Write([]byte("Content-Type: audio/mp2\r\n\r\n"))

			log.Printf("%v+", frame)

			for true {

				if frame.Next != nil {
					if frame.AData != nil {
						rw.Write(*frame.AData)
						err = rw.Flush()
						if err != nil {
							log.Printf("unable to write stream: %s", err)
							return
						}
					}
					frame = frame.Next
				} else {
					time.Sleep(time.Millisecond)
				}

			}

			return
		})

		dev.GET("/", func(c *gin.Context) {
			c.Data(200, "text/html", []byte("<img src='frame.mjpg'>"))
		})
	}

	//TODO: proper status page
	router.GET("/status", func(c *gin.Context) {
		c.JSON(200, devices)
	})

	//TODO: redesign
	router.GET("/", func(c *gin.Context) {
		html := "<h2>Available streams</h2>\n<ul>\n"
		html += "<li><a href='src/default/'>default</a>\n"
		for key := range devices {
			html += "<li><a href='src/" + key + "'>" + key + "</a>\n"
		}
		html += "</ul>\n"
		html += "<h2>Status</h2>\n"
		status, _ := json.MarshalIndent(devices, "", "\t")
		html += "<pre>" + string(status) + "</pre>"
		c.Header("Content-Type", "text/html")
		c.String(200, html)
	})

	router.Run(listen_string)
}

func statistics() {
	for true {
		active := 0
		for IP := range devices {
			device := devices[IP]
			device.BPS = float32(device.RxBytes - device.RxBytesLast)
			device.FPS = float32(device.RxFrames - device.RxFramesLast)
			device.RxBytesLast = device.RxBytes
			device.RxFramesLast = device.RxFrames
			if device.BPS > 0 {
				log.Printf("%s: MB/s=%.2f FPS=%.2f lost=%d", IP, device.BPS/(1024*1024), device.FPS, device.ChunksLost)
				active += 1
			}
		}
		if active == 0 {
			log.Printf("No active transmitters")
		}
		time.Sleep(time.Second)
	}
}

func isSPS(data []byte) bool {
	if len(data) < 5 {
		log.Printf("payload_is_sps: not enough data")
		return false
	}

	if data[0] != 0x00 || data[1] != 0x00 || data[2] != 0x00 || data[3] != 0x01 {
		log.Printf("payload_is_sps: this is not a valid start indicator")
		return false
	}

	if (data[4] & 0x1f) == 7 {
		log.Printf("haz sps")
		return true
	}

	//log.Println(hex.Dump(data[0:5]))
	//log.Println(hex.Dump(data))
	//log.Printf("payload_is_sps: unknown")
	return false
}

func decrypt(data *[]byte, n int) {
	cipher, _ := aes.NewCipher([]byte(encrypt_key))

	encrypted := make([]byte, n)
	copy(encrypted, *data)
	size := 16

	for bs, be := 0, size; bs < n; bs, be = bs+size, be+size {
		cipher.Decrypt((*data)[bs:be], encrypted[bs:be])
	}

	return
}

func copyData(data []byte) *[]byte {
	var out []byte
	out = make([]byte, len(data))
	copy(out, data)
	return &out
}

func msgHandler(src *net.UDPAddr, n int, p []byte) {
	var b []byte

	p = p[0:n]

	IP := src.IP.String()

	if _, ok := devices[IP]; !ok {
		devices[IP] = &Device{}
	}

	device := devices[IP]

	if device.LastFragmented {
		b = append(device.LastFragment, p...)
	} else {
		b = p
	}

	data := b[12:]

	header := b[0:12]

	if bytes.Compare(header[0:3], magic) != 0 {
		log.Println("invalid magic", hex.Dump(header))
		device.LastFragmented = false
		return
	}

	t := header[3]

	data_len := int(binary.BigEndian.Uint32(header[4:8]) - 4)
	data_cnt := int(binary.BigEndian.Uint32(header[8:12]))

	if device.Frame == nil {
		device.Frame = NewFrame(data_cnt)
	}

	if device.Frame.Number != data_cnt {
		device.Frame.Next = NewFrame(data_cnt)
		device.Frame = device.Frame.Next
	}

	if len(data) < data_len {
		log.Println("fragment: advertised len:", data_len, "UDP payload len:", len(data), "timestamp ms?:", data_cnt)
		device.LastFragmented = true
		device.LastFragment = make([]byte, len(b))
		copy(device.LastFragment, b)
		return
	}

	device.LastFragmented = false

	if len(data) > data_len {
		log.Println("fragment failed: advertised len:", data_len, "UDP payload len:", len(data), "timestamp ms?:", data_cnt)
		return
	}

	device.RxBytes += len(data)

	if t == 0x80 { //video80
		crypt_len := (data_len / 16) * 16
		if crypt_len > 1024 {
			crypt_len = 1024
		}
		if crypt_len < 1024 {
			log.Println("crypt_len:", crypt_len)
		}
		decrypt(&data, crypt_len)
		if (data[4]) != 0x21 {
			//log.Println(hex.Dump(data[0:5]))
		}
		device.Frame.VData = copyData(data)
	} else if t == 0x00 { //video00
		//log.Println("video00", data_cnt)
		//log.Println(hex.Dump(data[0:5]))
		device.Frame.VData = copyData(data)
	} else if t == 0x81 { //audio
		if len(data) != 576 {
			log.Println("audio packet len != 576, len: ", len(data))
			return
		}
		decrypt(&data, 576)
		device.Frame.AData = copyData(data)
		//log.Println("audio decrypted")
	} else if t == 0x82 { //status
		//log.Println("status?")
		//log.Println(hex.Dump(data))
	} else {
		log.Println("unknown packet type")
	}

	//	log.Println(n, "bytes read from", src, curFrame.Number, chunk_n, endframe)
	//log.Println(curFrame)
	//log.Println(hex.Dump(b[0:12]))
}

func serveMulticastUDP(a string, h func(*net.UDPAddr, int, []byte)) {
	addr, err := net.ResolveUDPAddr("udp", a)
	if err != nil {
		log.Fatal(err)
	}
	l, err := net.ListenMulticastUDP("udp", nil, addr)
	l.SetReadBuffer(2 * 1024 * 1024)
	b := make([]byte, maxDatagramSize)
	for {
		n, src, err := l.ReadFromUDP(b)
		if err != nil {
			log.Fatal("ReadFromUDP failed:", err)
		}
		h(src, n, b)
	}
}
