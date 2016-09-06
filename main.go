package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/kataras/iris"
	"github.com/spf13/viper"

	ds "github.com/averrin/shodan/modules/datastream"
	stor "github.com/averrin/shodan/modules/storage"
)

// VERSION is version number
var VERSION string

var sockets []iris.WebsocketConnection

var datastream *ds.DataStream
var storage *stor.Storage

func main() {
	port := flag.Int("port", 80, "serve port")
	flag.Parse()
	viper.SetConfigType("yaml")
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}

	datastream = ds.Connect(viper.GetStringMapString("datastream"))
	storage = stor.Connect(viper.GetStringMapString("storage"))

	datastream.Heartbeat("shodan-web")
	storage.ReportEvent("startWeb", "")

	iris.Config.Websocket.Endpoint = "/ws"
	iris.Websocket.OnConnection(func(c iris.WebsocketConnection) {
		sockets = append(sockets, c)
		c.To(iris.All).Emit("out", []byte("inited\n"))
		c.On("in", func(message string) {
			c.To(iris.All).Emit("out",
				[]byte(fmt.Sprintf(">> %s\n", message)))
		})
	})

	events := storage.GetEventsStream()
	go func() {
		for {
			select {
			case e := <-events:
				log.Println(e)
				event, _ := json.Marshal(e)
				for _, c := range sockets {
					c.To(iris.All).EmitMessage(event)
				}
			}
		}
	}()
	shodanStatus := datastream.GetHeartbeat("shodan")
	go func() {
		for {
			select {
			case ping := <-shodanStatus:
				e := stor.Event{
					Event:     "shodanOnline",
					Timestamp: time.Now(),
					Note:      fmt.Sprintf("%v", ping),
				}
				event, _ := json.Marshal(e)
				for _, c := range sockets {
					c.To(iris.All).EmitMessage(event)
				}
			}
		}
	}()

	iris.Listen(fmt.Sprintf("0.0.0.0:%d", *port))
	// iris.ListenTo(config.Server{
	// 	ListeningAddr: fmt.Sprintf("0.0.0.0:%d", *port),
	// 	AutoTLS:       true,
	// })
}
