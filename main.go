package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/kataras/iris"
	"github.com/spf13/viper"

	a "github.com/averrin/shodan/modules/auth"
	ds "github.com/averrin/shodan/modules/datastream"
	stor "github.com/averrin/shodan/modules/storage"
	r "gopkg.in/dancannon/gorethink.v2"
)

// VERSION is version number
var VERSION string

type Sockets []iris.WebsocketConnection

var sockets Sockets

var datastream *ds.DataStream
var auth *a.Auth
var storage *stor.Storage
var lock *sync.Mutex

func (s Sockets) In(c iris.WebsocketConnection) bool {
	for _, conn := range s {
		if c.ID() == conn.ID() {
			return true
		}
	}
	return false
}

func main() {
	lock = &sync.Mutex{}
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
	auth = a.Connect(datastream)
	storage = stor.Connect(viper.GetStringMapString("storage"))

	datastream.Heartbeat("shodan-web")
	storage.ReportEvent("startWeb", "")

	iris.Config.Websocket.Endpoint = "/ws"
	iris.Websocket.OnConnection(func(c iris.WebsocketConnection) {
		c.OnMessage(func(m []byte) {
			message := stor.Event{}
			json.Unmarshal(m, &message)
			if message.Event == "auth" {
				status := "error"
				if auth.Check(message.Note) {
					sockets = append(sockets, c)
					status = "success"
				}
				e := stor.Event{
					Event:     "auth",
					Timestamp: time.Now(),
					Note:      status,
				}
				event, _ := json.Marshal(e)
				c.EmitMessage([]byte(string(event) + "\n"))

			}
			if message.Event == "eventsHistory" && sockets.In(c) {
				history := []stor.Event{}
				db := (*storage)["database"]
				storage.Exec(
					r.DB(db).Table("events").OrderBy(r.Desc("Timestamp")).Limit(10).OrderBy(r.Asc("Timestamp")),
					&history,
				)
				for _, e := range history {
					event, _ := json.Marshal(e)
					c.EmitMessage([]byte(string(event) + "\n"))
					time.Sleep(100 * time.Millisecond)
				}
			}
			if message.Event == "accountHistory" && sockets.In(c) {
				history := []stor.Event{}
				db := (*storage)["database"]
				storage.Exec(
					r.DB(db).Table("events").Filter(map[string]string{"Event": "amount"}).OrderBy(r.Asc("Timestamp")),
					&history,
				)
				e := stor.Event{
					Event:     "accountHistory",
					Timestamp: time.Now(),
					Note:      "",
					Payload:   history,
				}
				event, _ := json.Marshal(e)
				c.EmitMessage([]byte(string(event) + "\n"))
			}
			if message.Event == "listNotes" && sockets.In(c) {
				e := GetNotes()
				event, _ := json.Marshal(e)
				c.EmitMessage([]byte(string(event) + "\n"))
			}
		})
		c.OnDisconnect(func() {
			for i, s := range sockets {
				if s.ID() == c.ID() {
					sockets = append(sockets[:i], sockets[i+1:]...)
				}
			}
		})
	})

	go ReportEvents()
	go ReportNotes()
	shodanStatus := datastream.GetHeartbeat("shodan")
	go ReportHeartbeat("shodan", shodanStatus)
	gideonStatus := datastream.GetHeartbeat("gideon")
	go ReportHeartbeat("gideon", gideonStatus)

	go ReportStatus()

	iris.Listen(fmt.Sprintf("0.0.0.0:%d", *port))
	// iris.ListenTo(config.Server{
	// 	ListeningAddr: fmt.Sprintf("0.0.0.0:%d", *port),
	// 	AutoTLS:       true,
	// })
}

func GetNotes() stor.Event {
	notes := []stor.Note{}
	db := (*storage)["database"]
	storage.Exec(
		r.DB(db).Table("notes"),
		&notes,
	)
	e := stor.Event{
		Event:     "listNotes",
		Timestamp: time.Now(),
		Note:      "",
		Payload:   notes,
	}
	return e
}

func ReportNotes() {
	events := storage.GetNotesStream()
	for {
		select {
		case <-events:
			e := GetNotes()
			event, _ := json.Marshal(e)
			lock.Lock()
			for _, c := range sockets {
				c.EmitMessage([]byte(string(event) + "\n"))
			}
			lock.Unlock()
			time.Sleep(500 * time.Millisecond)
		}
	}
}

func ReportEvents() {
	events := storage.GetEventsStream()
	for {
		select {
		case e := <-events:
			log.Println(e)
			event, _ := json.Marshal(e)
			lock.Lock()
			for _, c := range sockets {
				c.EmitMessage([]byte(string(event) + "\n"))
			}
			lock.Unlock()
			time.Sleep(500 * time.Millisecond)
		}
	}
}

func ReportStatus() {
	for {
		p := datastream.GetWhereIAm()
		v := ds.Value{}
		datastream.Get("amount", &v)
		b := ds.Value{}
		datastream.Get("battery", &b)
		wio := ds.Value{}
		datastream.Get("weatherisok", &wio)
		w := ds.Value{}
		datastream.Get("weather", &w)
		a := ds.Value{}
		datastream.Get("attendance", &a)
		s := struct {
			Place       ds.Point
			Amount      ds.Value
			Battery     ds.Value
			WeatherIsOk ds.Value
			Weather     ds.Value
			Attendance  ds.Value
		}{
			p, v, b, wio, w, a,
		}
		e := stor.Event{
			Event:     "status",
			Timestamp: time.Now(),
			Payload:   s,
		}
		event, _ := json.Marshal(e)
		lock.Lock()
		for _, c := range sockets {
			c.EmitMessage([]byte(string(event) + "\n"))
		}
		lock.Unlock()
		time.Sleep(5 * time.Second)
	}
}
func ReportHeartbeat(name string, status chan bool) {
	for {
		select {
		case ping := <-status:
			e := stor.Event{
				Event:     name + "Online",
				Timestamp: time.Now(),
				Note:      fmt.Sprintf("%v", ping),
			}
			event, _ := json.Marshal(e)
			lock.Lock()
			for _, c := range sockets {
				c.EmitMessage([]byte(string(event) + "\n"))
			}
			lock.Unlock()
		}
	}
}
