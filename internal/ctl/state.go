package ctl

import "time"

// Stats — счётчики демона.
type Stats struct {
	Packets     uint64 `json:"packets"`     // пакетов из очереди
	Answers     uint64 `json:"answers"`     // DNS-ответов с адресами
	Claimed     uint64 `json:"claimed"`     // из них подошло под правило
	Changes     uint64 `json:"changes"`     // изменений списков
	NotDNS      uint64 `json:"notDNS"`      // не UDP с порта 53
	Malformed   uint64 `json:"malformed"`   // DNS не разобрался
	Skipped     uint64 `json:"skipped"`     // запрос, ошибка, усечённый ответ, ответ без адресов
	BadName     uint64 `json:"badName"`     // запрошенное имя не похоже на доменное
	Dropped     uint64 `json:"dropped"`     // не учтено: память заполнена
	ApplyErrors uint64 `json:"applyErrors"` // сбоев обновления списков и маршрутов
}

// ExitState — через какой интерфейс сейчас идёт выход.
type ExitState struct {
	Name  string `json:"name"`
	Via   string `json:"via"`   // имя интерфейса в прошивке; пусто — живых туннелей нет
	Known bool   `json:"known"` // демон уже спрашивал прошивку
}

// Observation — DNS-ответ и решение по нему.
type Observation struct {
	At     time.Time `json:"at"`
	Client string    `json:"client"`
	Name   string    `json:"name"`
	Action string    `json:"action"`
	Line   int       `json:"line"` // 0 — сработал default
}

// State — состояние демона для веб-страницы (команда state).
type State struct {
	Mode    string        `json:"mode"` // observe или route
	Started time.Time     `json:"started"`
	Rules   int           `json:"rules"`
	Addrs   int           `json:"addrs"`  // адресов в памяти
	Claims  int           `json:"claims"` // претензий
	Stats   Stats         `json:"stats"`
	Exits   []ExitState   `json:"exits"`
	Recent  []Observation `json:"recent"` // новые первыми
}
