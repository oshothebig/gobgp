// Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"fmt"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	"github.com/stretchr/testify/assert"
	"net"
	"strconv"
	"testing"
	"time"
)

type MockConnection struct {
	net.Conn
	recvCh    chan []byte
	sendBuf   [][]byte
	readBytes int
}

func NewMockConnection() *MockConnection {
	m := &MockConnection{
		recvCh:  make(chan []byte, 128),
		sendBuf: make([][]byte, 129),
	}
	return m
}

func (m *MockConnection) Read(buf []byte) (int, error) {

	data := <-m.recvCh
	rest := len(buf) - m.readBytes
	if len(data) > rest {
		m.recvCh <- data[rest:]
		data = data[:rest]
	}

	for _, val := range data {
		buf[m.readBytes] = val
		m.readBytes += 1
	}

	length := 0
	if m.readBytes == len(buf) {
		m.readBytes = 0
		length = len(buf)
	} else {
		length = m.readBytes
	}

	fmt.Printf("%d bytes read from peer\n", length)
	return length, nil
}

func (m *MockConnection) Write(buf []byte) (int, error) {
	m.sendBuf = append(m.sendBuf, buf)
	msg, _ := bgp.ParseBGPMessage(buf)
	fmt.Printf("%d bytes written by gobgp  message type : %s\n", len(buf), showMessageType(msg.Header.Type))
	return len(buf), nil
}

func showMessageType(t uint8) string {
	switch t {
	case bgp.BGP_MSG_KEEPALIVE:
		return "BGP_MSG_KEEPALIVE"
	case bgp.BGP_MSG_NOTIFICATION:
		return "BGP_MSG_NOTIFICATION"
	case bgp.BGP_MSG_OPEN:
		return "BGP_MSG_OPEN"
	case bgp.BGP_MSG_UPDATE:
		return "BGP_MSG_UPDATE"
	case bgp.BGP_MSG_ROUTE_REFRESH:
		return "BGP_MSG_ROUTE_REFRESH"
	}
	return strconv.Itoa(int(t))
}

func (m *MockConnection) Close() error {
	fmt.Printf("close called\n")
	return nil
}

func TestReadAll(t *testing.T) {
	assert := assert.New(t)
	m := NewMockConnection()
	msg := open()
	expected1, _ := msg.Header.Serialize()
	expected2, _ := msg.Body.Serialize()

	pushBytes := func() {
		fmt.Println("push 5 bytes")
		m.recvCh <- expected1[0:5]
		fmt.Println("push rest")
		m.recvCh <- expected1[5:]
		fmt.Println("push bytes at once")
		m.recvCh <- expected2
	}

	go pushBytes()

	var actual1 []byte
	actual1, _ = readAll(m, bgp.BGP_HEADER_LENGTH)
	fmt.Println(actual1)
	assert.Equal(expected1, actual1)

	var actual2 []byte
	actual2, _ = readAll(m, len(expected2))
	fmt.Println(actual2)
	assert.Equal(expected2, actual2)
}

func TestFSMHandlerOpensent_HoldTimerExpired(t *testing.T) {
	assert := assert.New(t)
	m := NewMockConnection()

	p, h := makePeerAndHandler()

	// push mock connection
	p.fsm.passiveConn = m

	// set up keepalive ticker
	sec := time.Second * 1
	p.fsm.keepaliveTicker = time.NewTicker(sec)

	// set holdtime
	p.fsm.opensentHoldTime = 2

	state := h.opensent()

	assert.Equal(bgp.BGP_FSM_IDLE, state)
	lastMsg := m.sendBuf[len(m.sendBuf)-1]
	sent, _ := bgp.ParseBGPMessage(lastMsg)
	assert.Equal(bgp.BGP_MSG_NOTIFICATION, sent.Header.Type)
	assert.Equal(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED, sent.Body.(*bgp.BGPNotification).ErrorCode)

}

func TestFSMHandlerOpenconfirm_HoldTimerExpired(t *testing.T) {
	assert := assert.New(t)
	m := NewMockConnection()

	p, h := makePeerAndHandler()

	// push mock connection
	p.fsm.passiveConn = m

	// set up keepalive ticker
	p.fsm.peerConfig.Timers.KeepaliveInterval = 1

	// set holdtime
	p.fsm.negotiatedHoldTime = 2
	state := h.openconfirm()

	assert.Equal(bgp.BGP_FSM_IDLE, state)
	lastMsg := m.sendBuf[len(m.sendBuf)-1]
	sent, _ := bgp.ParseBGPMessage(lastMsg)
	assert.Equal(bgp.BGP_MSG_NOTIFICATION, sent.Header.Type)
	assert.Equal(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED, sent.Body.(*bgp.BGPNotification).ErrorCode)

}

func TestFSMHandlerEstablish_HoldTimerExpired(t *testing.T) {
	assert := assert.New(t)
	m := NewMockConnection()

	p, h := makePeerAndHandler()

	// push mock connection
	p.fsm.passiveConn = m

	// set up keepalive ticker
	sec := time.Second * 1
	p.fsm.keepaliveTicker = time.NewTicker(sec)

	msg := keepalive()
	header, _ := msg.Header.Serialize()
	body, _ := msg.Body.Serialize()

	pushPackets := func() {
		// first keepalive from peer
		m.recvCh <- header
		m.recvCh <- body
	}

	// set holdtime
	p.fsm.peerConfig.Timers.HoldTime = 2
	p.fsm.negotiatedHoldTime = 2

	go pushPackets()
	state := h.established()
	time.Sleep(time.Second * 1)
	assert.Equal(bgp.BGP_FSM_IDLE, state)
	lastMsg := m.sendBuf[len(m.sendBuf)-1]
	sent, _ := bgp.ParseBGPMessage(lastMsg)
	assert.Equal(bgp.BGP_MSG_NOTIFICATION, sent.Header.Type)
	assert.Equal(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED, sent.Body.(*bgp.BGPNotification).ErrorCode)
}

func makePeerAndHandler() (*Peer, *FSMHandler) {
	globalConfig := config.GlobalType{}
	neighborConfig := config.NeighborType{}

	p := &Peer{
		globalConfig:   globalConfig,
		peerConfig:     neighborConfig,
		acceptedConnCh: make(chan net.Conn),
		serverMsgCh:    make(chan *serverMsg),
		peerMsgCh:      make(chan *peerMsg),
		capMap:         make(map[bgp.BGPCapabilityCode]bgp.ParameterCapabilityInterface),
	}

	p.siblings = make(map[string]*serverMsgDataPeer)
	p.fsm = NewFSM(&globalConfig, &neighborConfig, p.acceptedConnCh)

	incoming := make(chan *fsmMsg, FSM_CHANNEL_LENGTH)
	p.outgoing = make(chan *bgp.BGPMessage, FSM_CHANNEL_LENGTH)

	h := &FSMHandler{
		fsm:      p.fsm,
		errorCh:  make(chan bool, 2),
		incoming: incoming,
		outgoing: p.outgoing,
	}

	return p, h

}

func open() *bgp.BGPMessage {
	p1 := bgp.NewOptionParameterCapability(
		[]bgp.ParameterCapabilityInterface{bgp.NewCapRouteRefresh()})
	p2 := bgp.NewOptionParameterCapability(
		[]bgp.ParameterCapabilityInterface{bgp.NewCapMultiProtocol(3, 4)})
	g := bgp.CapGracefulRestartTuples{4, 2, 3}
	p3 := bgp.NewOptionParameterCapability(
		[]bgp.ParameterCapabilityInterface{bgp.NewCapGracefulRestart(2, 100,
			[]bgp.CapGracefulRestartTuples{g})})
	p4 := bgp.NewOptionParameterCapability(
		[]bgp.ParameterCapabilityInterface{bgp.NewCapFourOctetASNumber(100000)})
	return bgp.NewBGPOpenMessage(11033, 303, "100.4.10.3",
		[]bgp.OptionParameterInterface{p1, p2, p3, p4})
}

func keepalive() *bgp.BGPMessage {
	return bgp.NewBGPKeepAliveMessage()
}
