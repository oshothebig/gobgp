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
	//"encoding/json"
	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/table"
	"github.com/stretchr/testify/assert"
	"net"
	"reflect"
	"testing"
	"time"
)

func peerRC3() *table.PeerInfo {
	peer := &table.PeerInfo{
		AS:      66003,
		ID:      net.ParseIP("10.0.255.3").To4(),
		LocalID: net.ParseIP("10.0.255.1").To4(),
	}
	return peer
}

func createAsPathAttribute(ases []uint32) *bgp.PathAttributeAsPath {
	aspathParam := []bgp.AsPathParamInterface{bgp.NewAs4PathParam(2, ases)}
	aspath := bgp.NewPathAttributeAsPath(aspathParam)
	return aspath
}

func createMpReach(nexthop string, prefix []bgp.AddrPrefixInterface) *bgp.PathAttributeMpReachNLRI {
	mp_reach := bgp.NewPathAttributeMpReachNLRI(nexthop, prefix)
	return mp_reach
}

func update_fromRC3() *bgp.BGPMessage {
	pathAttributes := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(1),
		createAsPathAttribute([]uint32{66003, 4000, 70000}),
		createMpReach("2001:db8::3",
			[]bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(64, "38:38:38:38::")}),
	}
	return bgp.NewBGPUpdateMessage([]bgp.WithdrawnRoute{}, pathAttributes, []bgp.NLRInfo{})
}

func TestProcessBGPUpdate_fourbyteAS(t *testing.T) {
	rib1 := table.NewTableManager("peer_test")

	m := update_fromRC3()
	peerInfo := peerRC3()
	msg := table.NewProcessMessage(m, peerInfo)
	pathList := msg.ToPathList()

	pList, wList, _ := rib1.ProcessPaths(pathList)
	assert.Equal(t, len(pList), 1)
	assert.Equal(t, len(wList), 0)
	fmt.Println(pList)
	sendMsg := table.CreateUpdateMsgFromPaths(pList)
	assert.Equal(t, len(sendMsg), 1)
	table.UpdatePathAttrs2ByteAs(sendMsg[0].Body.(*bgp.BGPUpdate))
	update := sendMsg[0].Body.(*bgp.BGPUpdate)
	assert.Equal(t, len(update.PathAttributes), 4)
	assert.Equal(t, reflect.TypeOf(update.PathAttributes[3]).String(), "*bgp.PathAttributeAs4Path")
	attr := update.PathAttributes[3].(*bgp.PathAttributeAs4Path)
	assert.Equal(t, len(attr.Value), 1)
	assert.Equal(t, attr.Value[0].AS, []uint32{66003, 70000})
	attrAS := update.PathAttributes[1].(*bgp.PathAttributeAsPath)
	assert.Equal(t, len(attrAS.Value), 1)
	assert.Equal(t, attrAS.Value[0].(*bgp.AsPathParam).AS, []uint16{bgp.AS_TRANS, 4000, bgp.AS_TRANS})

	rib2 := table.NewTableManager("peer_test")
	pList2, wList2, _ := rib2.ProcessPaths(pathList)
	assert.Equal(t, len(pList2), 1)
	assert.Equal(t, len(wList2), 0)
	sendMsg2 := table.CreateUpdateMsgFromPaths(pList2)
	assert.Equal(t, len(sendMsg2), 1)
	update2 := sendMsg2[0].Body.(*bgp.BGPUpdate)
	assert.Equal(t, len(update2.PathAttributes), 3)
	attrAS2 := update2.PathAttributes[1].(*bgp.PathAttributeAsPath)
	assert.Equal(t, len(attrAS2.Value), 1)
	assert.Equal(t, attrAS2.Value[0].(*bgp.As4PathParam).AS, []uint32{66003, 4000, 70000})
}

func TestPeerAdminShutdownWhileEstablished(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	assert := assert.New(t)
	m := NewMockConnection()
	globalConfig := config.GlobalType{}
	peerConfig := config.NeighborType{}
	peerConfig.PeerAs = 100000
	peerConfig.Timers.KeepaliveInterval = 5
	peer := makePeer(globalConfig, peerConfig)
	peer.fsm.opensentHoldTime = 10

	peer.t.Go(peer.loop)
	pushPackets := func() {
		o, _ := open().Serialize()
		m.setData(o)
		k, _ := keepalive().Serialize()
		m.setData(k)
	}
	go pushPackets()

	waitUntil(bgp.BGP_FSM_ACTIVE, peer, 1000)
	peer.acceptedConnCh <- m
	waitUntil(bgp.BGP_FSM_ESTABLISHED, peer, 1000)

	msg := &serverMsg{
		msgType: SRV_MSG_PEER_SHUTDOWN,
		msgData: nil,
	}
	peer.serverMsgCh <- msg

	waitUntil(bgp.BGP_FSM_IDLE, peer, 1000)

	assert.Equal(bgp.BGP_FSM_IDLE, peer.fsm.state)
	assert.Equal(ADMIN_STATE_DOWN, peer.fsm.adminState)
	lastMsg := m.sendBuf[len(m.sendBuf)-1]
	sent, _ := bgp.ParseBGPMessage(lastMsg)
	assert.Equal(bgp.BGP_MSG_NOTIFICATION, sent.Header.Type)
	assert.Equal(bgp.BGP_ERROR_CEASE, sent.Body.(*bgp.BGPNotification).ErrorCode)
	assert.Equal(bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN, sent.Body.(*bgp.BGPNotification).ErrorSubcode)
	assert.True(m.isClosed)

	// check counter
	counter := peer.fsm.peerConfig.BgpNeighborCommonState
	assert.Equal(0, counter.OpenIn)
	assert.Equal(0, counter.UpdateIn)
	assert.Equal(0, counter.KeepaliveIn)
	assert.Equal(0, counter.OpenIn)
	assert.Equal(0, counter.EstablishedCount)
	assert.Equal(0, counter.TotalIn)

}

func TestPeerAdminShutdownWhileActive(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	assert := assert.New(t)

	globalConfig := config.GlobalType{}
	peerConfig := config.NeighborType{}
	peerConfig.PeerAs = 100000
	peerConfig.Timers.KeepaliveInterval = 5
	peer := makePeer(globalConfig, peerConfig)
	peer.fsm.opensentHoldTime = 10
	peer.t.Go(peer.loop)

	waitUntil(bgp.BGP_FSM_ACTIVE, peer, 1000)

	msg := &serverMsg{
		msgType: SRV_MSG_PEER_SHUTDOWN,
		msgData: nil,
	}
	peer.serverMsgCh <- msg
	time.Sleep(100 * time.Millisecond)
	assert.Equal(bgp.BGP_FSM_IDLE, peer.fsm.state)
	assert.Equal(ADMIN_STATE_DOWN, peer.fsm.adminState)
}

func TestPeerAdminShutdownWhileOpensent(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	assert := assert.New(t)
	m := NewMockConnection()
	globalConfig := config.GlobalType{}
	peerConfig := config.NeighborType{}
	peerConfig.PeerAs = 100000
	peerConfig.Timers.KeepaliveInterval = 5
	peer := makePeer(globalConfig, peerConfig)
	peer.fsm.opensentHoldTime = 1
	peer.t.Go(peer.loop)

	waitUntil(bgp.BGP_FSM_ACTIVE, peer, 1000)
	peer.acceptedConnCh <- m

	time.Sleep(500 * time.Millisecond)
	msg := &serverMsg{
		msgType: SRV_MSG_PEER_SHUTDOWN,
		msgData: nil,
	}
	peer.serverMsgCh <- msg
	time.Sleep(100 * time.Millisecond)
	assert.Equal(bgp.BGP_FSM_IDLE, peer.fsm.state)
	assert.Equal(ADMIN_STATE_DOWN, peer.fsm.adminState)
	lastMsg := m.sendBuf[len(m.sendBuf)-1]
	sent, _ := bgp.ParseBGPMessage(lastMsg)
	assert.NotEqual(bgp.BGP_MSG_NOTIFICATION, sent.Header.Type)
	assert.True(m.isClosed)
}

func TestPeerAdminShutdownWhileOpenconfirm(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	assert := assert.New(t)
	m := NewMockConnection()
	globalConfig := config.GlobalType{}
	peerConfig := config.NeighborType{}
	peerConfig.PeerAs = 100000
	peerConfig.Timers.KeepaliveInterval = 5
	peer := makePeer(globalConfig, peerConfig)
	peer.fsm.opensentHoldTime = 10
	peer.t.Go(peer.loop)
	pushPackets := func() {
		o, _ := open().Serialize()
		m.setData(o)
	}
	go pushPackets()

	waitUntil(bgp.BGP_FSM_ACTIVE, peer, 1000)
	peer.acceptedConnCh <- m

	time.Sleep(500 * time.Millisecond)
	msg := &serverMsg{
		msgType: SRV_MSG_PEER_SHUTDOWN,
		msgData: nil,
	}
	peer.serverMsgCh <- msg
	time.Sleep(100 * time.Millisecond)
	assert.Equal(bgp.BGP_FSM_IDLE, peer.fsm.state)
	assert.Equal(ADMIN_STATE_DOWN, peer.fsm.adminState)
	lastMsg := m.sendBuf[len(m.sendBuf)-1]
	sent, _ := bgp.ParseBGPMessage(lastMsg)
	assert.NotEqual(bgp.BGP_MSG_NOTIFICATION, sent.Header.Type)
	assert.True(m.isClosed)

}

func TestPeerAdminEnable(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	assert := assert.New(t)
	m := NewMockConnection()
	globalConfig := config.GlobalType{}
	peerConfig := config.NeighborType{}
	peerConfig.PeerAs = 100000
	peerConfig.Timers.KeepaliveInterval = 5
	peer := makePeer(globalConfig, peerConfig)

	peer.fsm.opensentHoldTime = 5
	peer.t.Go(peer.loop)
	pushPackets := func() {
		o, _ := open().Serialize()
		m.setData(o)
		k, _ := keepalive().Serialize()
		m.setData(k)
	}
	go pushPackets()

	waitUntil(bgp.BGP_FSM_ACTIVE, peer, 1000)
	peer.acceptedConnCh <- m
	waitUntil(bgp.BGP_FSM_ESTABLISHED, peer, 1000)

	// shutdown peer at first
	msg := &serverMsg{
		msgType: SRV_MSG_PEER_SHUTDOWN,
		msgData: nil,
	}
	peer.serverMsgCh <- msg
	time.Sleep(100 * time.Millisecond)
	assert.Equal(bgp.BGP_FSM_IDLE, peer.fsm.state)
	assert.Equal(ADMIN_STATE_DOWN, peer.fsm.adminState)

	// enable peer
	msg = &serverMsg{
		msgType: SRV_MSG_PEER_UP,
		msgData: nil,
	}
	peer.serverMsgCh <- msg
	waitUntil(bgp.BGP_FSM_ACTIVE, peer, 1000)
	assert.Equal(bgp.BGP_FSM_ACTIVE, peer.fsm.state)

	m2 := NewMockConnection()
	pushPackets = func() {
		o, _ := open().Serialize()
		m2.setData(o)
		k, _ := keepalive().Serialize()
		m2.setData(k)
	}
	go pushPackets()

	peer.acceptedConnCh <- m2

	waitUntil(bgp.BGP_FSM_ESTABLISHED, peer, 1000)
	assert.Equal(bgp.BGP_FSM_ESTABLISHED, peer.fsm.state)
}

func waitUntil(state bgp.FSMState, peer *Peer, timeout int64) {
	isTimeout := false
	expire := func() {
		isTimeout = true
	}
	time.AfterFunc((time.Duration)(timeout)*time.Millisecond, expire)

	for {
		time.Sleep(1 * time.Millisecond)
		if peer.fsm.state == state || isTimeout {
			break
		}
	}
}

func makePeer(globalConfig config.GlobalType, peerConfig config.NeighborType) *Peer {

	sch := make(chan *serverMsg, 8)
	pch := make(chan *peerMsg, 4096)

	p := &Peer{
		globalConfig:   globalConfig,
		peerConfig:     peerConfig,
		acceptedConnCh: make(chan net.Conn),
		serverMsgCh:    sch,
		peerMsgCh:      pch,
		capMap:         make(map[bgp.BGPCapabilityCode]bgp.ParameterCapabilityInterface),
	}
	p.siblings = make(map[string]*serverMsgDataPeer)

	p.fsm = NewFSM(&globalConfig, &peerConfig, p.acceptedConnCh)
	peerConfig.BgpNeighborCommonState.State = uint32(bgp.BGP_FSM_IDLE)
	peerConfig.BgpNeighborCommonState.Downtime = time.Now()
	if peerConfig.NeighborAddress.To4() != nil {
		p.rf = bgp.RF_IPv4_UC
	} else {
		p.rf = bgp.RF_IPv6_UC
	}

	p.peerInfo = &table.PeerInfo{
		AS:      peerConfig.PeerAs,
		LocalID: globalConfig.RouterId,
		RF:      p.rf,
		Address: peerConfig.NeighborAddress,
	}
	p.adjRib = table.NewAdjRib()
	p.rib = table.NewTableManager(p.peerConfig.NeighborAddress.String())

	return p
}
