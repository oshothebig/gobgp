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

package table

import (
	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/packet"
	"reflect"
	"time"
)

type ProcessMessage struct {
	innerMessage *bgp.BGPMessage
	fromPeer     *PeerInfo
}

func NewProcessMessage(m *bgp.BGPMessage, peerInfo *PeerInfo) *ProcessMessage {
	return &ProcessMessage{
		innerMessage: m,
		fromPeer:     peerInfo,
	}
}

func (p *ProcessMessage) nlri2Path(now time.Time) []Path {
	updateMsg := p.innerMessage.Body.(*bgp.BGPUpdate)
	pathAttributes := updateMsg.PathAttributes
	pathList := make([]Path, 0)
	for _, nlri_info := range updateMsg.NLRI {
		// define local variable to pass nlri's address to CreatePath
		var nlri bgp.NLRInfo = nlri_info
		// create Path object
		path := CreatePath(p.fromPeer, &nlri, pathAttributes, false, now)
		pathList = append(pathList, path)
	}
	return pathList
}

func (p *ProcessMessage) withdraw2Path(now time.Time) []Path {
	updateMsg := p.innerMessage.Body.(*bgp.BGPUpdate)
	pathAttributes := updateMsg.PathAttributes
	pathList := make([]Path, 0)
	for _, nlriWithdraw := range updateMsg.WithdrawnRoutes {
		// define local variable to pass nlri's address to CreatePath
		var w bgp.WithdrawnRoute = nlriWithdraw
		// create withdrawn Path object
		path := CreatePath(p.fromPeer, &w, pathAttributes, true, now)
		pathList = append(pathList, path)
	}
	return pathList
}

func (p *ProcessMessage) mpreachNlri2Path(now time.Time) []Path {
	updateMsg := p.innerMessage.Body.(*bgp.BGPUpdate)
	pathAttributes := updateMsg.PathAttributes
	attrList := []*bgp.PathAttributeMpReachNLRI{}

	for _, attr := range pathAttributes {
		a, ok := attr.(*bgp.PathAttributeMpReachNLRI)
		if ok {
			attrList = append(attrList, a)
			break
		}
	}
	pathList := make([]Path, 0)

	for _, mp := range attrList {
		nlri_info := mp.Value
		for _, nlri := range nlri_info {
			path := CreatePath(p.fromPeer, nlri, pathAttributes, false, now)
			pathList = append(pathList, path)
		}
	}
	return pathList
}

func (p *ProcessMessage) mpunreachNlri2Path(now time.Time) []Path {
	updateMsg := p.innerMessage.Body.(*bgp.BGPUpdate)
	pathAttributes := updateMsg.PathAttributes
	attrList := []*bgp.PathAttributeMpUnreachNLRI{}

	for _, attr := range pathAttributes {
		a, ok := attr.(*bgp.PathAttributeMpUnreachNLRI)
		if ok {
			attrList = append(attrList, a)
			break
		}
	}
	pathList := make([]Path, 0)

	for _, mp := range attrList {
		nlri_info := mp.Value

		for _, nlri := range nlri_info {
			path := CreatePath(p.fromPeer, nlri, pathAttributes, true, now)
			pathList = append(pathList, path)
		}
	}
	return pathList
}

func (p *ProcessMessage) ToPathList() []Path {
	pathList := make([]Path, 0)
	now := time.Now()
	pathList = append(pathList, p.nlri2Path(now)...)
	pathList = append(pathList, p.withdraw2Path(now)...)
	pathList = append(pathList, p.mpreachNlri2Path(now)...)
	pathList = append(pathList, p.mpunreachNlri2Path(now)...)
	return pathList
}

type TableManager struct {
	Tables   map[bgp.RouteFamily]Table
	localAsn uint32
	owner    string
}

func NewTableManager(owner string) *TableManager {
	t := &TableManager{}
	t.Tables = make(map[bgp.RouteFamily]Table)
	t.Tables[bgp.RF_IPv4_UC] = NewIPv4Table(0)
	t.Tables[bgp.RF_IPv6_UC] = NewIPv6Table(0)
	t.owner = owner
	return t
}

func (manager *TableManager) calculate(destinationList []Destination) ([]Path, []Path, error) {
	bestPaths := make([]Path, 0)
	lostPaths := make([]Path, 0)

	for _, destination := range destinationList {
		// compute best path

		log.WithFields(log.Fields{
			"Topic": "table",
			"Owner": manager.owner,
			"Key":   destination.getNlri().String(),
		}).Info("Processing destination")

		newBestPath, reason, err := destination.Calculate(manager.localAsn)

		if err != nil {
			log.Error(err)
			continue
		}

		destination.setBestPathReason(reason)
		currentBestPath := destination.getBestPath()

		if newBestPath != nil && currentBestPath == newBestPath {
			// best path is not changed
			log.WithFields(log.Fields{
				"Topic":    "table",
				"Owner":    manager.owner,
				"Key":      destination.getNlri().String(),
				"peer":     newBestPath.getSource().Address,
				"next_hop": newBestPath.getNexthop().String(),
				"reason":   reason,
			}).Debug("best path is not changed")
			continue
		}

		if newBestPath == nil {
			log.WithFields(log.Fields{
				"Topic": "table",
				"Owner": manager.owner,
				"Key":   destination.getNlri().String(),
			}).Debug("best path is nil")

			if len(destination.getKnownPathList()) == 0 {
				// create withdraw path
				if currentBestPath != nil {
					log.WithFields(log.Fields{
						"Topic":    "table",
						"Owner":    manager.owner,
						"Key":      destination.getNlri().String(),
						"peer":     currentBestPath.getSource().Address,
						"next_hop": currentBestPath.getNexthop().String(),
					}).Debug("best path is lost")

					p := destination.getBestPath()
					destination.setOldBestPath(p)
					lostPaths = append(lostPaths, p.clone(true))
				}
				destination.setBestPath(nil)
			} else {

				log.WithFields(log.Fields{
					"Topic": "table",
					"Owner": manager.owner,
					"Key":   destination.getNlri().String(),
				}).Error("known path list is not empty")
			}
		} else {
			log.WithFields(log.Fields{
				"Topic":    "table",
				"Owner":    manager.owner,
				"Key":      newBestPath.getNlri().String(),
				"peer":     newBestPath.getSource().Address,
				"next_hop": newBestPath.getNexthop(),
				"reason":   reason,
			}).Debug("new best path")

			bestPaths = append(bestPaths, newBestPath)
			destination.setBestPath(newBestPath)
		}

		if len(destination.getKnownPathList()) == 0 && destination.getBestPath() == nil {
			rf := destination.getRouteFamily()
			t := manager.Tables[rf]
			deleteDest(t, destination)
			log.WithFields(log.Fields{
				"Topic":        "table",
				"Owner":        manager.owner,
				"Key":          destination.getNlri().String(),
				"route_family": rf,
			}).Debug("destination removed")
		}
	}
	return bestPaths, lostPaths, nil
}

func (manager *TableManager) DeletePathsforPeer(peerInfo *PeerInfo) ([]Path, []Path, error) {
	destinationList := manager.Tables[peerInfo.RF].DeleteDestByPeer(peerInfo)
	return manager.calculate(destinationList)

}

func (manager *TableManager) ProcessPaths(pathList []Path) ([]Path, []Path, error) {
	destinationList := make([]Destination, 0)
	for _, path := range pathList {
		rf := path.GetRouteFamily()
		// push Path into table
		destination := insert(manager.Tables[rf], path)
		destinationList = append(destinationList, destination)
	}
	return manager.calculate(destinationList)
}

// process BGPUpdate message
// this function processes only BGPUpdate
func (manager *TableManager) ProcessUpdate(fromPeer *PeerInfo, message *bgp.BGPMessage) ([]Path, []Path, error) {
	// check msg's type if it's BGPUpdate
	if message.Header.Type != bgp.BGP_MSG_UPDATE {
		log.WithFields(log.Fields{
			"Topic": "table",
			"Owner": manager.owner,
			"key":   fromPeer.Address.String(),
			"Type":  message.Header.Type,
		}).Warn("message is not BGPUpdate")
		return []Path{}, []Path{}, nil
	}

	msg := &ProcessMessage{
		innerMessage: message,
		fromPeer:     fromPeer,
	}

	return manager.ProcessPaths(msg.ToPathList())
}

type AdjRib struct {
	adjRibIn  map[bgp.RouteFamily]map[string]*ReceivedRoute
	adjRibOut map[bgp.RouteFamily]map[string]*ReceivedRoute
}

func NewAdjRib() *AdjRib {
	r := &AdjRib{
		adjRibIn:  make(map[bgp.RouteFamily]map[string]*ReceivedRoute),
		adjRibOut: make(map[bgp.RouteFamily]map[string]*ReceivedRoute),
	}
	r.adjRibIn[bgp.RF_IPv4_UC] = make(map[string]*ReceivedRoute)
	r.adjRibIn[bgp.RF_IPv6_UC] = make(map[string]*ReceivedRoute)
	r.adjRibOut[bgp.RF_IPv4_UC] = make(map[string]*ReceivedRoute)
	r.adjRibOut[bgp.RF_IPv6_UC] = make(map[string]*ReceivedRoute)
	return r
}

func (adj *AdjRib) update(rib map[bgp.RouteFamily]map[string]*ReceivedRoute, pathList []Path) {
	for _, path := range pathList {
		rf := path.GetRouteFamily()
		key := path.getPrefix()
		old, found := rib[rf][key]
		if path.IsWithdraw() {
			if found {
				delete(rib[rf], key)
			}
		} else {
			if found && reflect.DeepEqual(old.path.getPathAttrs(), path.getPathAttrs()) {
				path.setTimestamp(old.path.getTimestamp())
			}
			rib[rf][key] = NewReceivedRoute(path, false)
		}
	}
}

func (adj *AdjRib) UpdateIn(pathList []Path) {
	adj.update(adj.adjRibIn, pathList)
}

func (adj *AdjRib) UpdateOut(pathList []Path) {
	adj.update(adj.adjRibOut, pathList)
}

func (adj *AdjRib) getPathList(rib map[string]*ReceivedRoute) []Path {
	pathList := []Path{}

	for _, rr := range rib {
		pathList = append(pathList, rr.path)
	}
	return pathList
}

func (adj *AdjRib) GetInPathList(rf bgp.RouteFamily) []Path {
	return adj.getPathList(adj.adjRibIn[rf])
}

func (adj *AdjRib) GetOutPathList(rf bgp.RouteFamily) []Path {
	return adj.getPathList(adj.adjRibOut[rf])
}

func (adj *AdjRib) GetInCount(rf bgp.RouteFamily) int {
	return len(adj.adjRibIn[rf])
}

func (adj *AdjRib) GetOutCount(rf bgp.RouteFamily) int {
	return len(adj.adjRibOut[rf])
}

func (adj *AdjRib) DropAllIn(rf bgp.RouteFamily) {
	// replace old one
	adj.adjRibIn[rf] = make(map[string]*ReceivedRoute)
}

type ReceivedRoute struct {
	path     Path
	filtered bool
}

func (rr *ReceivedRoute) String() string {
	return rr.path.(*PathDefault).getPrefix()
}

func NewReceivedRoute(path Path, filtered bool) *ReceivedRoute {

	rroute := &ReceivedRoute{
		path:     path,
		filtered: filtered,
	}
	return rroute
}
