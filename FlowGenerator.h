#pragma once

#include <unordered_map>
#include <vector>
#include <string>
#include <memory>
#include "BasicFlow.h"  // Include the definition of BasicFlow

class FlowGenerator {
public:
    std::unordered_map<std::string, BasicFlow> currentFlows;
    std::unordered_map<std::string, BasicFlow> finishedFlows;
    std::unordered_map<std::string, std::vector<std::string>> IPAddresses;  // Assuming string representation for IPs

    bool bidirectional;
    int64_t flowTimeOut;
    int64_t flowActivityTimeOut;

    FlowGenerator(bool bidirectional, int64_t flowTimeout, int64_t activityTimeout)
        : bidirectional(bidirectional), flowTimeOut(flowTimeout), flowActivityTimeOut(activityTimeout) {
        init();
    }

    void init() {
        currentFlows.clear();
        IPAddresses.clear();
    }

    void addPacket(BasicPacketInfo packet) {
        BasicFlow flow;
        int64_t currentTimestamp = packet.getTimeStamp();
        std::string id;

        if (currentFlows.find(packet.fwdFlowId()) != currentFlows.end() || currentFlows.find(packet.bwdFlowId()) != currentFlows.end()) {
            if (currentFlows.find(packet.fwdFlowId()) != currentFlows.end()) {
                id = packet.fwdFlowId();
            } else {
                id = packet.bwdFlowId();
            }

            flow = currentFlows[id];
            if ((currentTimestamp - flow.getFlowStartTime()) > flowTimeOut) {
                currentFlows.erase(id);
                if (flow.packetCount() > 1) {
                    // Assuming mListener is some callback mechanism you've implemented
                    onFlowGenerated(flow);
                }
                currentFlows[id] = BasicFlow(bidirectional, packet, flow.getSrc(), flow.getDst(), flow.getSrcPort(), flow.getDstPort(), flow.activityTimeout);
                // if (currentFlows.size() % 50 == 0) {
                std::cout << "Timeout current has " << currentFlows.size() << " flow\n";
                // }
            } else if (packet.hasFlagFIN()) {
                // std::cout<<ip2str(flow.getSrc())<<" "<<ip2str(flow.getDst())<<std::endl;
                // std::cout<<ip2str(packet.getSrc())<<" "<<ip2str(packet.getDst())<<std::endl;
                if (flow.getSrc() == packet.getSrc()) {
                    // forward
                    if(flow.setFwdFINFlags() >= 1){
                        if (flow.getFwdFINFlags() >= 1 && flow.getBwdFINFlags() >= 1) {
                            // std::cout<<"2 fin"<<std::endl;
                            flow.addPacket(packet);
                            currentFlows[id] = flow;
                        } else {
                            flow.updateActiveIdleTime(currentTimestamp, this->flowActivityTimeOut);
                            flow.addPacket(packet);
                            currentFlows[id] = flow;
                        }
                    }
                } else {
                    // backward
                    if(flow.setBwdFINFlags() >= 1){
                        if (flow.getFwdFINFlags() >=1 && flow.getBwdFINFlags() >= 1) {
                            // std::cout<<"2 fin"<<std::endl;
                            // std::cout<<"close"<<std::endl;
                            flow.addPacket(packet);
                            currentFlows[id] = flow;
                        } else {
                            flow.updateActiveIdleTime(currentTimestamp, flowActivityTimeOut);
                            flow.addPacket(packet);
                            currentFlows[id] = flow;
                        }
                    }
                }
            } else if(packet.hasFlagRST()){
                flow.addPacket(packet);
                currentFlows.erase(id);
                onFlowGenerated(flow);
            } else {
                //
    			// Forward Flow and fwdFIN = 0
    			//
    			if ((flow.getSrc() == packet.getSrc()) && (flow.getFwdFINFlags() == 0)) {
        			flow.updateActiveIdleTime(currentTimestamp,flowActivityTimeOut);
        			flow.addPacket(packet);
        			currentFlows[id] = flow;
    			// 
    			// Backward Flow and bwdFIN = 0
    			//    				
    			} else if (flow.getBwdFINFlags() == 0) {
        			flow.updateActiveIdleTime(currentTimestamp,flowActivityTimeOut);
        			flow.addPacket(packet);
        			currentFlows[id] = flow;
        		//
        		// FLOW already closed!!!
        		//
    			} else {
                    currentFlows.erase(id);
                    onFlowGenerated(flow);
    			}
            }
            // std::cout<<flow.fFIN_cnt<<" "<<flow.bFIN_cnt<<std::endl;
        } else {
            currentFlows[packet.fwdFlowId()] = BasicFlow(bidirectional, packet, flowActivityTimeOut);
        }
    }

    void onFlowGenerated(BasicFlow& flow) { //一个流结束，生成记录
        std::string flowDump = flow.dumpFlowBasedFeaturesEx();
        std::cout<<"now has "<<currentFlows.size()<<" flow "<<std::endl;
        std::cout<<"generated:"<<flow.getFlowId()<<std::endl;
        auto feature_vec=flow.dump();
    }

};
