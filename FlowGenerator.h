#pragma once

#include <unordered_map>
#include <vector>
#include <string>
#include <memory>
#include "BasicFlow.h"  // Include the definition of BasicFlow

class FlowGenerator {
public:
    std::unordered_map<std::string, BasicFlow> currentFlows;
    std::unordered_map<std::string, std::vector<std::string>> IPAddresses;  // Assuming string representation for IPs

    bool bidirectional;
    __u64 flowTimeOut;
    __u64 flowActivityTimeOut;

    FlowGenerator(bool bidirectional, long flowTimeout, long activityTimeout)
        : bidirectional(bidirectional), flowTimeOut(flowTimeout), flowActivityTimeOut(activityTimeout) {
        init();
    }

    void init() {
        currentFlows.clear();
        IPAddresses.clear();
    }

    void addPacket(BasicPacketInfo packet) {
        BasicFlow flow;
        __u64 currentTimestamp = packet.getTimeStamp();
        std::string id;

        if (currentFlows.find(packet.fwdFlowId()) != currentFlows.end() || currentFlows.find(packet.bwdFlowId()) != currentFlows.end()) {
            if (currentFlows.find(packet.fwdFlowId()) != currentFlows.end()) {
                id = packet.fwdFlowId();
            } else {
                id = packet.bwdFlowId();
            }

            flow = currentFlows[id];
            if ((currentTimestamp - flow.getFlowStartTime()) > flowTimeOut) {
                if (flow.packetCount() > 1) {
                    // Assuming mListener is some callback mechanism you've implemented
                    onFlowGenerated(flow);
                }
                currentFlows.erase(id);
                currentFlows[id] = BasicFlow(bidirectional, packet, flow.getSrc(), flow.getDst(), flow.getSrcPort(), flow.getDstPort());
                if (currentFlows.size() % 50 == 0) {
                    std::cout << "Timeout current has " << currentFlows.size() << " flow\n";
                }
            } else if (packet.hasFlagFIN()) {
                std::cout << "FlagFIN current has " << currentFlows.size() << " flow\n";
                flow.addPacket(packet);
                onFlowGenerated(flow);
                currentFlows.erase(id);
            } else {
                flow.updateActiveIdleTime(currentTimestamp, this->flowActivityTimeOut);
                flow.addPacket(packet);
                currentFlows[id] = flow;
            }
        } else {
            currentFlows[packet.fwdFlowId()] = BasicFlow(bidirectional, packet);
        }
    }

    void onFlowGenerated(const BasicFlow& flow) { //一个流结束，生成记录
        std::string flowDump = flow.dumpFlowBasedFeaturesEx();
    }

};
