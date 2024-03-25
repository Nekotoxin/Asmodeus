#pragma once

#include <vector>
#include <unordered_map>
#include <string>
#include <cstdint> // for std::uint8_t
#include "BasicPacketInfo.h" // Include your translated BasicPacketInfo class

#include "FlowFeature.h"

#include <boost/accumulators/accumulators.hpp>
#include <boost/accumulators/statistics/stats.hpp>
#include <boost/accumulators/statistics/mean.hpp>
#include <boost/accumulators/statistics/variance.hpp>
#include <boost/accumulators/statistics/min.hpp>
#include <boost/accumulators/statistics/max.hpp>

using namespace boost::accumulators;

class BasicFlow {
public:
    static const std::string separator;
    accumulator_set<double, stats<tag::mean, tag::variance, tag::min, tag::max, tag::sum>> fwdPktStats;
    accumulator_set<double, stats<tag::mean, tag::variance, tag::min, tag::max, tag::sum>> bwdPktStats;
    accumulator_set<double, stats<tag::mean, tag::variance, tag::min, tag::max, tag::sum>> PktStats;
    
    std::vector<BasicPacketInfo> forward;
    std::vector<BasicPacketInfo> backward;

    int64_t forwardBytes;
    int64_t backwardBytes;
    int64_t fHeaderBytes;
    int64_t bHeaderBytes;

    bool isBidirectional;

    std::unordered_map<std::string, int> flagCounts; // MutableInt is simplified to int

    int fPSH_cnt;
    int bPSH_cnt;
    int fURG_cnt;
    int bURG_cnt;
    int fFIN_cnt;
	int bFIN_cnt;

    int64_t Act_data_pkt_forward;
    int64_t min_seg_size_forward;
    int Init_Win_bytes_forward = 0;
    int Init_Win_bytes_backward = 0;

    std::vector<uint8_t> src;
    std::vector<uint8_t> dst;
    int srcPort;
    int dstPort;
    int protocol;
    int64_t flowStartTime;
    int64_t startActiveTime;
    int64_t endActiveTime;
    std::string flowId;

    accumulator_set<double, stats<tag::mean, tag::variance, tag::min, tag::max, tag::sum>> flowIAT;
    accumulator_set<double, stats<tag::mean, tag::variance, tag::min, tag::max, tag::sum>> forwardIAT;
    accumulator_set<double, stats<tag::mean, tag::variance, tag::min, tag::max, tag::sum>> backwardIAT;
    accumulator_set<double, stats<tag::mean, tag::variance, tag::min, tag::max, tag::sum>> flowActive;
    accumulator_set<double, stats<tag::mean, tag::variance, tag::min, tag::max, tag::sum>> flowIdle;

    int64_t flowLastSeen;
    int64_t forwardLastSeen;
    int64_t backwardLastSeen;
    int64_t activityTimeout;

    int64_t fbulkDuration = 0;
    int64_t fbulkPacketCount = 0;
    int64_t fbulkSizeTotal = 0;
    int64_t fbulkStateCount = 0;
    int64_t fbulkPacketCountHelper = 0;
    int64_t fbulkStartHelper = 0;
    int64_t fbulkSizeHelper = 0;
    int64_t flastBulkTS = 0;
    int64_t bbulkDuration = 0;
    int64_t bbulkPacketCount = 0;
    int64_t bbulkSizeTotal = 0;
    int64_t bbulkStateCount = 0;
    int64_t bbulkPacketCountHelper = 0;
    int64_t bbulkStartHelper = 0;
    int64_t bbulkSizeHelper = 0;
    int64_t blastBulkTS = 0;

    int64_t sfLastPacketTS = -1;
    int sfCount = 0;
    int64_t sfAcHelper = -1;

    FlowFeature flowFeature;
public:
    std::vector<float> dump() {
        flowFeature.featureMap["Destination Port"] = dstPort; // 1
        flowFeature.featureMap["Flow Duration"] = getFlowDuration(); // 2
        flowFeature.featureMap["Total Fwd Packets"] = forward.size(); // 3
        flowFeature.featureMap["Total Backward Packets"] = backward.size(); // 4
        flowFeature.featureMap["Total Length of Fwd Packets"] = forwardBytes; // 5
        flowFeature.featureMap["Total Length of Bwd Packets"] = backwardBytes; // 6
        flowFeature.featureMap["Fwd Packet Length Max"] = extract::max(fwdPktStats); // 7
        flowFeature.featureMap["Fwd Packet Length Min"] = extract::min(fwdPktStats); // 8
        flowFeature.featureMap["Fwd Packet Length Mean"] = extract::mean(fwdPktStats); // 9
        flowFeature.featureMap["Fwd Packet Length Std"] = sqrt(extract::variance(fwdPktStats)); // 10
        flowFeature.featureMap["Bwd Packet Length Max"] = extract::max(bwdPktStats); // 11
        flowFeature.featureMap["Bwd Packet Length Min"] = extract::min(bwdPktStats); // 12
        flowFeature.featureMap["Bwd Packet Length Mean"] = extract::mean(bwdPktStats); // 13
        flowFeature.featureMap["Bwd Packet Length Std"] = sqrt(extract::variance(bwdPktStats)); // 14
        // Assuming flowDuration is in microseconds for these calculations
        double flowDurationInSeconds = static_cast<double>(getFlowDuration()) / 1000000.0; // Convert microseconds to seconds
        flowFeature.featureMap["Flow Bytes/s"] = (flowDurationInSeconds > 0) ? (static_cast<double>(forwardBytes + backwardBytes) / flowDurationInSeconds) : 0; // 15
        flowFeature.featureMap["Flow Packets/s"] = (flowDurationInSeconds > 0) ? (static_cast<double>(forward.size() + backward.size()) / flowDurationInSeconds) : 0; // 16
        flowFeature.featureMap["Flow IAT Mean"] = extract::mean(flowIAT); // 17
        flowFeature.featureMap["Flow IAT Std"] = sqrt(extract::variance(flowIAT)); // 18
        flowFeature.featureMap["Flow IAT Max"] = extract::max(flowIAT); // 19
        flowFeature.featureMap["Flow IAT Min"] = extract::min(flowIAT); // 20
        flowFeature.featureMap["Fwd IAT Total"] = extract::sum(forwardIAT); // 21
        flowFeature.featureMap["Fwd IAT Mean"] = extract::mean(forwardIAT); // 22
        flowFeature.featureMap["Fwd IAT Std"] = sqrt(extract::variance(forwardIAT)); // 23
        flowFeature.featureMap["Fwd IAT Max"] = extract::max(forwardIAT); // 24
        flowFeature.featureMap["Fwd IAT Min"] = extract::min(forwardIAT); // 25
        flowFeature.featureMap["Bwd IAT Total"] = extract::sum(backwardIAT); // 26
        flowFeature.featureMap["Bwd IAT Mean"] = extract::mean(backwardIAT); // 27
        flowFeature.featureMap["Bwd IAT Std"] = sqrt(extract::variance(backwardIAT)); // 28
        flowFeature.featureMap["Bwd IAT Max"] = extract::max(backwardIAT); // 29
        flowFeature.featureMap["Bwd IAT Min"] = extract::min(backwardIAT); // 30
        flowFeature.featureMap["Fwd PSH Flags"] = fPSH_cnt; // 31
        flowFeature.featureMap["Bwd PSH Flags"] = bPSH_cnt; // 32
        flowFeature.featureMap["Fwd URG Flags"] = fURG_cnt; // 33
        flowFeature.featureMap["Bwd URG Flags"] = bURG_cnt; // 34
        flowFeature.featureMap["Fwd Header Length"] = fHeaderBytes; // 35
        flowFeature.featureMap["Bwd Header Length"] = bHeaderBytes; // 36
        flowFeature.featureMap["Fwd Packets/s"] = getfPktsPerSecond(); // 37
        flowFeature.featureMap["Bwd Packets/s"] = getbPktsPerSecond(); // 38
        flowFeature.featureMap["Min Packet Length"] = extract::min(PktStats); // 39
        flowFeature.featureMap["Max Packet Length"] = extract::max(PktStats); // 40
        flowFeature.featureMap["Packet Length Mean"] = extract::mean(PktStats); // 41
        flowFeature.featureMap["Packet Length Std"] = sqrt(extract::variance(PktStats)); // 42
        flowFeature.featureMap["Packet Length Variance"] = extract::variance(PktStats); // 43
        flowFeature.featureMap["FIN Flag Count"] = flagCounts["FIN"]; // 44
        flowFeature.featureMap["SYN Flag Count"] = flagCounts["SYN"]; // 45
        flowFeature.featureMap["RST Flag Count"] = flagCounts["RST"]; // 46
        flowFeature.featureMap["PSH Flag Count"] = flagCounts["PSH"]; // 47
        flowFeature.featureMap["ACK Flag Count"] = flagCounts["ACK"]; // 48
        flowFeature.featureMap["URG Flag Count"] = flagCounts["URG"]; // 49
        flowFeature.featureMap["CWE Flag Count"] = flagCounts["CWR"]; // 50
        flowFeature.featureMap["ECE Flag Count"] = flagCounts["ECE"]; // 51
        flowFeature.featureMap["Down/Up Ratio"] = getDownUpRatio(); // 52
        flowFeature.featureMap["Average Packet Size"] = getAvgPacketSize(); // 53
        flowFeature.featureMap["Avg Fwd Segment Size"] = fAvgSegmentSize(); // 54
        flowFeature.featureMap["Avg Bwd Segment Size"] = bAvgSegmentSize(); // 55
        flowFeature.featureMap["Fwd Header Length"] = fHeaderBytes; // 56 (Repeated intentionally as per instructions)
        flowFeature.featureMap["Fwd Avg Bytes/Bulk"] = fAvgBytesPerBulk(); // 57
        flowFeature.featureMap["Fwd Avg Packets/Bulk"] = fAvgPacketsPerBulk(); // 58
        flowFeature.featureMap["Fwd Avg Bulk Rate"] = fAvgBulkRate(); // 59
        flowFeature.featureMap["Bwd Avg Bytes/Bulk"] = bAvgBytesPerBulk(); // 60
        flowFeature.featureMap["Bwd Avg Packets/Bulk"] = bAvgPacketsPerBulk(); // 61
        flowFeature.featureMap["Bwd Avg Bulk Rate"] = bAvgBulkRate(); // 62
        flowFeature.featureMap["Subflow Fwd Packets"] = getSflow_fpackets(); // 63
        flowFeature.featureMap["Subflow Fwd Bytes"] = getSflow_fbytes(); // 64
        flowFeature.featureMap["Subflow Bwd Packets"] = getSflow_bpackets(); // 65
        flowFeature.featureMap["Subflow Bwd Bytes"] = getSflow_bbytes(); // 66
        flowFeature.featureMap["Init_Win_bytes_forward"] = Init_Win_bytes_forward; // 67
        flowFeature.featureMap["Init_Win_bytes_backward"] = Init_Win_bytes_backward; // 68
        flowFeature.featureMap["act_data_pkt_fwd"] = Act_data_pkt_forward; // 69
        flowFeature.featureMap["min_seg_size_forward"] = min_seg_size_forward; // 70
        flowFeature.featureMap["Active Mean"] = extract::mean(flowActive); // 71
        flowFeature.featureMap["Active Std"] = sqrt(extract::variance(flowActive)); // 72
        flowFeature.featureMap["Active Max"] = extract::max(flowActive); // 73
        flowFeature.featureMap["Active Min"] = extract::min(flowActive); // 74
        flowFeature.featureMap["Idle Mean"] = extract::mean(flowIdle); // 75
        flowFeature.featureMap["Idle Std"] = sqrt(extract::variance(flowIdle)); // 76
        flowFeature.featureMap["Idle Max"] = extract::max(flowIdle); // 77
        flowFeature.featureMap["Idle Min"] = extract::min(flowIdle); // 78

        return flowFeature.getRequiredFeatures();
    }

    void initFlags() {
        flagCounts["FIN"] = 0;
        flagCounts["SYN"] = 0;
        flagCounts["RST"] = 0;
        flagCounts["PSH"] = 0;
        flagCounts["ACK"] = 0;
        flagCounts["URG"] = 0;
        flagCounts["CWR"] = 0;
        flagCounts["ECE"] = 0;
    }

    int getFwdFINFlags() {
		return fFIN_cnt;
	}
	
	int getBwdFINFlags() {
		return bFIN_cnt;
	}
	
	int setFwdFINFlags() {
		fFIN_cnt++;
		return fFIN_cnt;
	}
	
	int setBwdFINFlags() {
		bFIN_cnt++;
		return bFIN_cnt;
	}	

    // Previous private members...

    void initParameters() {
        forward.clear();
        backward.clear();
        // Reset accumulators
        fwdPktStats = {};
        bwdPktStats = {};
        flowIAT = {};
        forwardIAT = {};
        backwardIAT = {};
        flowActive = {};
        flowIdle = {};
        PktStats = {};

        flagCounts.clear();
        initFlags(); // You need to define this function based on how you want to initialize flags.

        forwardBytes = 0ULL;
        backwardBytes = 0ULL;
        startActiveTime = 0ULL;
        endActiveTime = 0ULL;
        src.clear();
        dst.clear();
        fPSH_cnt = 0;
        bPSH_cnt = 0;
        fURG_cnt = 0;
        bURG_cnt = 0;
        fFIN_cnt = 0;
        bFIN_cnt = 0;
        fHeaderBytes = 0ULL;
        bHeaderBytes = 0ULL;
    }

public:
    BasicFlow(){}
    BasicFlow(bool isBidirectional, BasicPacketInfo packet, std::vector<uint8_t> flowSrc, std::vector<uint8_t> flowDst, int flowSrcPort, int flowDstPort, int64_t activityTimeout) {
        initParameters();
        this->isBidirectional = isBidirectional;
        firstPacket(packet); // You need to define this function based on how you handle the first packet.
        src = std::move(flowSrc);
        dst = std::move(flowDst);
        srcPort = flowSrcPort;
        dstPort = flowDstPort;
        this->activityTimeout=activityTimeout;
    }

    BasicFlow(bool isBidirectional, BasicPacketInfo packet, int64_t activityTimeout) {
        initParameters();
        this->activityTimeout=activityTimeout;
        this->isBidirectional = isBidirectional;
        firstPacket(packet); // Define this function as well.
    }

    BasicFlow(BasicPacketInfo packet, int64_t activityTimeout) {
        initParameters();
        this->activityTimeout=activityTimeout;
        isBidirectional = true;
        firstPacket(packet); // Define this function.
    }

    void firstPacket(BasicPacketInfo& packet) {
        updateFlowBulk(packet);
        detectUpdateSubflows(packet);
        checkFlags(packet);
        flowStartTime = packet.getTimeStamp();
        flowLastSeen = packet.getTimeStamp();
        startActiveTime = packet.getTimeStamp();
        endActiveTime = packet.getTimeStamp();
        // Assuming PktStats is an accumulator now
        PktStats(packet.getPayloadBytes());

        if (src.empty()) {
            src = packet.getSrc(); // Ensure this is a deep copy or appropriate reference handling
            srcPort = packet.getSrcPort();
        }
        if (dst.empty()) {
            dst = packet.getDst(); // Ensure this is a deep copy or appropriate reference handling
            dstPort = packet.getDstPort();
        }
        if (src == packet.getSrc()) {
            min_seg_size_forward = packet.getHeaderBytes();
            Init_Win_bytes_forward = packet.getTCPWindow();
            // Assuming fwdPktStats is an accumulator now
            fwdPktStats(packet.getPayloadBytes());
            fHeaderBytes = packet.getHeaderBytes();
            forwardLastSeen = packet.getTimeStamp();
            forwardBytes += packet.getPayloadBytes();
            forward.push_back(packet);
            if (packet.hasFlagPSH()) {
                fPSH_cnt++;
            }
            if (packet.hasFlagURG()) {
                fURG_cnt++;
            }
        } else {
            Init_Win_bytes_backward = packet.getTCPWindow();
            // Assuming bwdPktStats is an accumulator now
            bwdPktStats(packet.getPayloadBytes());
            bHeaderBytes = packet.getHeaderBytes();
            backwardLastSeen = packet.getTimeStamp();
            backwardBytes += packet.getPayloadBytes();
            backward.push_back(packet);
            if (packet.hasFlagPSH()) {
                bPSH_cnt++;
            }
            if (packet.hasFlagURG()) {
                bURG_cnt++;
            }
        }
        protocol = packet.getProtocol();
        flowId = ip2str(src) + "-" + ip2str(dst) + "-" + std::to_string(srcPort) + "-" + std::to_string(dstPort) + "-" + std::to_string(protocol);;
    }

    std::string getFlowId() const {
        return flowId;
    }

    void addPacket(BasicPacketInfo& packet) {
        updateFlowBulk(packet);
        detectUpdateSubflows(packet);
        checkFlags(packet);
        int64_t currentTimestamp = packet.getTimeStamp();
        if (isBidirectional) {
            // Assuming PktStats is an accumulator now
            PktStats(packet.getPayloadBytes());

            if (src == packet.getSrc()) {
                if (packet.getPayloadBytes() >= 1) {
                    Act_data_pkt_forward++;
                }
                // Assuming fwdPktStats is an accumulator now
                fwdPktStats(packet.getPayloadBytes());
                fHeaderBytes += packet.getHeaderBytes();
                forward.push_back(packet);
                forwardBytes += packet.getPayloadBytes();
                if (forward.size() > 1) {
                    // Assuming forwardIAT is an accumulator now
                    forwardIAT(currentTimestamp - forwardLastSeen);
                }
                forwardLastSeen = currentTimestamp;
                min_seg_size_forward = std::min(packet.getHeaderBytes(), min_seg_size_forward);
            } else {
                // Assuming bwdPktStats is an accumulator now
                bwdPktStats(packet.getPayloadBytes());
                Init_Win_bytes_backward = packet.getTCPWindow();
                bHeaderBytes += packet.getHeaderBytes();
                backward.push_back(packet);
                backwardBytes += packet.getPayloadBytes();
                if (backward.size() > 1) {
                    // Assuming backwardIAT is an accumulator now
                    backwardIAT(currentTimestamp - backwardLastSeen);
                }
                backwardLastSeen = currentTimestamp;
            }
        } else {
            if (packet.getPayloadBytes() >= 1) {
                Act_data_pkt_forward++;
            }
            // Assuming fwdPktStats is an accumulator now
            fwdPktStats(packet.getPayloadBytes());
            // Assuming PktStats is an accumulator now
            PktStats(packet.getPayloadBytes());
            fHeaderBytes += packet.getHeaderBytes();
            forward.push_back(packet);
            forwardBytes += packet.getPayloadBytes();
            // Assuming forwardIAT is an accumulator now
            forwardIAT(currentTimestamp - forwardLastSeen);
            forwardLastSeen = currentTimestamp;
            min_seg_size_forward = std::min(packet.getHeaderBytes(), min_seg_size_forward);
        }

        flowIAT(packet.getTimeStamp() - flowLastSeen);
        flowLastSeen = packet.getTimeStamp();
    }



    void checkFlags(BasicPacketInfo& packet) {
        if (packet.hasFlagFIN()) {
            flagCounts["FIN"]++;
        }
        if (packet.hasFlagSYN()) {
            flagCounts["SYN"]++;
        }
        if (packet.hasFlagRST()) {
            flagCounts["RST"]++;
        }
        if (packet.hasFlagPSH()) {
            flagCounts["PSH"]++;
        }
        if (packet.hasFlagACK()) {
            flagCounts["ACK"]++;
        }
        if (packet.hasFlagURG()) {
            flagCounts["URG"]++;
        }
        if (packet.hasFlagCWR()) {
            flagCounts["CWR"]++;
        }
        if (packet.hasFlagECE()) {
            flagCounts["ECE"]++;
        }
    }


    void detectUpdateSubflows(BasicPacketInfo& packet) {
        if (sfLastPacketTS == -1) {
            sfLastPacketTS = packet.getTimeStamp();
            sfAcHelper = packet.getTimeStamp();
        }

        // Commented out the print statement, equivalent to //System.out.print(" - "+(packet.timeStamp - sfLastPacketTS));
        if ((packet.getTimeStamp() - sfLastPacketTS) / static_cast<double>(1000000) > 1.0) {
            sfCount++;
            updateActiveIdleTime(packet.getTimeStamp() - sfLastPacketTS, activityTimeout);
            sfAcHelper = packet.getTimeStamp();
        }

        sfLastPacketTS = packet.getTimeStamp();
    }


    void updateFlowBulk(BasicPacketInfo& packet) {
        if (src == packet.getSrc()) {
            updateForwardBulk(packet, blastBulkTS);
        } else {
            updateBackwardBulk(packet, flastBulkTS);
        }
    }


    // Public members and methods (to be defined...)
    void updateForwardBulk(BasicPacketInfo& packet, int64_t tsOflastBulkInOther) {
        int64_t size = packet.getPayloadBytes();
        if (tsOflastBulkInOther > fbulkStartHelper) {
            fbulkStartHelper = 0;
        }
        if (size <= 0) {
            return;
        }

        packet.getPayloadPacket(); // Assuming this method is for side effects as it's not used here.

        if (fbulkStartHelper == 0) {
            fbulkStartHelper = packet.getTimeStamp();
            fbulkPacketCountHelper = 1;
            fbulkSizeHelper = size;
            flastBulkTS = packet.getTimeStamp();
        } else {
            // Too much idle time?
            if ((static_cast<double>(packet.getTimeStamp() - flastBulkTS) / 1000000) > 1.0) {
                fbulkStartHelper = packet.getTimeStamp();
                flastBulkTS = packet.getTimeStamp();
                fbulkPacketCountHelper = 1;
                fbulkSizeHelper = size;
            } else {
                // Add to bulk
                fbulkPacketCountHelper += 1;
                fbulkSizeHelper += size;
                
                // New bulk
                if (fbulkPacketCountHelper == 4) {
                    fbulkStateCount += 1;
                    fbulkPacketCount += fbulkPacketCountHelper;
                    fbulkSizeTotal += fbulkSizeHelper;
                    fbulkDuration += packet.getTimeStamp() - fbulkStartHelper;
                } else if (fbulkPacketCountHelper > 4) { // Continuation of existing bulk
                    fbulkPacketCount += 1;
                    fbulkSizeTotal += size;
                    fbulkDuration += packet.getTimeStamp() - flastBulkTS;
                }
                flastBulkTS = packet.getTimeStamp();
            }
        }
    }

    void updateBackwardBulk(BasicPacketInfo& packet, int64_t tsOflastBulkInOther) {
        int64_t size = packet.getPayloadBytes();
        if (tsOflastBulkInOther > bbulkStartHelper) {
            bbulkStartHelper = 0;
        }
        if (size <= 0) {
            return;
        }

        packet.getPayloadPacket(); // Assuming this method is for side effects, as in the previous method.

        if (bbulkStartHelper == 0) {
            bbulkStartHelper = packet.getTimeStamp();
            bbulkPacketCountHelper = 1;
            bbulkSizeHelper = size;
            blastBulkTS = packet.getTimeStamp();
        } else {
            // Too much idle time?
            if ((static_cast<double>(packet.getTimeStamp() - blastBulkTS) / 1000000) > 1.0) {
                bbulkStartHelper = packet.getTimeStamp();
                blastBulkTS = packet.getTimeStamp();
                bbulkPacketCountHelper = 1;
                bbulkSizeHelper = size;
            } else {
                // Add to bulk
                bbulkPacketCountHelper += 1;
                bbulkSizeHelper += size;
                
                // New bulk
                if (bbulkPacketCountHelper == 4) {
                    bbulkStateCount += 1;
                    bbulkPacketCount += bbulkPacketCountHelper;
                    bbulkSizeTotal += bbulkSizeHelper;
                    bbulkDuration += packet.getTimeStamp() - bbulkStartHelper;
                } else if (bbulkPacketCountHelper > 4) { // Continuation of existing bulk
                    bbulkPacketCount += 1;
                    bbulkSizeTotal += size;
                    bbulkDuration += packet.getTimeStamp() - blastBulkTS;
                }
                blastBulkTS = packet.getTimeStamp();
            }
        }
    }

    double getfPktsPerSecond() {
        int64_t duration = flowLastSeen - flowStartTime;
        if (duration > 0) {
            return (static_cast<double>(forward.size()) / (duration / 1000000.0));
        } else {
            return 0.0;
        }
    }

    int packetCount() {
        if (isBidirectional) {
            return (forward.size() + backward.size());
        } else {
            return forward.size();
        }
    }


    double getbPktsPerSecond() {
        int64_t duration = flowLastSeen - flowStartTime;
        if (duration > 0) {
            return (static_cast<double>(backward.size()) / (duration / 1000000.0));
        } else {
            return 0.0;
        }
    }

    double getDownUpRatio() {
        if (forward.size() > 0) {
            return static_cast<double>(backward.size()) / forward.size();
        }
        return 0.0;
    }

    double getAvgPacketSize() {
        auto count = packetCount();
        if (count > 0) {
            return boost::accumulators::extract::sum(PktStats) / static_cast<double>(count);
        }
        return 0.0;
    }

    double fAvgSegmentSize() {
        if (!forward.empty()) {
            return boost::accumulators::extract::sum(fwdPktStats) / static_cast<double>(forward.size());
        }
        return 0.0;
    }

    double bAvgSegmentSize() {
        if (!backward.empty()) {
            return boost::accumulators::extract::sum(bwdPktStats) / static_cast<double>(backward.size());
        }
        return 0.0;
    }
//---
    int64_t getSflow_fbytes() {
        if (sfCount <= 0) return 0;
        return forwardBytes / sfCount;
    }

    int64_t getSflow_fpackets() {
        if (sfCount <= 0) return 0;
        return forward.size() / sfCount;
    }

    int64_t getSflow_bbytes() {
        if (sfCount <= 0) return 0;
        return backwardBytes / sfCount;
    }

    int64_t getSflow_bpackets() {
        if (sfCount <= 0) return 0;
        return backward.size() / sfCount;
    }

    double fbulkDurationInSecond() {
        return fbulkDuration / static_cast<double>(1000000);
    }

    int64_t fAvgBytesPerBulk() {
        if (fbulkStateCount != 0) {
            return fbulkSizeTotal / fbulkStateCount;
        }
        return 0;
    }

    int64_t bAvgBytesPerBulk() {
        if (bbulkStateCount != 0) {
            return bbulkSizeTotal / bbulkStateCount;
        }
        return 0;
    }

    

    int64_t fAvgPacketsPerBulk() {
        if (fbulkStateCount != 0) {
            return fbulkPacketCount / fbulkStateCount;
        }
        return 0;
    }

    int64_t fAvgBulkRate() {
        if (fbulkDuration != 0) {
            return static_cast<int64_t>(fbulkSizeTotal / fbulkDurationInSecond());
        }
        return 0;
    }


    double bbulkDurationInSecond() {
        return bbulkDuration / static_cast<double>(1000000);
    }

    int64_t bAvgPacketsPerBulk() {
        if (bbulkStateCount != 0) {
            return bbulkPacketCount / bbulkStateCount;
        }
        return 0;
    }

    int64_t bAvgBulkRate() {
        if (bbulkDuration != 0) {
            return static_cast<int64_t>(bbulkSizeTotal / bbulkDurationInSecond());
        }
        return 0;
    }

    void updateActiveIdleTime(int64_t currentTime, int64_t threshold) {
        if ((currentTime - endActiveTime) > threshold) {
            if ((endActiveTime - startActiveTime) > 0) {
                // Assuming flowActive is a Boost accumulator or similar structure
                flowActive(endActiveTime - startActiveTime);
            }
            // Assuming flowIdle is a Boost accumulator or similar structure
            flowIdle(currentTime - endActiveTime);
            startActiveTime = currentTime;
            endActiveTime = currentTime;
        } else {
            endActiveTime = currentTime;
        }
    }

    std::vector<uint8_t> getSrc() {
        return src;  // Assuming src is a std::vector<uint8_t>
    }

    std::vector<uint8_t> getDst() {
        return dst;  // Assuming dst is a std::vector<uint8_t>
    }

    int getSrcPort() {
        return srcPort;
    }

    int getDstPort() {
        return dstPort;
    }

    int getProtocol() {
        return protocol;
    }

    int64_t getFlowStartTime() {
        return flowStartTime;
    }

    int64_t getFlowDuration() const {
        return flowLastSeen - flowStartTime;
    }

    std::string dumpFlowBasedFeaturesEx() const {
        std::ostringstream stream;

        stream << "Flow Features:" << std::endl;
        stream << "Forward Bytes: " << forwardBytes << std::endl;
        stream << "Backward Bytes: " << backwardBytes << std::endl;
        stream << "Flow Duration: " << getFlowDuration() << std::endl;
        stream << "Number of Forward Packets: " << forward.size() << std::endl;
        stream << "Number of Backward Packets: " << backward.size() << std::endl;

        // 添加更多你感兴趣的字段...
        
        return stream.str();
    }

};

// Initialize static member
const std::string BasicFlow::separator = ",";
