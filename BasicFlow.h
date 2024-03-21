#pragma once

#include <vector>
#include <unordered_map>
#include <string>
#include <cstdint> // for std::uint8_t
#include "BasicPacketInfo.h" // Include your translated BasicPacketInfo class

#include <boost/accumulators/accumulators.hpp>
#include <boost/accumulators/statistics/stats.hpp>
#include <boost/accumulators/statistics/mean.hpp>
#include <boost/accumulators/statistics/variance.hpp>
#include <boost/accumulators/statistics/min.hpp>
#include <boost/accumulators/statistics/max.hpp>

using namespace boost::accumulators;

class BasicFlow {
private:
    static const std::string separator;
    accumulator_set<double, stats<tag::mean, tag::variance, tag::min, tag::max, tag::sum>> fwdPktStats;
    accumulator_set<double, stats<tag::mean, tag::variance, tag::min, tag::max, tag::sum>> bwdPktStats;
    
    std::vector<BasicPacketInfo> forward;
    std::vector<BasicPacketInfo> backward;

    long forwardBytes;
    long backwardBytes;
    long fHeaderBytes;
    long bHeaderBytes;

    bool isBidirectional;

    std::unordered_map<std::string, int> flagCounts; // MutableInt is simplified to int

    int fPSH_cnt;
    int bPSH_cnt;
    int fURG_cnt;
    int bURG_cnt;
    int fFIN_cnt;
	int bFIN_cnt;

    long Act_data_pkt_forward;
    long min_seg_size_forward;
    int Init_Win_bytes_forward = 0;
    int Init_Win_bytes_backward = 0;

    std::vector<uint8_t> src;
    std::vector<uint8_t> dst;
    int srcPort;
    int dstPort;
    int protocol;
    long flowStartTime;
    long startActiveTime;
    long endActiveTime;
    std::string flowId;

    accumulator_set<double, stats<tag::mean, tag::variance, tag::min, tag::max, tag::sum>> flowIAT;
    accumulator_set<double, stats<tag::mean, tag::variance, tag::min, tag::max, tag::sum>> forwardIAT;
    accumulator_set<double, stats<tag::mean, tag::variance, tag::min, tag::max, tag::sum>> backwardIAT;
    accumulator_set<double, stats<tag::mean, tag::variance, tag::min, tag::max, tag::sum>> flowLengthStats;
    accumulator_set<double, stats<tag::mean, tag::variance, tag::min, tag::max, tag::sum>> flowActive;
    accumulator_set<double, stats<tag::mean, tag::variance, tag::min, tag::max, tag::sum>> flowIdle;

    long flowLastSeen;
    long forwardLastSeen;
    long backwardLastSeen;

    long fbulkDuration = 0;
    long fbulkPacketCount = 0;
    long fbulkSizeTotal = 0;
    long fbulkStateCount = 0;
    long fbulkPacketCountHelper = 0;
    long fbulkStartHelper = 0;
    long fbulkSizeHelper = 0;
    long flastBulkTS = 0;
    long bbulkDuration = 0;
    long bbulkPacketCount = 0;
    long bbulkSizeTotal = 0;
    long bbulkStateCount = 0;
    long bbulkPacketCountHelper = 0;
    long bbulkStartHelper = 0;
    long bbulkSizeHelper = 0;
    long blastBulkTS = 0;

    long sfLastPacketTS = -1;
    int sfCount = 0;
    long sfAcHelper = -1;
public:
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
        flowLengthStats = {};

        flagCounts.clear();
        initFlags(); // You need to define this function based on how you want to initialize flags.

        forwardBytes = 0L;
        backwardBytes = 0L;
        startActiveTime = 0L;
        endActiveTime = 0L;
        src.clear();
        dst.clear();
        fPSH_cnt = 0;
        bPSH_cnt = 0;
        fURG_cnt = 0;
        bURG_cnt = 0;
        fFIN_cnt = 0;
        bFIN_cnt = 0;
        fHeaderBytes = 0L;
        bHeaderBytes = 0L;
    }

public:
    BasicFlow(){}
    BasicFlow(bool isBidirectional, BasicPacketInfo packet, std::vector<uint8_t> flowSrc, std::vector<uint8_t> flowDst, int flowSrcPort, int flowDstPort) {
        initParameters();
        this->isBidirectional = isBidirectional;
        firstPacket(packet); // You need to define this function based on how you handle the first packet.
        src = std::move(flowSrc);
        dst = std::move(flowDst);
        srcPort = flowSrcPort;
        dstPort = flowDstPort;
    }

    BasicFlow(bool isBidirectional, BasicPacketInfo packet) {
        initParameters();
        this->isBidirectional = isBidirectional;
        firstPacket(packet); // Define this function as well.
    }

    BasicFlow(BasicPacketInfo packet) {
        initParameters();
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
        // Assuming flowLengthStats is an accumulator now
        flowLengthStats(packet.getPayloadBytes());

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
        flowId = packet.getFlowId();
    }

    void addPacket(BasicPacketInfo& packet) {
        updateFlowBulk(packet);
        detectUpdateSubflows(packet);
        checkFlags(packet);
        __u64 currentTimestamp = packet.getTimeStamp();
        if (isBidirectional) {
            // Assuming flowLengthStats is an accumulator now
            flowLengthStats(packet.getPayloadBytes());

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
            // Assuming flowLengthStats is an accumulator now
            flowLengthStats(packet.getPayloadBytes());
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
            updateActiveIdleTime(packet.getTimeStamp() - sfLastPacketTS, 5000000L);
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
    void updateForwardBulk(BasicPacketInfo& packet, long tsOflastBulkInOther) {
        long size = packet.getPayloadBytes();
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

    void updateBackwardBulk(BasicPacketInfo& packet, long tsOflastBulkInOther) {
        long size = packet.getPayloadBytes();
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
        long duration = flowLastSeen - flowStartTime;
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
        long duration = flowLastSeen - flowStartTime;
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
            return boost::accumulators::extract::sum(flowLengthStats) / static_cast<double>(count);
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
    long getSflow_fbytes() {
        if (sfCount <= 0) return 0;
        return forwardBytes / sfCount;
    }

    long getSflow_fpackets() {
        if (sfCount <= 0) return 0;
        return forward.size() / sfCount;
    }

    long getSflow_bbytes() {
        if (sfCount <= 0) return 0;
        return backwardBytes / sfCount;
    }

    long getSflow_bpackets() {
        if (sfCount <= 0) return 0;
        return backward.size() / sfCount;
    }

    double fbulkDurationInSecond() {
        return fbulkDuration / static_cast<double>(1000000);
    }

    long fAvgBytesPerBulk() {
        if (fbulkStateCount != 0) {
            return fbulkSizeTotal / fbulkStateCount;
        }
        return 0;
    }

    long fAvgPacketsPerBulk() {
        if (fbulkStateCount != 0) {
            return fbulkPacketCount / fbulkStateCount;
        }
        return 0;
    }

    long fAvgBulkRate() {
        if (fbulkDuration != 0) {
            return static_cast<long>(fbulkSizeTotal / fbulkDurationInSecond());
        }
        return 0;
    }


    double bbulkDurationInSecond() {
        return bbulkDuration / static_cast<double>(1000000);
    }

    long bAvgPacketsPerBulk() {
        if (bbulkStateCount != 0) {
            return bbulkPacketCount / bbulkStateCount;
        }
        return 0;
    }

    long bAvgBulkRate() {
        if (bbulkDuration != 0) {
            return static_cast<long>(bbulkSizeTotal / bbulkDurationInSecond());
        }
        return 0;
    }

    void updateActiveIdleTime(long currentTime, long threshold) {
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

    __u64 getFlowStartTime() {
        return flowStartTime;
    }

    __u64 getFlowDuration() const {
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
    
    std::cout<<stream.str()<<std::endl;
    std::cout<<"-------------------------------"<<std::endl;

    // 添加更多你感兴趣的字段...
    
    return stream.str();
    }

};

// Initialize static member
const std::string BasicFlow::separator = ",";
