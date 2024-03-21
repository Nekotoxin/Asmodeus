#pragma once

#include <vector>
#include <string>
#include <algorithm> // For std::copy
#include <cstring> // For std::memcpy
#include <sstream>
#include <iomanip>
#include <iostream>

#include "IDGenerator.h"

std::string ip2str(const std::vector<uint8_t>& addr) {
    std::ostringstream stream;
    for (size_t i = 0; i < addr.size(); ++i) {
        stream << (i ? "." : "") << static_cast<int>(addr[i]);
    }
    return stream.str();
}


class BasicPacketInfo {
private:
    long id;
    std::vector<uint8_t> src;
    std::vector<uint8_t> dst;
    int srcPort;
    int dstPort;
    int protocol;
    __u64 timeStamp;
    long payloadBytes;
    std::string flowId;  
    bool flagFIN = false;
    bool flagPSH = false;
    bool flagURG = false;
    bool flagECE = false;
    bool flagSYN = false;
    bool flagACK = false;
    bool flagCWR = false;
    bool flagRST = false;
    int TCPWindow = 0;
    long headerBytes;
    int payloadPacket = 0;

public:
    BasicPacketInfo(const std::vector<uint8_t>& src, const std::vector<uint8_t>& dst, int srcPort, int dstPort,
                    int protocol, __u64 timeStamp, IdGenerator& generator)
        : src(src), dst(dst), srcPort(srcPort), dstPort(dstPort), protocol(protocol), timeStamp(timeStamp) {
        id = generator.nextId();
        generateFlowId();
    }
    
    BasicPacketInfo(IdGenerator& generator) {
        id = generator.nextId();
    }
    
    std::string generateFlowId() {
        bool forward = true;
        
        for(size_t i = 0; i < src.size(); i++) {           
            if(src[i] != dst[i]){
                if(src[i] > dst[i]){
                    forward = false;
                }
                break;
            }
        }
        
        if(forward) {
            flowId = ip2str(src) + "-" + ip2str(dst) + "-" + std::to_string(srcPort) + "-" + std::to_string(dstPort) + "-" + std::to_string(protocol);
        } else {
            flowId = ip2str(dst) + "-" + ip2str(src) + "-" + std::to_string(dstPort) + "-" + std::to_string(srcPort) + "-" + std::to_string(protocol);
        }
        return flowId;
    }

    std::string fwdFlowId() {
        flowId = ip2str(src) + "-" + ip2str(dst) + "-" + std::to_string(srcPort) + "-" + std::to_string(dstPort) + "-" + std::to_string(protocol);
        return flowId;
    }
    
    std::string bwdFlowId() {
        flowId = ip2str(dst) + "-" + ip2str(src) + "-" + std::to_string(dstPort) + "-" + std::to_string(srcPort) + "-" + std::to_string(protocol);
        return flowId;
    }

    std::string getSourceIP() {
        return ip2str(src);
    }

    std::string getDestinationIP() {
        return ip2str(dst);
    }

    // Implement getters and setters for other member variables...

    int getPayloadPacket() {
        return ++payloadPacket;
    }
    
    long getId() const {
        return id;
    }

    void setId(long newId) {
        id = newId;
    }

    std::vector<uint8_t> getSrc() const {
        return src;
    }

    void setSrc(const std::vector<uint8_t>& newSrc) {
        src = newSrc;
    }

    std::vector<uint8_t> getDst() const {
        return dst;
    }

    void setDst(const std::vector<uint8_t>& newDst) {
        dst = newDst;
    }

    int getSrcPort() const {
        return srcPort;
    }

    void setSrcPort(int newSrcPort) {
        srcPort = newSrcPort;
    }

    int getDstPort() const {
        return dstPort;
    }

    void setDstPort(int newDstPort) {
        dstPort = newDstPort;
    }

    int getProtocol() const {
        return protocol;
    }

    void setProtocol(int newProtocol) {
        protocol = newProtocol;
    }

    __u64 getTimeStamp() const {
        return timeStamp;
    }

    void setTimeStamp(__u64 newTimeStamp) {
        timeStamp = newTimeStamp;
    }

    std::string getFlowId() const {
        return flowId.empty() ? const_cast<BasicPacketInfo*>(this)->generateFlowId() : flowId;
    }

    void setFlowId(const std::string& newFlowId) {
        flowId = newFlowId;
    }

    long getPayloadBytes() const {
        return payloadBytes;
    }

    void setPayloadBytes(long newPayloadBytes) {
        payloadBytes = newPayloadBytes;
    }

    long getHeaderBytes() const {
        return headerBytes;
    }

    void setHeaderBytes(long newHeaderBytes) {
        headerBytes = newHeaderBytes;
    }

    // TCP flag getters and setters
    bool hasFlagFIN() const {
        return flagFIN;
    }

    void setFlagFIN(bool newFlagFIN) {
        flagFIN = newFlagFIN;
    }

    bool hasFlagPSH() const {
        return flagPSH;
    }

    void setFlagPSH(bool newFlagPSH) {
        flagPSH = newFlagPSH;
    }

    bool hasFlagURG() const {
        return flagURG;
    }

    void setFlagURG(bool newFlagURG) {
        flagURG = newFlagURG;
    }

    bool hasFlagECE() const {
        return flagECE;
    }

    void setFlagECE(bool newFlagECE) {
        flagECE = newFlagECE;
    }

    bool hasFlagSYN() const {
        return flagSYN;
    }

    void setFlagSYN(bool newFlagSYN) {
        flagSYN = newFlagSYN;
    }

    bool hasFlagACK() const {
        return flagACK;
    }

    void setFlagACK(bool newFlagACK) {
        flagACK = newFlagACK;
    }

    bool hasFlagCWR() const {
        return flagCWR;
    }

    void setFlagCWR(bool newFlagCWR) {
        flagCWR = newFlagCWR;
    }

    bool hasFlagRST() const {
        return flagRST;
    }

    void setFlagRST(bool newFlagRST) {
        flagRST = newFlagRST;
    }

    int getTCPWindow() const {
        return TCPWindow;
    }

    void setTCPWindow(int newTCPWindow) {
        TCPWindow = newTCPWindow;
    }
};
