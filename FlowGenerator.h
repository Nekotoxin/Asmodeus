#pragma once

#include <unordered_map>
#include <vector>
#include <string>
#include <memory>
#include "BasicFlow.h"  // Include the definition of BasicFlow

#include <mutex>
#include "onnxruntime_cxx_api.h"

class FlowGenerator {
public:
    Ort::Env env;
    std::unique_ptr<Ort::Session> session; // 使用智能指针
    std::mutex ort_mtx; // 用于同步访问session的互斥锁

    std::unordered_map<std::string, BasicFlow> currentFlows;
    std::unordered_map<std::string, BasicFlow> finishedFlows;
    std::unordered_map<std::string, std::vector<std::string>> IPAddresses;  // Assuming string representation for IPs

    bool bidirectional;
    int64_t flowTimeOut;
    int64_t flowActivityTimeOut;

    FlowGenerator(bool bidirectional, int64_t flowTimeout, int64_t activityTimeout)
        : bidirectional(bidirectional), flowTimeOut(flowTimeout), flowActivityTimeOut(activityTimeout) {
        init();
        Ort::Env local_env(ORT_LOGGING_LEVEL_WARNING, "FlowGenerator");
        env = std::move(local_env);
        Ort::SessionOptions session_options;
        const char* modelPath = "models/xgb_model.onnx";

        try {
            auto local_session = std::make_unique<Ort::Session>(env, modelPath, session_options);
            session = std::move(local_session);
        } catch (const Ort::Exception& exception) {
            std::cerr << "Failed to create ONNX Runtime session: " << exception.what() << std::endl;
        } catch (const std::exception& ex) {
            std::cerr << "An unknown error occurred: " << ex.what() << std::endl;
        }
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
                    onFlowGenerated(flow);
                }
                currentFlows[id] = BasicFlow(bidirectional, packet, flow.getSrc(), flow.getDst(), flow.getSrcPort(), flow.getDstPort(), flow.activityTimeout);
                std::cout << "Timeout current has " << currentFlows.size() << " flow\n";
            } else if (packet.hasFlagFIN()) {
                if (flow.getSrc() == packet.getSrc()) {
                    // forward
                    if(flow.setFwdFINFlags() >= 1){
                        if (flow.getFwdFINFlags() >= 1 && flow.getBwdFINFlags() >= 1) {
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
    			// Forward Flow and fwdFIN = 0
    			if ((flow.getSrc() == packet.getSrc()) && (flow.getFwdFINFlags() == 0)) {
        			flow.updateActiveIdleTime(currentTimestamp,flowActivityTimeOut);
        			flow.addPacket(packet);
        			currentFlows[id] = flow;
    			// Backward Flow and bwdFIN = 0			
    			} else if (flow.getBwdFINFlags() == 0) {
        			flow.updateActiveIdleTime(currentTimestamp,flowActivityTimeOut);
        			flow.addPacket(packet);
        			currentFlows[id] = flow;
        		// FLOW already closed!!!
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


    void onFlowGenerated(BasicFlow& flow) { 
        // flow close, generated data
        std::lock_guard<std::mutex> guard(ort_mtx);
        if (!session) return;
        std::vector<float> input_tensor_values = flow.dump();

        std::vector<int64_t> input_node_dims = {1, static_cast<int64_t>(input_tensor_values.size())}; // 假设batch size为1
        std::vector<const char*> input_node_names = {"input"};

        std::vector<const char*> output_node_names = {"output_label", "output_probability"};
        Ort::MemoryInfo memory_info = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
        // create input tensor
        Ort::Value input_tensor = Ort::Value::CreateTensor<float>(memory_info, input_tensor_values.data(), input_tensor_values.size(), input_node_dims.data(), input_node_dims.size());

        // inference
        auto output_tensors = session->Run(Ort::RunOptions{nullptr}, input_node_names.data(), &input_tensor, 1, output_node_names.data(), output_node_names.size());

        // handle output
        if (!output_tensors.empty()) {
            auto& output_tensor = output_tensors.front();
            int64_t* arr = output_tensor.GetTensorMutableData<int64_t>();
            int pred=arr[0];
            // if(pred!=0){
                std::cout<<flow.getFlowId()<<" generated, ";
                std::cout<<"predict result: "<<flow.flowFeature.pred_labels[pred]<<std::endl;
            // }
        }

        
    }
};
