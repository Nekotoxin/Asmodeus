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
        std::lock_guard<std::mutex> guard(ort_mtx);
        std::cout<<"------------------------------------------------------"<<std::endl;
        if (!session) return;

        // 构造输入Tensor
        std::vector<float> input_tensor_values = flow.dump(); // 假设这些值已经是适当的浮点数格式
        std::vector<int64_t> input_tensor_shape = {1, static_cast<int64_t>(input_tensor_values.size())};
        Ort::MemoryInfo memory_info = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
        Ort::Value input_tensor = Ort::Value::CreateTensor<float>(memory_info, input_tensor_values.data(), input_tensor_values.size(), input_tensor_shape.data(), input_tensor_shape.size());

        // 准备模型的输入和输出节点名称
        const char* input_nodes[] = {"input"};
        const char* output_nodes[] = {"output_label", "output_probability"};

        // 运行模型推理
        auto output_tensors = session->Run(Ort::RunOptions{nullptr}, input_nodes, &input_tensor, 1, output_nodes, 2);

        // 处理输出
        if (!output_tensors.empty()) {
            // 处理output_label
            auto& output_label_tensor = output_tensors[0];
            auto output_label = output_label_tensor.GetTensorMutableData<int64_t>();
            std::cout << "Predicted label: " << flow.flowFeature.pred_labels[*output_label] << std::endl;

            // 处理output_probability
            Ort::Value& output_probability_seq = output_tensors[1];
            size_t num_maps = output_probability_seq.GetCount(); // 获取序列中映射的数量

            for (size_t i = 0; i < num_maps; ++i) {
                Ort::Value map_value = output_probability_seq.GetValue(i, Ort::AllocatorWithDefaultOptions());
                // 从映射中提取键和值
                Ort::Value keys = map_value.GetValue(0, Ort::AllocatorWithDefaultOptions()); // 获取键
                Ort::Value values = map_value.GetValue(1, Ort::AllocatorWithDefaultOptions()); // 获取值

                // 假设键是int64_t类型，值是float类型
                auto keys_data = keys.GetTensorData<int64_t>();
                auto values_data = values.GetTensorData<float>();

                std::cout << "Map " << i << ":" << std::endl;
                for (size_t j = 0; j < keys.GetTensorTypeAndShapeInfo().GetElementCount(); ++j) {
                    std::cout << "Class " << flow.flowFeature.pred_labels[keys_data[j]] << ": Probability " << values_data[j] << std::endl;
                }
            }
        }
    }

};
