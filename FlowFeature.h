#include <iostream>
#include <vector>
#include <map>
#include <cmath>
#include <string>

class FlowFeature {
public:
    static const std::vector<std::string> allFeatureNamesVec;
    static const std::vector<std::string> requiredFeatureNamesVec;
    static const std::vector<std::string> pred_labels;

    std::map<std::string, float> featureMap;

    FlowFeature() {
        for (const std::string& featureName : allFeatureNamesVec) {
            featureMap[featureName] = 0.0; // Initialize all features to 0
        }
    }

    std::vector<float> getRequiredFeatures(/* pass your data parameters here */) {
        std::vector<float> featureValues;
        // Example: Retrieve feature values from featureMap
        for (const std::string& featureName : requiredFeatureNamesVec) {
            // Check if the featureName exists in the map
            if (featureMap.find(featureName) != featureMap.end()) {
                // Check for NaN and Inf values
                if (std::isnan(featureMap[featureName]) || std::isinf(featureMap[featureName])) {
                    featureValues.push_back(0.0); // Replace NaN or Inf with 0
                    // std::cout << featureName << ": " << "replaced by 0 due to NaN or Inf" << std::endl;
                } else {
                    // If the value is normal, add it to featureValues
                    featureValues.push_back(featureMap[featureName]);
                    // std::cout << featureName << ": " << featureMap[featureName] << std::endl;
                }
            } else {
                // If not exists, add a placeholder value
                featureValues.push_back(0.0); // Or any default value you prefer
                // std::cout<<featureName<<": "<<"unexisted"<<std::endl;
            }
        }
        return featureValues;
    }


};

const std::vector<std::string> FlowFeature::allFeatureNamesVec = {
    "Destination Port","Flow Duration","Total Fwd Packets","Total Backward Packets","Total Length of Fwd Packets","Total Length of Bwd Packets","Fwd Packet Length Max","Fwd Packet Length Min","Fwd Packet Length Mean","Fwd Packet Length Std","Bwd Packet Length Max","Bwd Packet Length Min","Bwd Packet Length Mean","Bwd Packet Length Std","Flow Bytes/s","Flow Packets/s","Flow IAT Mean","Flow IAT Std","Flow IAT Max","Flow IAT Min","Fwd IAT Total","Fwd IAT Mean","Fwd IAT Std","Fwd IAT Max","Fwd IAT Min","Bwd IAT Total","Bwd IAT Mean","Bwd IAT Std","Bwd IAT Max","Bwd IAT Min","Fwd PSH Flags","Bwd PSH Flags","Fwd URG Flags","Bwd URG Flags","Fwd Header Length","Bwd Header Length","Fwd Packets/s","Bwd Packets/s","Min Packet Length","Max Packet Length","Packet Length Mean","Packet Length Std","Packet Length Variance","FIN Flag Count","SYN Flag Count","RST Flag Count","PSH Flag Count","ACK Flag Count","URG Flag Count","CWE Flag Count","ECE Flag Count","Down/Up Ratio","Average Packet Size","Avg Fwd Segment Size","Avg Bwd Segment Size","Fwd Header Length","Fwd Avg Bytes/Bulk","Fwd Avg Packets/Bulk","Fwd Avg Bulk Rate","Bwd Avg Bytes/Bulk","Bwd Avg Packets/Bulk","Bwd Avg Bulk Rate","Subflow Fwd Packets","Subflow Fwd Bytes","Subflow Bwd Packets","Subflow Bwd Bytes","Init_Win_bytes_forward","Init_Win_bytes_backward","act_data_pkt_fwd","min_seg_size_forward","Active Mean","Active Std","Active Max","Active Min","Idle Mean","Idle Std","Idle Max","Idle Min"
};

const std::vector<std::string> FlowFeature::requiredFeatureNamesVec = {
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Length of Fwd Packets", "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Bwd Packet Length Max", "Bwd Packet Length Min", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Fwd URG Flags", "Fwd Header Length", "Bwd Header Length", "Bwd Packets/s", "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Variance", "FIN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "Down/Up Ratio", "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward", "Active Mean", "Active Std", "Active Max", "Active Min", "Idle Std"
};

// const std::vector<std::string> FlowFeature::pred_labels = {"BENIGN", "Bot", "DDoS", "DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest", "DoS slowloris", "FTP-Patator", "Heartbleed", "Infiltration", "PortScan", "SSH-Patator", "Web Attack"};

const std::vector<std::string> FlowFeature::pred_labels = {"BENIGN","Dos","PortScan"}; // use model trained using data collected by myself