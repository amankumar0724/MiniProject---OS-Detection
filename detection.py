import pandas as pd
import numpy as np
import warnings
import psutil
from scapy.all import *
from scapy.layers.inet import TCP
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import LabelEncoder
import pyshark
from sklearn.ensemble import RandomForestClassifier

dataset_path = 'dataset.xlsx'

data = pd.read_excel(dataset_path)
data.dropna(inplace=True)

warnings.filterwarnings("ignore")

data['IP_Flags'] = data['IP_Flags'].apply(lambda flag: int(flag, 16))
data['TCP_Flags'] = data['TCP_Flags'].apply(lambda flag: int(flag, 16))

os_encoder = LabelEncoder()
data['OS'] = os_encoder.fit_transform(data['OS'])

features = data.drop(columns=['OS', 'Minor_Version'])
labels = data['OS']

X_train, X_test, y_train, y_test = train_test_split(features, labels, test_size=0.25, random_state=42)

rf_model = RandomForestClassifier(random_state=42)
rf_model.fit(X_train, y_train)
y_predicted = rf_model.predict(X_test)


def get_closest_minor_version(os_class, feature_row, dataset):
    feature_row = np.array(feature_row, dtype=float)

    subset = dataset[dataset['OS'] == os_class]
    feature_cols = ['TTL', 'IP_Flags', 'TCP_Flags', 'Acknowledgment_Number',
                    'Sequence_Number', 'Window_Size', 'Data_Offset', 'Packet_Length']

    subset['IP_Flags'] = subset['IP_Flags'].apply(lambda f: int(f, 16) if isinstance(f, str) else f)
    subset['TCP_Flags'] = subset['TCP_Flags'].apply(lambda f: int(f, 16) if isinstance(f, str) else f)

    subset_features = subset[feature_cols].values
    distances = np.linalg.norm(subset_features - feature_row, axis=1)
    closest_idx = distances.argmin()

    return subset.iloc[closest_idx]['Minor_Version']


network_iface = "Wi-Fi"
live_capture = pyshark.LiveCapture(interface=network_iface)

print("=" * 100)
print("Live OS fingerprinting started. Press Ctrl+C to terminate.")
print("=" * 100)

ip_classification = {}

for pkt_id, packet in enumerate(live_capture):
    if 'IP' in packet and 'TCP' in packet:
        try:
            ip_src = packet.ip.src if hasattr(packet, 'ip') else 'N/A'
            if ip_src in ip_classification:
                continue

            ip_flag_val = int(packet.ip.flags, 16) if packet.ip.flags else 0
            tcp_flag_val = int(packet.tcp.flags, 16) if packet.tcp.flags else 0
            pkt_len = packet.length if hasattr(packet, 'length') else 0
            ttl_val = packet.ip.ttl if hasattr(packet.ip, 'ttl') else 0
            ack_num = packet.tcp.ack if hasattr(packet.tcp, 'ack') else 0
            tcp_offset = packet.tcp.dataofs if hasattr(packet.tcp, 'dataofs') else 0
            win_size = packet.tcp.window if hasattr(packet.tcp, 'window') else 0
            seq_num = packet.tcp.seq if hasattr(packet.tcp, 'seq') else 0

            observed_features = [ttl_val, ip_flag_val, tcp_flag_val, ack_num,
                                 seq_num, win_size, tcp_offset, pkt_len]

            sample_df = pd.DataFrame([observed_features], columns=X_train.columns)

            predicted_os_code = rf_model.predict(sample_df)[0]
            predicted_os_name = os_encoder.inverse_transform([predicted_os_code])[0]
            estimated_minor = get_closest_minor_version(predicted_os_code, observed_features, data)

            ip_classification[ip_src] = predicted_os_name

            print(f"Source IP: {ip_src}, Detected OS: {predicted_os_name}, Minor Version: {estimated_minor}")

        except Exception as err:
            print(f"Packet parsing error: {err}")

