import pandas as pd
import requests
import json
import datetime

col_mapping = {
    "dst_port": "Destination Port", "flow_duration": "Flow Duration",
    "tot_fwd_pkts": "Total Fwd Packets", "totlen_fwd_pkts": "Total Length of Fwd Packets",
    "flow_iat_mean": "Flow IAT Mean", "syn_flag_cnt": "SYN Flag Count",
    "rst_flag_cnt": "RST Flag Count", "ack_flag_cnt": "ACK Flag Count",
    "fin_flag_cnt": "FIN Flag Count", "psh_flag_cnt": "PSH Flag Count",
    "flow_byts_s": "Flow Bytes/s", "flow_pkts_s": "Flow Packets/s",
    "init_fwd_win_byts": "Init_Win_bytes_forward", "init_bwd_win_byts": "Init_Win_bytes_backward",
    "pkt_len_std": "Packet Length Std"
}

df = pd.read_csv('datasets/attack_offline.csv')
row = df.iloc[0]

raw_cols = list(col_mapping.keys())
payload_features = [float(row[c]) for c in raw_cols]

print("1. Envoi à l'API SOC-IA...")
ia_url = "http://127.0.0.1:8000/score"
ia_response = requests.post(ia_url, json={"features": payload_features}).json()

print(f"Score obtenu : {ia_response['anomaly_score']} ({ia_response['severity']})")

if ia_response.get('is_anomaly'):
    print("\n2. Anomalie détectée ! Déclenchement du pipeline SOAR (n8n)...")
    n8n_url = "http://localhost:5678/webhook/soc-ia-alert"
    
    # Génération du timestamp exact pour OpenSearch
    current_timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    
    alert_payload = {
        "src_ip": str(row.get('src_ip', '127.0.0.1')), 
        "anomaly_score": ia_response['anomaly_score'],
        "severity": ia_response['severity'],
        "features": payload_features,
        "timestamp": current_timestamp
    }
    
    try:
        n8n_response = requests.post(n8n_url, json=alert_payload)
        print("Alerte envoyée avec succès à n8n !")
    except Exception as e:
        print(f"Erreur de connexion à n8n : {e}")
