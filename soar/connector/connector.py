import os
import time
import subprocess
import requests

# Configuration
CSV_FILE = "live_flows.csv"
API_URL = "http://localhost:8000/score"
INTERFACE = "wlo1"

# Les 15 features exactes issues de notre mapping (ordre strict)
FEATURES_ORDER = [
    "dst_port", "flow_duration", "tot_fwd_pkts", "totlen_fwd_pkts", 
    "flow_iat_mean", "syn_flag_cnt", "rst_flag_cnt", "ack_flag_cnt", 
    "fin_flag_cnt", "psh_flag_cnt", "flow_byts_s", "flow_pkts_s", 
    "init_fwd_win_byts", "init_bwd_win_byts", "pkt_len_std"
]

def main():
    print(f"[*] Démarrage du connecteur SOC-IA sur l'interface {INTERFACE}...")
    
    if os.path.exists(CSV_FILE):
        os.remove(CSV_FILE)

    # Préparation de la commande avec sudo et le chemin absolu vers cicflowmeter
    fields_str = ",".join(FEATURES_ORDER)
    cmd = f"sudo /home/anas/Documents/soc-project/ia-module/venv/bin/cicflowmeter -i {INTERFACE} -c {CSV_FILE} --fields {fields_str}"
    
    print(f"[*] Lancement de la capture (sudo requis) : {cmd}")
    # shell=True car on utilise sudo
    process = subprocess.Popen(cmd, shell=True)

    print("[*] En attente de trafic réseau pour analyse...")
    
    last_pos = 0
    try:
        while True:
            if os.path.exists(CSV_FILE):
                with open(CSV_FILE, 'r') as f:
                    f.seek(last_pos)
                    lines = f.readlines()
                    last_pos = f.tell()

                if lines:
                    for line in lines:
                        if "dst_port" in line: 
                            continue # On ignore la ligne d'en-tête
                        
                        values = line.strip().split(',')
                        if len(values) == 15:
                            # Conversion des valeurs en float pour l'API
                            try:
                                features_float = [float(v) for v in values]
                                payload = {"features": features_float}
                                
                                response = requests.post(API_URL, json=payload, timeout=2)
                                result = response.json()
                                score = result.get('anomaly_score', 0)
                                is_anomaly = result.get('is_anomaly', False)
                                
                                if is_anomaly:
                                    print(f"🚨 [ANOMALIE] Score: {score:.4f} | Payload: {payload}")
                                else:
                                    print(f"✅ [Trafic Bénin] Score: {score:.4f}")
                            except Exception as e:
                                print(f"Erreur d'envoi à l'API: {e}")
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n[*] Arrêt du connecteur demandé par l'utilisateur...")
        process.terminate()

if __name__ == "__main__":
    main()
