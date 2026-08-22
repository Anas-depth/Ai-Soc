"""
Mapping eve.json (Suricata) -> features attendues par l'API de scoring
Ordre strict conforme à src/config.py -> FEATURES (voir S2, Section 3.12)
"""

# Valeurs par défaut pour les champs Suricata sans équivalent direct
# (documenté dans api_integration.md - à ajuster si besoin en S3)
DEFAULT_VALUES = {
    "syn_flag_count": 0,
    "rst_flag_count": 0,
    "ack_flag_count": 0,
    "fin_flag_count": 0,
    "psh_flag_count": 0,
    "init_win_bytes_forward": -1,
    "init_win_bytes_backward": -1,
    "packet_length_std": 0.0,
}

def extract_features(event: dict) -> list:
    """
    Prend un événement eve.json (type=flow) et retourne
    la liste des 15 features dans l'ordre attendu par l'API.
    """
    flow = event.get("flow", {})

    features = [
        event.get("dest_port", 0),                                  # 1. Destination Port
        flow.get("age", 0) * 1000,                                  # 2. Flow Duration (approx, en ms)
        flow.get("pkts_toserver", 0),                                # 3. Total Fwd Packets
        flow.get("bytes_toserver", 0),                               # 4. Total Length of Fwd Packets
        0.0,                                                         # 5. Flow IAT Mean (à calculer en S3)
        DEFAULT_VALUES["syn_flag_count"],                            # 6. SYN Flag Count
        DEFAULT_VALUES["rst_flag_count"],                            # 7. RST Flag Count
        DEFAULT_VALUES["ack_flag_count"],                            # 8. ACK Flag Count
        DEFAULT_VALUES["fin_flag_count"],                            # 9. FIN Flag Count
        DEFAULT_VALUES["psh_flag_count"],                            # 10. PSH Flag Count
        0.0,                                                         # 11. Flow Bytes/s (à calculer en S3)
        0.0,                                                         # 12. Flow Packets/s (à calculer en S3)
        DEFAULT_VALUES["init_win_bytes_forward"],                    # 13. Init_Win_bytes_forward
        DEFAULT_VALUES["init_win_bytes_backward"],                   # 14. Init_Win_bytes_backward
        DEFAULT_VALUES["packet_length_std"],                         # 15. Packet Length Std
    ]

    return features
