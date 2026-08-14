# Interface d'intégration — Module IA de scoring (S2 → S3)

## Endpoint
POST http://<host>:8000/score

## Format d'entrée attendu
{
  "features": [float, float, ..., float]  // 15 valeurs, ordre strict
}

Ordre exact des features (voir src/config.py -> FEATURES) :
1. Destination Port
2. Flow Duration
3. Total Fwd Packets
4. Total Length of Fwd Packets
5. Flow IAT Mean
6. SYN Flag Count
7. RST Flag Count
8. ACK Flag Count
9. FIN Flag Count
10. PSH Flag Count
11. Flow Bytes/s
12. Flow Packets/s
13. Init_Win_bytes_forward
14. Init_Win_bytes_backward
15. Packet Length Std

## Mapping depuis eve.json (Suricata) / logs Wazuh
À faire en S3 : construire dans n8n (ou un script Python intermédiaire) un mapping
champ eve.json -> feature ci-dessus (ex. flow.pkts_toserver -> Total Fwd Packets,
flow.bytes_toserver -> Total Length of Fwd Packets, etc.). Certains champs Suricata
n'ont pas d'équivalent direct (ex. flags TCP agrégés, Init_Win_bytes) et nécessiteront
soit un calcul dérivé, soit une valeur par défaut documentée.

## Format de sortie
{
  "anomaly_score": float,   // MSE de reconstruction de l'autoencoder
  "threshold": float,       // seuil de décision (0.2512)
  "is_anomaly": bool,
  "severity": "LOW" | "MEDIUM" | "HIGH"
}

## Réinjection du score dans Wazuh (Bloc 3 -> architecture)
En S3 : le score renvoyé par ce endpoint doit être réinjecté soit via l'API REST de
Wazuh (création d'un événement custom dans un index dédié), soit via un fichier de log
local surveillé par un decoder Wazuh personnalisé. Choix à trancher en début de S3
selon la charge RAM disponible et la complexité d'intégration côté Wazuh Manager.

## Limites connues (documentées, issues du Jour 4, corrigées Jour 5)
- Recall global : 85,01 % | Precision : 93,73 % | F1 : 89,15 % | FPR : 13,95 %
  (seuil MSE = 0,2512, recalibré au Jour 5 après correction d'un bug de pipeline
  log1p ; écart négligeable vs les valeurs Jour 4 initiales)
- Marge de sécurité quasi nulle sur le Recall (0,01 pt au-dessus de la cible 85 %)
  -> à surveiller en cas de dérive du trafic réel en S3/S4.
- Recall variable selon le type d'attaque (65,18 % sur DDoS, 96,32 % sur XSS, etc.)
  -> voir logs/jour4_final_threshold_v2.json pour le détail par catégorie.
- Imputation NaN/inf non gérée en inférence : une requête avec une valeur non finie
  est rejetée plutôt qu'imputée (décision Jour 5, cf. limitation méthodologique :
  la médiane d'imputation d'entraînement n'a pas été persistée).
