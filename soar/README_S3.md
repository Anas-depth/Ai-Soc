# Module SOAR & Dashboard KPI — Semaine 3 (AEGIS Entropy / SOC-IA)

## 1. Architecture Globale du Pipeline
1. **Extraction / Ingestion Réseau** : Capture et extraction des 15 flux réseaux via CICFlowMeter en écoute sur l'interface active.
2. **Scoring par Autoencodeur (FastAPI)** : Ingestion par `POST http://localhost:8000/score`. Détection des déviations avec le seuil critique MSE fixé à `0.2512`.
3. **Orchestration & Enrichissement CTI (n8n)** :
   - Webhook récepteur : `POST http://localhost:5678/webhook/soc-ia-alert`.
   - Enrichissement externe : AbuseIPDB (Score de réputation IP) et VirusTotal (Analyse IoC).
   - Filtrage conditionnel (Nœud IF) : Acheminement immédiat des sévérités `HIGH` et `MEDIUM` vers le salon Discord `#soc-alerts`.
4. **Stockage & Indexation (OpenSearch / Wazuh)** : Sauvegarde intégrale des flux d'alertes enrichis dans l'index `soc-ia-alerts`.
5. **Supervision & KPIs (Grafana)** :
   - Source de données : `grafana-opensearch-datasource` (port 9200).
   - Dashboard opérationnel à 4 panels : Volumétrie par sévérité, Suivi temporel, Top IPs malveillantes, et KPI Stat dynamique (Score max).

## 2. Format des Événements Indexés (Index OpenSearch `soc-ia-alerts`)
```json
{
  "src_ip": "185.220.101.5",
  "anomaly_score": 0.850,
  "severity": "HIGH",
  "abuse_score": 100,
  "timestamp": "2026-08-21T13:55:00Z"
}
