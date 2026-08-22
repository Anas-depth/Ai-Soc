# Métadonnées des Figures - Semaine 3 (Dashboard KPI)

## Fichier : grafana_kpi_dashboard_s3.png
- **Source d'origine** : Dashboard.png
- **Titre suggéré** : Dashboard de Supervision Opérationnelle et KPIs SOC-IA (Grafana)
- **Section du rapport visée** : Chapitre 4 / Section 4.4 (Étape 4.4 : Visualisation & KPIs SOAR)
- **Description technique détaillée des 4 panels** :
  1. **Volumétrie des alertes par sévérité** (Bar chart en haut à gauche) : Affiche 2 alertes critiques catégorisées HIGH (en rouge).
  2. **Score d'anomalie moyen dans le temps** (Time series en haut à droite) : Suivi chronologique de l'évolution du score moyen d'anomalie issu de l'autoencodeur.
  3. **Top IPs Suspectes Détectées** (Tableau en bas à gauche) : Journalisation filtrée des alertes avec horodatage, score (0.850), sévérité (HIGH) et adresse IP source attaquante (185.220.101.5 - nœud de sortie Tor).
  4. **Dernier Score d'Anomalie Détecté** (Stat KPI en bas à droite) : Affichage dynamique à 0.850 en rouge vif, traduisant le dépassement net du seuil critique de décision fixé à 0.2512.
- **Rôle dans l'argumentation** : Valide l'aboutissement du livrable Jour 4 de la Semaine 3 en démontrant l'interconnexion complète de la chaîne de détection (FastAPI -> n8n -> OpenSearch -> Grafana).

## Fichier : n8n_soar_workflow.png
- **Titre suggéré** : Architecture et chaîne d'orchestration SOAR sous n8n (Semaine 3)
- **Section du rapport visée** : Chapitre 4 / Section 4.3 (Orchestration SOAR & Enrichissement CTI)
- **Description technique des nœuds** :
  1. *Webhook (soc-ia-alert)* : Réception asynchrone des alertes de l'API de scoring.
  2. *Check AbuseIPDB & Check VirusTotal* : Enrichissement Threat Intelligence en parallèle sur l'adresse IP source.
  3. *Merge / Format Alert* : Consolidation des attributs (scores de réputation, contexte réseau, score IA).
  4. *Conditionnel IF & Discord Webhook* : Routage des alertes de sévérité HIGH et MEDIUM vers le salon opérationnel #soc-alerts.
  5. *Indexation OpenSearch* : Envoi systématique du document JSON vers l'index soc-ia-alerts sur le port 9200.
