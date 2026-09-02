# AI-Enhanced Open-Source Mini-SOC

## 1. Introduction and Context
This project was carried out as part of an initiation engineering internship (Networks and Telecommunications Systems Engineering - GRST) at ENSA Kenitra, hosted by **YLUNOR** in Casablanca, Morocco. 

The objective was to design and implement a lightweight, resource-constrained (single 16GB RAM workstation, 100% remote work), open-source **Security Operations Center (SOC)** enhanced with an **Artificial Intelligence (AI)** module for behavioral threat detection (UEBA).

---

## 2. Global Architecture & Technology Stack
The architecture relies on standard open-source tools optimized to run within strict hardware limitations:
* **Host Environment:** Ubuntu LTS, Docker & Docker Compose.
* **Network & Collection:** Suricata (NIDS)[cite: 1] and Wazuh (SIEM/XDR)[cite: 1].
* **Feature Extraction:** `cicflowmeter` (Python port) ensuring strict statistical fidelity with the CICIDS2017 training dataset[cite: 1, 2].
* **Artificial Intelligence Module:** Dense Autoencoder neural network (15 features, 1,139 parameters) trained in an unsupervised manner on benign traffic, exposed via a **FastAPI** REST service[cite: 1].
* **Orchestration (SOAR):** **n8n** for asynchronous webhook ingestion, parallel CTI enrichment, and conditional alerting[cite: 1, 2].
* **Threat Intelligence:** AbuseIPDB and VirusTotal APIs[cite: 1, 2].
* **Visualization & Monitoring:** Grafana connected directly to the Wazuh OpenSearch indexer, tracking real-time SOC KPIs[cite: 1, 2].
* **Alerting:** Real-time notifications dispatched to a dedicated Discord channel (`#soc-alerts`)[cite: 1, 2].

---

## 3. Project Lifecycle & Sprints Breakdown

### Sprint 1: Scoping and Environment Setup
* State-of-the-art analysis (NIST CSF, MITRE ATT&CK, Zero Trust)[cite: 1].
* Deployment of Wazuh (single-node) and Suricata using Docker Compose.
* Dataset exploration and selection (CICIDS2017)[cite: 1].

### Sprint 2: AI Module & Preprocessing Rigor
* Implementation of an anti-data-leakage preprocessing pipeline (IQR winsorization, log1p transformation with persisted shifts, standardization)[cite: 1].
* Training and selection of the **Autoencoder** model (discarding Isolation Forest due to lower performance)[cite: 1].
* Decision threshold calibration based on a target False Positive Rate (FPR) of 14%, yielding an official MSE threshold of **0.2512**[cite: 1].
* Resolution of a major methodological log1p data leakage bug on closing day[cite: 1].
* Quantitative evaluation achieving **85.01% Recall**, **93.73% Precision**, and **13.95% FPR** (validated over 30 bootstrap iterations)[cite: 1].
* Exposure of the model via FastAPI (`api_scoring.py`)[cite: 1].

### Sprint 3: SOAR Orchestration and Dashboards
* Deployment of n8n and creation of automated workflows (`Webhook -> CTI Enrichment -> Merge -> Conditional IF -> Discord & OpenSearch Indexing`)[cite: 1, 2].
* Design of a 4-panel Grafana KPI dashboard connected to OpenSearch, featuring a dynamic critical red threshold set at **0.2512**[cite: 1, 2].

### Sprint 4: Real-Time Integration & Proof of Concept
* Development of the live network connector (`connector_live.py`) using `cicflowmeter` to prevent data drift[cite: 1, 2].
* Resolution of OpenSearch ISO 8601 timestamp compatibility issues[cite: 1, 2].
* Simulation of an aggressive network attack (Nmap T4 port scan)[cite: 1, 2], captured via `tcpdump` and replayed via `tcpreplay` on the loopback interface[cite: 1, 2].
* **End-to-End Validation:** The pipeline successfully captured, scored (achieving a critical anomaly score of **4.03**), enriched, indexed, and alerted analysts via Discord in just a few seconds (**MTTD $\approx$ seconds**), with an MTTR optimized for automation[cite: 1, 2].

---

## 4. Key Engineering Takeaways & Limitations
* **Methodological Rigor:** Adhering strictly to the anti-data-leakage principle and matching the CICIDS2017 feature extraction logic via `cicflowmeter`[cite: 1, 2].
* **Resource Optimization:** Successfully running a full enterprise-grade security stack locally under 16GB RAM constraints[cite: 1, 2].
* **Acknowledged Limitations:** Near-zero margin on Recall (0.01 pt above the 85% target), heterogeneity of detection across attack types (high volume vs. subtle attacks), and manual handling of inference bounds[cite: 1].

## 5. Repository Structure
* `ia-module/` : Core AI models, preprocessing scripts, FastAPI service, and evaluation notebooks[cite: 1].
* `soar/` : n8n configurations and live network connectors[cite: 2].
* `Rapport/` : Complete LaTeX documentation and PoC evidence[cite: 1, 2].
