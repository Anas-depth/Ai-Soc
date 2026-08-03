from nids_datasets import Dataset

# UNSW-NB15 - flux réseau
data_unsw = Dataset(dataset='UNSW-NB15', subset='Network-Flows', files='all')
data_unsw.download()

# CIC-IDS2017 - flux réseau
data_cicids = Dataset(dataset='CIC-IDS2017', subset='Network-Flows', files='all')
data_cicids.download()

print("Téléchargement terminé.")
