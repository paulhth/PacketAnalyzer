# PacketAnalyzer

This repository contains scripts to extract basic packet features from PCAP files and train a simple model.

Minimum steps to set up the development environment (macOS / zsh):

1. Create and activate a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Upgrade pip and install Python dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

3. Install tshark (required by `pyshark`)

macOS (Homebrew):

```bash
brew install wireshark
# If you only want the command-line tool (tshark), Homebrew's wireshark formula includes it.
```

Linux (Debian/Ubuntu):

```bash
sudo apt update
sudo apt install -y tshark
```

Notes: `pyshark` is a wrapper around tshark; make sure `tshark` is available in your PATH. You may need to grant appropriate permissions to capture packets or run `tshark`.

4. Run the scripts

- Extract basic features from `data/raw_pcaps/traffic_sample.pcapng` to `data/datasets/basic_packet_features.csv`:

```bash
python src/extract_basic_features.py
```

- Train a model from a prepared dataset (expects `data/datasets/prepared_packet_features.csv`):

```bash
python src/train_model.py
```

If you want to keep raw PCAPs out of the repository (recommended), they are ignored by `.gitignore`.

If you accidentally staged a virtual environment directory before adding `.gitignore`, unstage it and remove it from the index:

```bash
# replace .venv and venv with whatever directory you used
git rm -r --cached .venv venv || true
git add .gitignore requirements.txt README.md
git commit -m "Add .gitignore, requirements and README; stop tracking virtualenvs"
```

Optional: Use Git LFS for large PCAPs

```bash
brew install git-lfs
git lfs install
git lfs track "*.pcap" "*.pcapng"
git add .gitattributes
```

