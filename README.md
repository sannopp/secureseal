## Installation

Install dependencies:

pip install cryptography

## Usage

Initialize CA:

python3 secureseal.py init-ca --pki-dir pki

Create users:

python3 secureseal.py new-user --pki-dir pki --cn Sanjana --password sanjanapass --out-dir users
python3 secureseal.py new-user --pki-dir pki --cn Arbind --password arbindpass --out-dir users

Seal a file:

python3 secureseal.py seal --pki-dir pki --sender users/Sanjana.p12 --sender-pass sanjanapass \
--recipient users/Arbind.p12 --recipient-pass arbindpass --infile report.txt --outfile sealed.json

Open sealed package:

python3 secureseal.py open --pki-dir pki --recipient users/Arbind.p12 --recipient-pass arbindpass \
--package sealed.json --outfile opened.txt --replay-db replay.db
