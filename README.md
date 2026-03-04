## Installation

Install dependencies:

```bash
pip install cryptography
```

## Usage

### Initialize CA

```bash
python3 secureseal.py init-ca --pki-dir pki
```

### Create users

```bash
python3 secureseal.py new-user --pki-dir pki --cn Sanjana --password sanjanapass --out-dir users
python3 secureseal.py new-user --pki-dir pki --cn Arbind --password arbindpass --out-dir users
```

### Seal a file

```bash
python3 secureseal.py seal --pki-dir pki \
--sender users/Sanjana.p12 --sender-pass sanjanapass \
--recipient users/Arbind.p12 --recipient-pass arbindpass \
--infile report.txt --outfile sealed.json
```

### Open sealed package

```bash
python3 secureseal.py open --pki-dir pki \
--recipient users/Arbind.p12 --recipient-pass arbindpass \
--package sealed.json --outfile opened.txt --replay-db replay.db
```  
## Security Features

- AES-256-GCM for authenticated encryption
- RSA-OAEP for key wrapping
- RSA-PSS for digital signatures
- SHA-256 hashing for integrity
- PKI certificate validation
- Replay protection using SQLite doc_id tracking
