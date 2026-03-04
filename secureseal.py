#!/usr/bin/env python3
"""
SecureSeal - PKI-based document sealing tool (PKI + Sign + Hybrid Encrypt + Replay protection)

Commands:
init-ca
new-user
revoke
seal
open

Example flow:
python3 [secureseal.py](http://secureseal.py/) init-ca --pki-dir pki
python3 [secureseal.py](http://secureseal.py/) new-user --pki-dir pki --cn Sanjana --password sanjanapass --out-dir users
python3 [secureseal.py](http://secureseal.py/) new-user --pki-dir pki --cn Arbind  --password arbindpass  --out-dir users
echo "secret" > report.txt
python3 [secureseal.py](http://secureseal.py/) seal --pki-dir pki --sender users/Sanjana.p12 --sender-pass sanjanapass \
--recipient users/Arbind.p12 --recipient-pass arbindpass --infile report.txt --outfile sealed.json
python3 [secureseal.py](http://secureseal.py/) open --pki-dir pki --recipient users/Arbind.p12 --recipient-pass arbindpass \
--package sealed.json --outfile opened.txt --replay-db replay.db
"""

import argparse
import base64
import json
import os
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

UTC = timezone.utc

def b64e(b: bytes) -> str:
return base64.b64encode(b).decode("utf-8")

def b64d(s: str) -> bytes:
return base64.b64decode(s.encode("utf-8"))

def canonical_json(obj) -> bytes:
return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def sha256(data: bytes) -> bytes:
h = hashes.Hash(hashes.SHA256())
h.update(data)
return h.finalize()

def utc_now_iso() -> str:
return datetime.now(UTC).isoformat()

def gen_rsa(bits: int = 3072) -> rsa.RSAPrivateKey:
return rsa.generate_private_key(public_exponent=65537, key_size=bits)

def name(cn: str, org: str = "SecureSeal") -> [x509.Name](http://x509.name/):
return [x509.Name](http://x509.name/)([
x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
x509.NameAttribute(NameOID.COMMON_NAME, cn),
])

@dataclass
class ReplayDB:
path: str

```
def init(self) -> None:
    with sqlite3.connect(self.path) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS seen (
                doc_id TEXT PRIMARY KEY,
                seen_at TEXT NOT NULL
            )
        """)

def is_replay(self, doc_id: str) -> bool:
    with sqlite3.connect(self.path) as con:
        cur = con.execute("SELECT 1 FROM seen WHERE doc_id=?", (doc_id,))
        return cur.fetchone() is not None

def mark_seen(self, doc_id: str) -> None:
    with sqlite3.connect(self.path) as con:
        con.execute(
            "INSERT OR REPLACE INTO seen(doc_id, seen_at) VALUES(?, ?)",
            (doc_id, utc_now_iso()),
        )

@staticmethod
def validate_timestamp(ts_iso: str, max_age_minutes: int = 10) -> None:
    ts = datetime.fromisoformat(ts_iso)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    now = datetime.now(UTC)

    if ts > now + timedelta(minutes=2):
        raise ValueError("Timestamp is in the future (clock skew too large).")
    if now - ts > timedelta(minutes=max_age_minutes):
        raise ValueError("Timestamp too old; possible replay.")
```

@dataclass
class CA:
key: rsa.RSAPrivateKey
cert: x509.Certificate
revoked_serials: set[int]

```
def save(self, pki_dir: str) -> None:
    os.makedirs(pki_dir, exist_ok=True)
    with open(os.path.join(pki_dir, "ca_key.pem"), "wb") as f:
        f.write(self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
    with open(os.path.join(pki_dir, "ca_cert.pem"), "wb") as f:
        f.write(self.cert.public_bytes(serialization.Encoding.PEM))

    with open(os.path.join(pki_dir, "revoked_serials.txt"), "w", encoding="utf-8") as f:
        for s in sorted(self.revoked_serials):
            f.write(f"{s}\\n")

@staticmethod
def load(pki_dir: str) -> "CA":
    with open(os.path.join(pki_dir, "ca_key.pem"), "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    with open(os.path.join(pki_dir, "ca_cert.pem"), "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())

    revoked = set()
    rp = os.path.join(pki_dir, "revoked_serials.txt")
    if os.path.exists(rp):
        with open(rp, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    revoked.add(int(line))
    return CA(key=key, cert=cert, revoked_serials=revoked)
```

def create_root_ca(valid_days: int = 3650) -> CA:
key = gen_rsa()
now = datetime.now(UTC)

```
cert = (
    x509.CertificateBuilder()
    .subject_name(name("SecureSeal Root CA"))
    .issuer_name(name("SecureSeal Root CA"))
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - timedelta(minutes=5))
    .not_valid_after(now + timedelta(days=valid_days))
    .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
    .add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    .sign(key, hashes.SHA256())
)
return CA(key=key, cert=cert, revoked_serials=set())
```

def issue_user(ca: CA, cn: str, valid_days: int = 825) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
key = gen_rsa()
now = datetime.now(UTC)

```
cert = (
    x509.CertificateBuilder()
    .subject_name(name(cn))
    .issuer_name(ca.cert.subject)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - timedelta(minutes=5))
    .not_valid_after(now + timedelta(days=valid_days))
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,     # RSA-OAEP key wrap
            content_commitment=True,   # signing intent
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    .sign(ca.key, hashes.SHA256())
)
return key, cert
```

def save_pkcs12(path: str, key, cert, password: str, friendly_name: str) -> None:
p12 = pkcs12.serialize_key_and_certificates(
name=friendly_name.encode("utf-8"),
key=key,
cert=cert,
cas=None,
encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
)
with open(path, "wb") as f:
f.write(p12)

def load_pkcs12(path: str, password: str):
with open(path, "rb") as f:
key, cert, _cas = pkcs12.load_key_and_certificates(f.read(), password.encode("utf-8"))
if key is None or cert is None:
raise ValueError("PKCS#12 missing key or cert.")
return key, cert

def verify_leaf_with_ca(ca_cert: x509.Certificate, leaf_cert: x509.Certificate, revoked: set[int]) -> None:
now = datetime.now(UTC)

```
if leaf_cert.serial_number in revoked:
    raise ValueError("Certificate is revoked.")

if now < leaf_cert.not_valid_before.replace(tzinfo=UTC) or now > leaf_cert.not_valid_after.replace(tzinfo=UTC):
    raise ValueError("Leaf certificate not valid at this time.")

if leaf_cert.issuer != ca_cert.subject:
    raise ValueError("Leaf issuer does not match trusted CA.")

ca_cert.public_key().verify(
    leaf_cert.signature,
    leaf_cert.tbs_certificate_bytes,
    padding.PKCS1v15(),
    leaf_cert.signature_hash_algorithm,
)
```

def sign_structure(sender_priv, structure: dict) -> str:
msg = canonical_json(structure)
sig = sender_priv.sign(
msg,
padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
hashes.SHA256(),
)
return b64e(sig)

def verify_signature(sender_pub, structure: dict, sig_b64: str) -> None:
msg = canonical_json(structure)
sig = b64d(sig_b64)
sender_pub.verify(
sig,
msg,
padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
hashes.SHA256(),
)

def aes_gcm_encrypt(aes_key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
nonce = os.urandom(12)
ct = AESGCM(aes_key).encrypt(nonce, plaintext, aad)
return nonce, ct

def aes_gcm_decrypt(aes_key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
return AESGCM(aes_key).decrypt(nonce, ciphertext, aad)

def rsa_wrap(pub, data: bytes) -> bytes:
return pub.encrypt(
data,
padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
)

def rsa_unwrap(priv, wrapped: bytes) -> bytes:
return priv.decrypt(
wrapped,
padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
)

def seal_file(infile: str, sender_p12: str, sender_pass: str, recipient_p12: str, recipient_pass: str, ca: CA) -> dict:
sender_key, sender_cert = load_pkcs12(sender_p12, sender_pass)
recipient_key, recipient_cert = load_pkcs12(recipient_p12, recipient_pass)

```
with open(infile, "rb") as f:
    data = f.read()

meta = {
    "doc_id": str(uuid.uuid4()),
    "timestamp": utc_now_iso(),
    "infile": os.path.basename(infile),
    "sender_subject": sender_cert.subject.rfc4514_string(),
    "recipient_subject": recipient_cert.subject.rfc4514_string(),
}

doc_hash = b64e(sha256(data))
signed_structure = {"metadata": meta, "doc_hash_b64": doc_hash}
sig_b64 = sign_structure(sender_key, signed_structure)

aes_key = os.urandom(32)  # AES-256
aad = canonical_json(meta)
nonce, ciphertext = aes_gcm_encrypt(aes_key, data, aad=aad)
wrapped_key = rsa_wrap(recipient_cert.public_key(), aes_key)

package = {
    "version": "1.0",
    "metadata": meta,
    "crypto": {
        "hash": "SHA-256",
        "signature": "RSA-PSS-SHA256",
        "encryption": "AES-256-GCM",
        "key_wrap": "RSA-OAEP-SHA256",
    },
    "encrypted": {
        "nonce_b64": b64e(nonce),
        "ciphertext_b64": b64e(ciphertext),
        "wrapped_key_b64": b64e(wrapped_key),
    },
    "signature": {
        "signed_structure": signed_structure,
        "signature_b64": sig_b64,
    },
    "certs": {
        "sender_cert_pem": sender_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        "recipient_cert_pem": recipient_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
        "ca_cert_pem": ca.cert.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
    },
}
return package
```

def open_package(package_path: str, outfile: str, recipient_p12: str, recipient_pass: str, ca: CA,
replay_db_path: str, max_age_minutes: int = 10) -> None:
recipient_key, recipient_cert = load_pkcs12(recipient_p12, recipient_pass)

```
with open(package_path, "r", encoding="utf-8") as f:
    pkg = json.load(f)

ca_in_pkg = x509.load_pem_x509_certificate(pkg["certs"]["ca_cert_pem"].encode("utf-8"))
if ca_in_pkg.fingerprint(hashes.SHA256()) != ca.cert.fingerprint(hashes.SHA256()):
    raise ValueError("Untrusted CA in package (possible MITM).")

sender_cert = x509.load_pem_x509_certificate(pkg["certs"]["sender_cert_pem"].encode("utf-8"))
recipient_cert_in_pkg = x509.load_pem_x509_certificate(pkg["certs"]["recipient_cert_pem"].encode("utf-8"))

verify_leaf_with_ca(ca.cert, sender_cert, ca.revoked_serials)
verify_leaf_with_ca(ca.cert, recipient_cert_in_pkg, ca.revoked_serials)

if recipient_cert.serial_number != recipient_cert_in_pkg.serial_number:
    raise ValueError("Recipient certificate mismatch (not intended for this user).")

meta = pkg["metadata"]
ReplayDB.validate_timestamp(meta["timestamp"], max_age_minutes=max_age_minutes)

rdb = ReplayDB(replay_db_path)
rdb.init()
if rdb.is_replay(meta["doc_id"]):
    raise ValueError("Replay detected: doc_id already processed.")

signed_structure = pkg["signature"]["signed_structure"]
verify_signature(sender_cert.public_key(), signed_structure, pkg["signature"]["signature_b64"])

wrapped_key = b64d(pkg["encrypted"]["wrapped_key_b64"])
aes_key = rsa_unwrap(recipient_key, wrapped_key)

nonce = b64d(pkg["encrypted"]["nonce_b64"])
ciphertext = b64d(pkg["encrypted"]["ciphertext_b64"])
aad = canonical_json(meta)
plaintext = aes_gcm_decrypt(aes_key, nonce, ciphertext, aad=aad)

expected_hash_b64 = signed_structure["doc_hash_b64"]
actual_hash_b64 = b64e(sha256(plaintext))
if actual_hash_b64 != expected_hash_b64:
    raise ValueError("Integrity failure: hash mismatch after decryption.")

rdb.mark_seen(meta["doc_id"])

with open(outfile, "wb") as f:
    f.write(plaintext)
```

def cmd_init_ca(args):
ca = create_root_ca()
ca.save(args.pki_dir)
print(f"[OK] CA created in: {args.pki_dir}")

def cmd_new_user(args):
ca = CA.load(args.pki_dir)
key, cert = issue_user(ca, [args.cn](http://args.cn/))
os.makedirs(args.out_dir, exist_ok=True)
p12_path = os.path.join(args.out_dir, f"{[args.cn](http://args.cn/)}.p12")
save_pkcs12(p12_path, key, cert, args.password, [args.cn](http://args.cn/))
print(f"[OK] User created: {[args.cn](http://args.cn/)}")
print(f"     PKCS#12: {p12_path}")

def cmd_revoke(args):
ca = CA.load(args.pki_dir)
# revoke by loading cert from a user's p12
_key, cert = load_pkcs12(args.user_p12, args.user_pass)
ca.revoked_serials.add(cert.serial_number)
ca.save(args.pki_dir)
print(f"[OK] Revoked serial: {cert.serial_number}")

def cmd_seal(args):
ca = CA.load(args.pki_dir)
pkg = seal_file(args.infile, args.sender, args.sender_pass, args.recipient, args.recipient_pass, ca)
with open(args.outfile, "w", encoding="utf-8") as f:
json.dump(pkg, f, indent=2, sort_keys=True)
print(f"[OK] Sealed package: {args.outfile}")
print(f"     doc_id: {pkg['metadata']['doc_id']}")

def cmd_open(args):
ca = CA.load(args.pki_dir)
open_package(args.package, args.outfile, args.recipient, args.recipient_pass, ca,
replay_db_path=args.replay_db, max_age_minutes=args.max_age_minutes)
print(f"[OK] Opened & verified to: {args.outfile}")

def build_parser():
p = argparse.ArgumentParser(prog="secureseal")
sub = p.add_subparsers(dest="cmd", required=True)

```
a = sub.add_parser("init-ca")
a.add_argument("--pki-dir", default="pki")
a.set_defaults(func=cmd_init_ca)

a = sub.add_parser("new-user")
a.add_argument("--pki-dir", default="pki")
a.add_argument("--cn", required=True, help="Common Name (e.g., Sanjana)")
a.add_argument("--password", required=True, help="Password for PKCS#12 file")
a.add_argument("--out-dir", default="users")
a.set_defaults(func=cmd_new_user)

a = sub.add_parser("revoke")
a.add_argument("--pki-dir", default="pki")
a.add_argument("--user-p12", required=True)
a.add_argument("--user-pass", required=True)
a.set_defaults(func=cmd_revoke)

a = sub.add_parser("seal")
a.add_argument("--pki-dir", default="pki")
a.add_argument("--sender", required=True, help="Sender .p12")
a.add_argument("--sender-pass", required=True)
a.add_argument("--recipient", required=True, help="Recipient .p12")
a.add_argument("--recipient-pass", required=True)
a.add_argument("--infile", required=True)
a.add_argument("--outfile", required=True)
a.set_defaults(func=cmd_seal)

a = sub.add_parser("open")
a.add_argument("--pki-dir", default="pki")
a.add_argument("--recipient", required=True, help="Recipient .p12")
a.add_argument("--recipient-pass", required=True)
a.add_argument("--package", required=True)
a.add_argument("--outfile", required=True)
a.add_argument("--replay-db", default="replay.db")
a.add_argument("--max-age-minutes", type=int, default=10)
a.set_defaults(func=cmd_open)

return p
```

def main():
args = build_parser().parse_args()
args.func(args)

if **name** == "**main**":
main()
