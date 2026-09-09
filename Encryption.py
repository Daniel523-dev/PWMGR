from cryptography.hazmat.primitives.serialization import load_der_private_key, load_der_public_key, load_pem_private_key, load_pem_public_key, Encoding, PrivateFormat, PublicFormat, NoEncryption, BestAvailableEncryption
from cryptography.x509 import NameAttribute, Name, load_der_x509_certificate, CertificateBuilder, random_serial_number, BasicConstraints, load_pem_x509_certificate,DNSName,SubjectAlternativeName
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519, ec
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
import os, hashlib, hmac, ipaddress
KDF_LEVELS={0:[2,32768,4],1:[3,81920,4],2:[4,131072,3],3:[5,180224,3],4:[6,229376,3],5:[8,278528,2],6:[9,327680,2],7:[10,376832,2],8:[11,425984,2],9:[12,475136,1],10:[13,524288,1]}
def kdf_level(LEVEL):
    if LEVEL in KDF_LEVELS:return KDF_LEVELS[LEVEL]
    if not isinstance(LEVEL,int) or isinstance(LEVEL,bool) or LEVEL < 0:raise ValueError("LEVEL must be a non-negative integer")
    return LEVEL + 2 + (1 if LEVEL >= 5 else 0), 32768 + LEVEL * 49152, max(1, 4 - ((LEVEL + 2) // 4))
# print(kdf_level(42))
def kdf_fast(master_pw: bytes, salt: bytes) -> bytes:return kdf(master_pw,salt,0)
def kdf_slow(master_pw: bytes, salt: bytes) -> bytes:return kdf(master_pw,salt,10)
def kdf(master_pw,salt,level=5):
    lvl=kdf_level(level)
    return hash_secret_raw(secret=master_pw, salt=salt, time_cost=lvl[0], memory_cost=lvl[1], parallelism=lvl[2], hash_len=512, type=Type.ID)
def encrypt(data: bytes, key: bytes) -> bytes:
    salt = os.urandom(32)
    iv = os.urandom(16)
    ct=bytearray(iv + salt)
    cipher=Cipher(algorithms.AES(hashlib.sha3_256(key + salt).digest()), modes.CTR(iv), backend=default_backend()).encryptor()
    _hash = hashlib.sha3_256(data).digest()
    data = memoryview(data)
    l=len(data)
    ct.extend(cipher.update(_hash))
    i=0
    while i<l:
        j=i+32768
        ct.extend(cipher.update(data[i:j]))
        i=j
    return bytes(ct)
def decrypt(encrypted: bytes, key: bytes) -> bytes:
    cipher=Cipher(algorithms.AES(hashlib.sha3_256(key + encrypted[16:48]).digest()), modes.CTR(encrypted[:16]), backend=default_backend()).decryptor()
    encrypted = memoryview(encrypted)
    l=len(encrypted)
    data=cipher.update(encrypted[48:32816])
    _hash=data[:32]
    payload=data[32:]
    out=bytearray(payload)
    hasher=hashlib.sha3_256(payload)
    i=32816
    while i<l:
        j=i+32768
        data=cipher.update(encrypted[i:j])
        out.extend(data)
        hasher.update(data)
        i=j
    out=bytes(out)
    if hmac.compare_digest(_hash,hasher.digest()):return out
def encryptGCM(data: bytes, key: bytes) -> bytes:
    salt = os.urandom(32)
    iv = os.urandom(12)
    enc_key = hashlib.sha3_256(key + salt).digest()
    cipher = Cipher(algorithms.AES(enc_key), modes.GCM(iv), backend=default_backend()).encryptor()
    ct = bytearray()
    ct.extend(iv)
    ct.extend(salt)
    mv = memoryview(data)
    i = 0
    while i < len(mv):
        j = i + 32768
        ct.extend(cipher.update(mv[i:j]))
        i = j
    ct.extend(cipher.finalize())
    ct.extend(cipher.tag)
    return bytes(ct)
def decryptGCM(encrypted: bytes, key: bytes) -> bytes:
    iv = encrypted[:12]
    salt = encrypted[12:44]
    tag = encrypted[-16:]
    ciphertext = encrypted[44:-16]
    enc_key = hashlib.sha3_256(key + salt).digest()
    cipher = Cipher(algorithms.AES(enc_key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    mv = memoryview(ciphertext)
    i = 0
    out = bytearray()
    while i < len(mv):
        j = i + 32768
        out.extend(cipher.update(mv[i:j]))
        i = j
    out.extend(cipher.finalize())
    return bytes(out)
def generate_tls(cert_path, key_path, common_name="TLS Certificate", country=None, state=None, locality=None, organization=None, organizational_unit=None, email=None, valid_days=3650, san_ips=None, san_dns=None):
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return

    san_ips = [] if san_ips is None else san_ips
    san_dns = [] if san_dns is None else san_dns

    key = ec.generate_private_key(ec.SECP256R1())

    attributes = [
        NameAttribute(oid, value)
        for oid, value in [
            (NameOID.COMMON_NAME, common_name),
            (NameOID.COUNTRY_NAME, country),
            (NameOID.STATE_OR_PROVINCE_NAME, state),
            (NameOID.LOCALITY_NAME, locality),
            (NameOID.ORGANIZATION_NAME, organization),
            (NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit),
            (NameOID.EMAIL_ADDRESS, email)
        ]
        if value
    ]

    subject = Name(attributes)

    san_entries = (
        [ipaddress.IPAddress(ipaddress.ip_address(ip)) for ip in san_ips] +
        [DNSName(dns) for dns in san_dns]
    )

    cert = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=valid_days))
        .add_extension(
            BasicConstraints(
                ca=False,
                path_length=None
            ),
            critical=True
        )
    )

    if san_entries:
        cert = cert.add_extension(
            SubjectAlternativeName(san_entries),
            critical=False
        )

    cert = cert.sign(
        private_key=key,
        algorithm=hashes.SHA256()
    )

    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                Encoding.PEM,
                PrivateFormat.PKCS8,
                NoEncryption()
            )
        )

    with open(cert_path, "wb") as f:
        f.write(
            cert.public_bytes(
                Encoding.PEM
            )
        )
def gen_x25519() -> tuple[bytes, bytes]:
    private_key = x25519.X25519PrivateKey.generate()
    return (private_key.private_bytes(encoding=Encoding.Raw,format=PrivateFormat.Raw,encryption_algorithm=NoEncryption()),private_key.public_key().public_bytes(encoding=Encoding.Raw,format=PublicFormat.Raw))
def shared_secret(prv: bytes, pub: bytes) -> bytes:return x25519.X25519PrivateKey.from_private_bytes(prv).exchange(x25519.X25519PublicKey.from_public_bytes(pub))
def gen_ed25519() -> tuple[bytes, bytes]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    return (private_key.private_bytes(encoding=Encoding.Raw,format=PrivateFormat.Raw,encryption_algorithm=NoEncryption()),private_key.public_key().public_bytes(encoding=Encoding.Raw,format=PublicFormat.Raw))
def ed25519_sign(prv: bytes, data: bytes) -> bytes:return load_keys(prv,type=1).sign(data) + data
def ed25519_verify(pub: bytes, data: bytes) -> bool:load_keys(pub,type=2).verify(data[:64], data[64:]);return data[64:]
def gen_CA(prv_path,pub_path,cert_path,password=None, common_name=None, country=None, state=None, locality=None, organization=None, organizational_unit=None, email=None, valid_days=3650):
    prv = ed25519.Ed25519PrivateKey.generate()
    pub = prv.public_key()
    name_attributes = []
    if common_name: name_attributes.append(NameAttribute(NameOID.COMMON_NAME, common_name))
    if country: name_attributes.append(NameAttribute(NameOID.COUNTRY_NAME, country))
    if state: name_attributes.append(NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
    if locality: name_attributes.append(NameAttribute(NameOID.LOCALITY_NAME, locality))
    if organization: name_attributes.append(NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    if organizational_unit: name_attributes.append(NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit))
    if email: name_attributes.append(NameAttribute(NameOID.EMAIL_ADDRESS, email))
    subject = Name(name_attributes)
    if password:
        with open(prv_path,'wb') as f:f.write(prv.private_bytes(encoding=Encoding.PEM if prv_path.lower().endswith('.pem') else Encoding.DER,format=PrivateFormat.PKCS8,encryption_algorithm=BestAvailableEncryption(password)))
    else:
        with open(prv_path,'wb') as f:f.write(prv.private_bytes(encoding=Encoding.PEM if prv_path.lower().endswith('.pem') else Encoding.DER,format=PrivateFormat.PKCS8,encryption_algorithm=NoEncryption()))
    with open(pub_path,'wb') as f:f.write(pub.public_bytes(encoding=Encoding.PEM if pub_path.lower().endswith('.pem') else Encoding.DER,format=PublicFormat.SubjectPublicKeyInfo))
    with open(cert_path,'wb') as f:f.write(CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(pub).serial_number(random_serial_number()).not_valid_before(datetime.now(timezone.utc) - timedelta(days=1)).not_valid_after(datetime.now(timezone.utc) + timedelta(days=valid_days)).add_extension(BasicConstraints(ca=True, path_length=None), critical=True).sign(private_key=prv, algorithm=None).public_bytes(Encoding.PEM if cert_path.lower().endswith('.pem') else Encoding.DER))
def gen_keys(prv_path,pub_path,cert_path,ca_prv_path,ca_cert_path,password=None,ca_password=None,common_name=None,country=None,state=None,locality=None,organization=None,organizational_unit=None,email=None,valid_days=3650):
    with open(ca_prv_path,'rb') as f:ca_priv = load_der_private_key(f.read(),password=ca_password)
    with open(ca_cert_path,'rb') as f:ca_cert = load_der_x509_certificate(f.read())
    prv = ed25519.Ed25519PrivateKey.generate()
    pub = prv.public_key()
    name_attributes = []
    if common_name: name_attributes.append(NameAttribute(NameOID.COMMON_NAME, common_name))
    if country: name_attributes.append(NameAttribute(NameOID.COUNTRY_NAME, country))
    if state: name_attributes.append(NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
    if locality: name_attributes.append(NameAttribute(NameOID.LOCALITY_NAME, locality))
    if organization: name_attributes.append(NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    if organizational_unit: name_attributes.append(NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit))
    if email: name_attributes.append(NameAttribute(NameOID.EMAIL_ADDRESS, email))
    if password:
        with open(prv_path,'wb') as f:f.write(prv.private_bytes(encoding=Encoding.DER,format=PrivateFormat.PKCS8,encryption_algorithm=BestAvailableEncryption(password)))
    else:
        with open(prv_path,'wb') as f:f.write(prv.private_bytes(encoding=Encoding.DER,format=PrivateFormat.PKCS8,encryption_algorithm=NoEncryption()))
    with open(pub_path,'wb') as f:f.write(pub.public_bytes(encoding=Encoding.DER,format=PublicFormat.SubjectPublicKeyInfo))
    with open(cert_path,'wb') as f:f.write(CertificateBuilder().subject_name(Name(name_attributes)).issuer_name(ca_cert.subject).public_key(pub).serial_number(random_serial_number()).not_valid_before(datetime.now(timezone.utc) - timedelta(days=1)).not_valid_after(datetime.now(timezone.utc) + timedelta(days=valid_days)).add_extension(BasicConstraints(ca=False, path_length=None), critical=True).sign(private_key=ca_priv, algorithm=None).public_bytes(Encoding.DER))
def validate_keys(prv,pub,cert=None):
    pub_bytes = load_keys(pub,type=2).public_bytes(Encoding.Raw,PublicFormat.Raw)
    if not hmac.compare_digest(load_keys(prv,type=1).public_key().public_bytes(Encoding.Raw,PublicFormat.Raw), pub_bytes):return False
    if cert!=None:
        if not hmac.compare_digest(load_keys(cert,type=3).public_key().public_bytes(Encoding.Raw,PublicFormat.Raw), pub_bytes):return False
    return True
def load_keys(key,password=None,type=0):
    if isinstance(key,str) and os.path.exists(key):
        with open(key,'rb') as f:key=f.read()
    key_strip=key.lstrip() if isinstance(key,bytes) else key
    if isinstance(key,(bytes,bytearray)):
        if key_strip.startswith(b'-----BEGIN'):
            if type in (0,1) and b'PRIVATE KEY' in key_strip:return load_pem_private_key(key,password=password)
            if type in (0,2) and b'PUBLIC KEY' in key_strip:return load_pem_public_key(key)
            if type in (0,3) and b'CERTIFICATE' in key_strip:return load_pem_x509_certificate(key)
        if len(key)==32:
            if type in (0,1):
                try:return ed25519.Ed25519PrivateKey.from_private_bytes(key)
                except:pass
            if type in (0,2):
                try:return ed25519.Ed25519PublicKey.from_public_bytes(key)
                except:pass
        if type in (0,1):
            try:return load_der_private_key(key,password=password)
            except:pass
        if type in (0,2):
            try:return load_der_public_key(key)
            except:pass
        if type in (0,3):
            try:return load_der_x509_certificate(key)
            except:pass
    raise ValueError("Unsupported key format")
