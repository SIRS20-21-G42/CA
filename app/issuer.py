from cryptography                              import x509
from cryptography.x509.oid                     import NameOID
from cryptography.hazmat.primitives            import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from ipaddress                                 import IPv4Address

from flask import abort, Flask, request

import datetime
import logging
import os
import ssl
import threading

logging.basicConfig(level=logging.DEBUG)

WORK_DIR = "/ca_files"

# Files variables
PATH_PRIVATE = os.path.join(WORK_DIR, "CA/")
PATH_PUBLIC  = os.path.join(WORK_DIR, "PUBLIC/")
PATH_SIGNED  = os.path.join(WORK_DIR, "CERTIFICATES/")

# RSA contants
RSA_KEY_SIZE  = 2048
RSA_PUB_EXP   = 65537
RSA_PASS_VAR  = "CA_PASS"
RSA_PRIV_PATH = os.path.join(PATH_PRIVATE, "priv.key")
RSA_PUB_PATH  = os.path.join(PATH_PUBLIC , "pub.key")
RSA_CERT_PATH = os.path.join(PATH_PUBLIC , "CA.cert")

# CA parameters
CA_COUTRY   = u"PT"
CA_STATE    = u"Lisbon"
CA_LOCALITY = u"Lisbon"
CA_ORG_NAME = u"SIRS LLC"
CA_VALIDITY = 365 # days

SIGNED_VALIDITY = 365 # days

PRIV_KEY: rsa.RSAPrivateKey
CA_CERT: x509.Certificate

CERT_LOCK = threading.Lock()

# Test if running with password
os.environ[RSA_PASS_VAR]

# Check if paths exist
if not os.path.isdir(PATH_PRIVATE):
    os.mkdir(PATH_PRIVATE)
    logging.info("Created folder for server private info")

if not os.path.isdir(PATH_PUBLIC):
    os.mkdir(PATH_PUBLIC)
    logging.info("Created folder for server certificate and public key")

if not os.path.isdir(PATH_SIGNED):
    os.mkdir(PATH_SIGNED)
    logging.info("Created folder for signed certificates")

# Check if keys exist
if not os.path.isfile(RSA_PRIV_PATH):
    # Generate new keys
    logging.info("Private key not found")
    PRIV_KEY = rsa.generate_private_key(public_exponent=RSA_PUB_EXP, key_size=RSA_KEY_SIZE)

    with open(RSA_PRIV_PATH, "wb") as f:
        f.write(PRIV_KEY.private_bytes(encoding=serialization.Encoding.PEM,
                                       format=serialization.PrivateFormat.PKCS8,
                                       encryption_algorithm=serialization.BestAvailableEncryption(os.environ[RSA_PASS_VAR].encode())))

    logging.info("New private key generated")
else:
    # Load private key
    with open(RSA_PRIV_PATH, "rb") as f:
        PRIV_KEY = serialization.load_pem_private_key(f.read(),
                                                      password=os.environ[RSA_PASS_VAR].encode())

    logging.info("Private key loaded")

if not os.path.isfile(RSA_PUB_PATH):
    # Save public key
    with open(RSA_PUB_PATH, "wb") as f:
        f.write(PRIV_KEY.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                   format=serialization.PublicFormat.SubjectPublicKeyInfo))

    logging.info("Public key exported")

if not os.path.isfile(RSA_CERT_PATH):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, CA_COUTRY),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, CA_STATE),
        x509.NameAttribute(NameOID.LOCALITY_NAME, CA_LOCALITY),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, CA_ORG_NAME),
    ])

    logging.info("Creating CA Certificate")

    # Self-sign certificate
    # Allow to sign certificates with this certificate (and those signed by this cannot sign others)
    CA_CERT = x509.CertificateBuilder() \
                  .subject_name(subject) \
                  .issuer_name(issuer) \
                  .public_key(PRIV_KEY.public_key()) \
                  .serial_number(x509.random_serial_number()) \
                  .not_valid_before(datetime.datetime.utcnow()) \
                  .not_valid_after(datetime.datetime.utcnow() + \
                                   datetime.timedelta(days=CA_VALIDITY)) \
                  .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True) \
                  .add_extension(x509.SubjectAlternativeName([x509.DNSName("ca"),
                                                              x509.IPAddress(IPv4Address("10.45.0.5"))]), critical=True) \
                  .sign(PRIV_KEY, hashes.SHA256())

    # Save certificate
    with open(RSA_CERT_PATH, "wb") as f:
        f.write(CA_CERT.public_bytes(serialization.Encoding.PEM))

    logging.info("CA Certificate exported")
else:
    # Load certificate
    with open(RSA_CERT_PATH, "rb") as f:
        CA_CERT = x509.load_pem_x509_certificate(f.read())

    logging.info("CA Certificate loaded")

context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain(certfile=RSA_CERT_PATH, keyfile=RSA_PRIV_PATH, password=os.environ[RSA_PASS_VAR])

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024

@app.route("/sign", methods=["POST"])
def sign_cert():
    """
    csr - PEM-format Certificate Signing Request
    Needs to have the field Organization Name filled
    """

    if not request.files.get(key="csr"):
        abort(400)

    try:
        csr = x509.load_pem_x509_csr(request.files["csr"].stream.read())
    except ValueError:
        logging.info("Invalid CSR")
        abort(415)

    # Check if has organization name
    org = csr.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
    if org is None:
        abort(415)

    # Sign
    cert = x509.CertificateBuilder() \
               .subject_name(csr.subject) \
               .issuer_name(CA_CERT.subject) \
               .public_key(csr.public_key()) \
               .serial_number(x509.random_serial_number()) \
               .not_valid_before(datetime.datetime.utcnow()) \
               .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=SIGNED_VALIDITY)) \
               .sign(PRIV_KEY, hashes.SHA256())

    # Easier to sign (expensive operation) more certificates and then discard them than
    # to sign only one at a time due to possible colisions
    output = b""
    with CERT_LOCK:
        # Check if there isn't another issued certificate for same organization
        path = os.path.join(PATH_SIGNED, org + ".cert")
        if os.path.isfile(path):
            abort(409)

        # Save certificate
        output = cert.public_bytes(serialization.Encoding.PEM)
        with open(path, "wb") as f:
            f.write(output)

    return output.decode("ascii")

@app.route("/CACert", methods=["GET"])
def get_cacert():
    """
    Get the CA Certificate
    """
    return CA_CERT.public_bytes(serialization.Encoding.PEM).decode("ascii")

@app.route("/cert/<org>", methods=["GET"])
def get_cert(org):
    """
    Get an organization's certificate
    org - the name of the organization
    """
    try:
        output: x509.Certificate
        with open(os.path.join(PATH_SIGNED, org + ".cert"), "rb") as f:
            output = x509.load_pem_x509_certificate(f.read())

        return output.public_bytes(serialization.Encoding.PEM).decode("ascii")
    except OSError:
        abort(404)

app.run(host="0.0.0.0", ssl_context=context, use_reloader=False)
