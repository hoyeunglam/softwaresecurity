import cryptography

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding


def encrypt():
    with open("signer@cs-hva.nl.pub", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

        vote = open('vote.state', 'rb')
        data = vote.read()
        encrypted = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        f = open('vote.state', 'wb')
        f.write(encrypted)
        f.close()
        return encrypted


def decrypt():
    with open("signer@cs-hva.nl.prv", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

        f = open('vote.state', 'rb')
        encrypted = f.read()
        dectext = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        f = open('vote.state', 'wb')
        f.write(dectext)
        f.close()
        return dectext









