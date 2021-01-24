import sys, os
import getopt
import io
import csv
import datetime
import collections
import json


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

gDbg = False
gSigner = "signer@cs-hva.nl"


def private():
    f = open('vote.state', 'w')
    f.write("Private Information")
    f.close()


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
        f = open('vote.state.enc', 'wb')
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

        f = open('vote.state.enc', 'rb')
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


def sign(data, signer=gSigner, sfx='.prv'):
    if isinstance(data, io.StringIO):
        data = data.read()

    if not isinstance(data, bytes):
        data = bytes(data, encoding='utf-8')

    sign = b''
    # Calculate the signature of the data using a prvKey, sha256, pkcs1 en rsa-2048
    # Student Work {{
    with io.open(signer + '.prv', "rb") as fp:  # reads in the private key as fp (read object)
        prvKey = serialization.load_pem_private_key(fp.read(), password=None)  # sets private key as prvKey-
        # (serialization) write key into bytes
    sign = prvKey.sign(  # RSA private key object
        data,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    # Student Work }}

    return ':'.join(['#sign', 'sha256-PKCS1-rsa2048', signer, sign.hex()])


def verify(data, signature, signer=gSigner, sfx='.pub'):
    if isinstance(data, io.StringIO): data = data.read()
    if not isinstance(data, bytes): data = bytes(data, encoding='utf-8')
    flds = signature.split(':')
    if flds[1] != 'sha256-PKCS1-rsa2048' and flds[2] != signer:
        print('Error: Unknown signature:', signature)
        return None
    sign = bytes.fromhex(flds[3])

    res = False
    # Validate the signature of the data using a prvKey, sha256, pkcs1 en rsa-2048
    # Student Work {{
    with io.open(signer + '.pub', "rb") as fp:
        pubKey = serialization.load_pem_public_key(fp.read())
    try:
        sign = bytes.fromhex(flds[3])
        pubKey.verify(
            sign,
            data,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        res = True
    except Exception as e:
        print('Exception', e)
        res = False
    # Student Work }}

    return res


def load_file(fname, useSign=True, signer=gSigner):
    """ Load file check signature """
    data = io.open(fname, 'r', encoding='UTF-8').read()
    n = data.find('#sign')
    if n > 0:
        sign = data[n:].strip()
        data = data[0:n]
        if useSign:
            res = verify(data, sign, signer, sfx='.pub')
            if not res: return None
    return io.StringIO(data)


def save_file(fname, data, useSign=True, signer=gSigner):
    """ Save file check signature """
    if isinstance(data, io.StringIO): data = data.read()
    n = data.find('#sign')
    if n > 0:
        data = data[0:n]
    if useSign:
        data += sign(data, signer) + '\n'
    io.open(fname, 'w', encoding='UTF-8').write(data)
    return


def load_voters(fname):
    try:
        voters = {s['studNr']: s for s in csv.DictReader(load_file(fname), delimiter=';')}
        return voters
    except Exception as e:
        return {}


def load_candidates(fname):
    try:
        candidates = {s['mdwId']: s for s in csv.DictReader(load_file(fname), delimiter=';')}
        return candidates
    except Exception as e:
        return {}


# This is non-secure version of Voting.
# Make it more secure
# Does ir follow your Constrains (Randvoorwaarden)
class Vote:
    _voters = []
    _casts = []

    def __init__(self):
        fname = 'vote' + '.state'
        if os.path.exists(fname):
            decrypt()
            # Recover saved state
            jDct = json.load(io.open(fname, 'r'))
            self._voters = jDct['voters']
            self._casts = jDct['casts']
            private()
            if gDbg: print('DEBUG: recovered state:', fname)

    def __del__(self):
        # Save state
        fname = 'vote' + '.state'
        jDct = {'voters': self._voters, 'casts': self._casts}
        json.dump(jDct, io.open(fname, 'w'))
        if gDbg: print('DEBUG: saved state:', fname)
        encrypt()
        private()

    def vote(self, voteId, candId):
        # Do some checks about voters and candidates
        # StudentWork {{

        if voteId in self._voters:
            print('Error: Multiple votes: {}'.format(voteId))
            os._exit(0)

        # StudentWork }}
        encrypt()
        now = datetime.datetime.now()
        if voteId in gVoters and candId in gCandidates:
            self._voters.append(voteId)
            self._casts.append(candId)
        return f'Voter: {voteId} voted {candId} at {now}'

    def results(self):
        votes = collections.Counter(self._casts)
        return votes.most_common()

    def audit(self):
        save_file('audit_cand.json', json.dumps(self._casts))
        # original save file without hash
        # save_file('audit_vote.json', json.dumps(self._voters))
        save_file('audit_vote.json', json.dumps([hash(i) for i in self._voters]))
        if gDbg: print("DEBUG: saved audit-trail")

    def create(self):
        # Reinitialize state
        self._voters = []
        self._casts = []

        fname = 'vote' + '.state'
        if os.path.exists(fname):
            os.remove(fname)

    def delete(self):
        # Reinitialize state
        self._voters = []
        self._casts = []

        fname = 'vote' + '.state'
        if os.path.exists(fname):
            os.remove(fname)

    def stats(self):
        return {
            'candidates': len(gCandidates),
            'registered': len(gVoters),
            'voters': len(self._voters),
            'casts': len(self._casts),
        }


gVoters = load_voters('voters.csv')
gCandidates = load_candidates('candidates.csv')
if __name__ == '__main__':
    cmd = ''
    opts, args = getopt.getopt(sys.argv[1:], 'hp:c:', ['create', 'vote', 'res', 'stats', 'delete'])
    for opt, arg in opts:
        if opt == '-h':
            print('Usage: vote --create')
            print('\tInitialize vote system')
            print('Usage: vote --vote -p <voteId> -c <candId>')
            print('\tCast vote')
            print('Usage: vote --res')
            print('\tShow results')
            print('Usage: vote --stats')
            print('\tShow statistics')
            print('Usage: vote --delete')
            print('\tDelete all information (securily)')
            sys.exit()
        if opt == '-D': gDbg = True

        if opt == '-p': voteId = arg
        if opt == '-c': candId = arg
        if opt[0:2] == '--': cmd = opt[2:]

    voting = Vote()
    if cmd == 'create':
        voting.create()
    if cmd == 'vote':
        reciept = voting.vote(voteId, candId)
        if reciept: print(reciept)
    if cmd == 'res':
        voting.audit()
        for res in voting.results()[:3]:
            print('{0:3s}: {1:3d}'.format(res[0], res[1]))
    if cmd == 'stats':
        print(voting.stats())
    if cmd == 'delete':
        voting.delete()

    # force saving state
    voting = None

