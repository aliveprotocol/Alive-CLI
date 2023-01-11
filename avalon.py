import json
import base58
import hashlib
import secp256k1

def sign(tx: dict, private_key: str) -> None:
    if 'hash' not in tx:
        stringifiedTx = json.dumps(tx,separators=(',', ':'))
        tx['hash'] = hashlib.sha256(stringifiedTx.encode('UTF-8')).hexdigest()
    pk = secp256k1.PrivateKey(base58.b58decode(private_key))
    hexhash = bytes.fromhex(tx['hash'])
    sign = pk.ecdsa_recoverable_serialize(pk.ecdsa_sign_recoverable(hexhash,raw=True,digest=hashlib.sha256))

    if 'signature' not in tx or tx['signature'] is None or type(tx['signature']) is not list:
        tx['signature'] = []

    tx['signature'].append([base58.b58encode(sign[0]).decode('UTF-8'),sign[1]])

def priv_to_pub(private_key: str) -> str:
    return base58.b58encode(secp256k1.PrivateKey(base58.b58decode(private_key)).pubkey.serialize()).decode('UTF-8')