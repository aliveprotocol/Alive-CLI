import json
import time
import sys
import requests
import base58
import hashlib
import secp256k1

if len(sys.argv) != 5:
    print('Usage: ' + sys.argv + ' <avalon_api_node> <link> <username> <private_key>')
    sys.exit(0)

api = sys.argv[1]
link = sys.argv[2]
sender = sys.argv[3]
key = sys.argv[4]

tx = {
    'type': 20,
    'data': {
        'link': link
    },
    'sender': sender,
    'ts': round(time.time() * 1000)
}

txString = json.dumps(tx,separators=(',',':'))
tx['hash'] = hashlib.sha256(txString.encode('UTF-8')).hexdigest()

pk = secp256k1.PrivateKey(base58.b58decode(key))
hexhash = bytes.fromhex(tx['hash'])
sign = pk.ecdsa_sign(hexhash,raw=True,digest=hashlib.sha256)
signature = base58.b58encode(pk.ecdsa_serialize_compact(sign)).decode('UTF-8')
tx['signature'] = signature

headers = {
    'Accept': 'application/json, text/plain, */*',
    'Content-Type': 'application/json'
}
broadcast = requests.post(api + '/transact',data=json.dumps(tx,separators=(',',':')),headers=headers)
print(broadcast.text)