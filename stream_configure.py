import sys

if len(sys.argv) != 7:
    print('Usage: python3 ' + sys.argv[0] + ' <network> <api_node> <link> <alivedb_pubkey> <username> <private_key>')
    sys.exit(0)

api = sys.argv[2]
link = sys.argv[3]
pub = sys.argv[4]
sender = sys.argv[5]
key = sys.argv[6]

if sys.argv[1] == 'dtc':
    # Avalon
    import json
    import time
    import requests
    import base58
    import hashlib
    import secp256k1

    tx = {
        'type': 21,
        'data': {
            'link': link,
            'pub': pub
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
elif sys.argv[1] == 'hive':
    # Hive
    from beem import Hive
    hive_client = Hive(node=api,keys=[key])

    json_data = {
        'op': 2,
        'link': link,
        'pub': pub
    }

    hive_client.custom_json('alive-test',json_data,required_posting_auths=[sender])
else:
    raise ValueError('Invalid network')