import sys
from pprint import pprint

if '.' in __name__:
    from . import constants
else:
    import constants

if len(sys.argv) < 7:
    print('Usage: python3 ' + sys.argv[0] + ' <network> <api_node> <link> <alivedb_pubkey> <username> <private_key> <preferred_gateway>')
    sys.exit(0)

api = sys.argv[2]
link = sys.argv[3]
pub = sys.argv[4]
sender = sys.argv[5]
key = sys.argv[6]
gw = None

if len(sys.argv) >= 8:
    gw = sys.argv[7]

if sys.argv[1] == 'avalon':
    # Avalon
    import json
    import time
    import requests
    import avalon

    tx = {
        'type': 25,
        'data': {
            'link': link,
            'json': {
                'live': True,
                'pub': pub,
                'l2': 'gundb'
            }
        },
        'sender': sender,
        'ts': round(time.time() * 1000)
    }
    avalon.sign(tx,key)

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
        'pub': pub,
        'l2': 'gundb'
    }
    if gw:
        json_data['gw'] = gw

    pprint(hive_client.custom_json(constants.hive_custom_json_id,json_data,required_posting_auths=[sender]))
else:
    raise ValueError('Invalid network')