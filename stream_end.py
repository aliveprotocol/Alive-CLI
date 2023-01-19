import sys

if '.' in __name__:
    from . import constants
else:
    import constants

if len(sys.argv) != 6:
    print('Usage: python3 ' + sys.argv[0] + ' <network> <api_node> <link> <username> <private_key>')
    sys.exit(0)

api = sys.argv[2]
link = sys.argv[3]
sender = sys.argv[4]
key = sys.argv[5]

if sys.argv[1] == 'avalon':
    # Avalon
    import json
    import time
    import requests
    import avalon

    playlist = requests.get(api+'/playlist/'+sender+'/'+link)
    playlistJson = {}
    if playlist.status_code == 200:
        playlistJson = playlist.json()['json']
        if 'ended' in playlistJson and isinstance(playlistJson['ended'],bool) and playlistJson['ended'] is True:
            raise RuntimeError('Stream already ended')
    else:
        raise RuntimeError('Could not fetch playlist')
    playlistJson['ended'] = True
    tx = {
        'type': 25,
        'data': {
            'link': link,
            'json': playlistJson
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
        'op': 1,
        'link': link
    }
    hive_client.custom_json(constants.hive_custom_json_id,json_data,required_posting_auths=[sender])
else:
    raise ValueError('Invalid network')