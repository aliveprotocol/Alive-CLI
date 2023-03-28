import sys
from pprint import pprint

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
    raise RuntimeError('Avalon network is deprecated')
elif sys.argv[1] == 'hive':
    # Hive
    from beem import Hive
    hive_client = Hive(node=api,keys=[key])

    json_data = {
        'op': 1,
        'link': link
    }
    pprint(hive_client.custom_json(constants.hive_custom_json_id,json_data,required_posting_auths=[sender]))
else:
    raise ValueError('Invalid network')