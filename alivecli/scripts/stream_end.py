import sys
from pprint import pprint
from alivecli import constants
from alivecli.exceptions import AliveBlockchainAPIException

def main():
    if len(sys.argv) != 6:
        print('Usage: alive_end <network> <api_node> <link> <username> <private_key>')
        sys.exit(0)

    api = sys.argv[2]
    link = sys.argv[3]
    sender = sys.argv[4]
    key = sys.argv[5]

    if sys.argv[1] == 'avalon':
        raise AliveBlockchainAPIException('Avalon network is deprecated')
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