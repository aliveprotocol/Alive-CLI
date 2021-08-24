import json
import beem
import beembase

client = beem.Hive(node=['http://192.168.0.186:8091'])
rc = beem.rc.RC(hive_instance=client)

test_username = 'techcoderx'
test_link = 'teststream1'
test_length = 10.033
test_src = 'QmZEuPARFdA3aAjRzkZAQme8hm3KXbAXdqh9tAazocH9zd'
# assuming 5 minutes per chunk

opdata = {
    'required_auths':[],
    'required_posting_auths':[test_username],
    'id': 'alive',
    'json': {
        'op': 0, # push stream
        'link': test_link,
        'src': test_src
    }
}

op = beembase.operations.Custom_json(opdata)
op_size = rc.get_tx_size(op)
result = rc.custom_json(op_size)
print()
print('Graphene tx size: ' + str(op_size))
print('RC per tx: ' + str(result) + ' ' + str(round(result/1000000000,3)) + 'KV')
print('RC 1hr: ' + str(round(result*12/1000000000,3)) + 'KV')
print('Hive KVests 5d: ' + str(round(result*1440/1000000000,3)))
print()

avalon_tx = {
    'type': 23,
    'data': {
        'link': test_link,
        'src': test_src
    },
    'sender': test_username,
    'ts': 1610713944639,
    'hash': '1698fe7e753de1810459fa43aee45f9a3ebb4c1d7faa1205596e5f2850089411',
    'signature': '2hRZLEoKDXrvLywvbTLSbJSU9NLMipWioPEAWz6bxWLPQ1ehnyuSsWeLkNJHJtXgp29NYqBqHDmE6PPWHgkZtHZb'
}

avalon_tx_size = len(json.dumps(avalon_tx,separators=(',', ':')))

print('Avalon tx size: ' + str(avalon_tx_size))
print('Bandwidth 1hr: ' + str(avalon_tx_size*12))
print('Minutes 64KB: ' + str(round(64000/avalon_tx_size*5,2)))
print()