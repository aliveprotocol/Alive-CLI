import beem
import beembase

client = beem.Hive(node=['https://techcoderx.com'])
rc = beem.rc.RC(hive_instance=client)

test_username = 'techcoderx'
test_link = 'teststream1'
test_length = 10.033
test_src = 'QmZEuPARFdA3aAjRzkZAQme8hm3KXbAXdqh9tAazocH9zd'
test_seq = 10
chunk_interval_minutes = 5

opdata = {
    'required_auths':[],
    'required_posting_auths':[test_username],
    'id': 'alive',
    'json': {
        'op': 0, # push stream
        'seq': test_seq,
        'link': test_link,
        'src': test_src
    }
}

op = beembase.operations.Custom_json(opdata)
op_size = rc.get_tx_size(op)
result = rc.custom_json(op_size)
tx_per_hour = 60/chunk_interval_minutes
print()
print('CUSTOM_JSON')
print('Graphene tx size: ' + str(op_size))
print('RC per tx: ' + str(result) + ' ' + str(round(result/1000000000,3)) + 'KV')
print('RC 1hr: ' + str(round(result*tx_per_hour/1000000000,3)) + 'KV')
print('Hive KVests 5d: ' + str(round(result*tx_per_hour*5*24/1000000000,3)))
print()