"""
OneLoveIPFS hosting service Python API
"""
import requests
import base58
import hashlib
from beemgraphenebase import ecdsasig

DEFAULT_ENDPOINT = 'https://uploader.oneloveipfs.com'

def generate_message_to_sign(username: str, network: str, auth_id: str, api: str) -> str:
    message = username+':'+auth_id+':'+network+':'
    if network == 'hive':
        try:
            props = requests.post(api,json={
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'condenser_api.get_dynamic_global_properties',
                'params': []
            }).json()['result']
            message = message+str(props['head_block_number'])+':'+str(props['head_block_id'])
        except:
            raise RuntimeError('Could not fetch dynamic global properties')
    elif network == 'dtc' or network == 'avalon':
        try:
            count = requests.get(api+'/count').json()['count']
            bhash = requests.get(api+'/block/'+str(count)).json()['hash']
            message = message+str(count)+':'+str(bhash)
        except:
            raise RuntimeError('Could not fetch latest blockchain info from Avalon')
    return message

def sign_message(message: str, priv_key: str) -> str:
    return message+':'+ecdsasig.sign_message(message=message,wif=priv_key).hex()

def sign_message_avalon(message: str, priv_key: str) -> str:
    k = bytearray([0x80]) + bytearray(base58.b58decode(priv_key))
    wif = base58.b58encode(k + bytearray(hashlib.sha256(hashlib.sha256(bytes(k)).digest()).digest()[:4])).decode('utf-8')
    return sign_message(message,wif)

def login(signed_msg: str, endpoint: str = DEFAULT_ENDPOINT) -> dict:
    headers = { 'Content-Type': 'text/plain' }
    loginsig = requests.post(endpoint+'/loginsig',data=signed_msg,headers=headers)
    if loginsig.status_code != 200:
        raise RuntimeError('Could not authenticate to upload endpoint')
    return loginsig.json()