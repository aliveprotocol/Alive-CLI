"""
OneLoveIPFS hosting service Python API
"""
import requests
from beemgraphenebase import ecdsasig
from .exceptions import *

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
            raise AliveBlockchainAPIException('Could not fetch dynamic global properties')
    elif network == 'avalon' or network == 'avalon':
        raise AliveDeprecationException('Avalon network is deprecated')
    return message

def sign_message(message: str, priv_key: str) -> str:
    return message+':'+ecdsasig.sign_message(message=message,wif=priv_key).hex()

def login(signed_msg: str, endpoint: str = DEFAULT_ENDPOINT) -> dict:
    headers = { 'Content-Type': 'text/plain' }
    loginsig = requests.post(endpoint+'/loginsig',data=signed_msg,headers=headers)
    if loginsig.status_code != 200:
        raise AliveAuthRequestException('Could not authenticate to upload endpoint')
    return loginsig.json()