from Crypto.Cipher import AES
import hashlib
import hmac
import secp256k1
import base58
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from typing import Union

def ecies_decrypt(priv_key, message_parts):
    sender_public_key_obj = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), message_parts["ephemPublicKey"])
    private_key_obj = ec.derive_private_key(to_int(priv_key),ec.SECP256K1(),default_backend())
    aes_shared_key = private_key_obj.exchange(ec.ECDH(), sender_public_key_obj)
    # Now let's do AES-CBC with this, including the hmac matching (modeled after eccrypto code).
    aes_keyhash = hashlib.sha512(aes_shared_key).digest()
    hmac_key = aes_keyhash[32:]
    test_hmac = hmac.new(hmac_key, message_parts["iv"] + message_parts["ephemPublicKey"] + message_parts["ciphertext"], hashlib.sha256).digest()
    if test_hmac != message_parts["mac"]:
        raise Exception("Mac does not match")
    aes_key = aes_keyhash[:32]
    # Actual decrypt is modeled after ecies.utils.aes_decrypt() - but with CBC mode to match eccrypto.
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv=message_parts["iv"])
    try:
        decrypted_bytes = aes_cipher.decrypt(message_parts["ciphertext"])
        # Padding characters (unprintable) may be at the end to fit AES block size, so strip them.
        unprintable_chars = bytes(''.join(map(chr, range(0,32))).join(map(chr, range(127,160))), 'utf-8')
        decrypted_string = decrypted_bytes.rstrip(unprintable_chars).decode("utf-8")
        return decrypted_string
    except:
        raise Exception("Could not decode ciphertext")

# Converts encrypted message from jAvalon to Python compatible encrypted object
def js_to_py_encrypted(js_encrypted_msg):
    encrypted_b58_lst = js_encrypted_msg.split('_')
    ephemPubKey_obj = secp256k1.PublicKey().deserialize(base58.b58decode(encrypted_b58_lst[1]))
    
    py_encrypted_obj = {
        'iv': base58.b58decode(encrypted_b58_lst[0]),
        'ephemPublicKey': secp256k1.PublicKey(pubkey=ephemPubKey_obj).serialize(compressed=False),
        'ciphertext': base58.b58decode(encrypted_b58_lst[2]),
        'mac': base58.b58decode(encrypted_b58_lst[3])
    }

    return py_encrypted_obj

def to_int(primitive: Union[bytes, bytearray, int, bool] = None) -> int:
    """
    From https://github.com/ethereum/eth-utils/blob/master/eth_utils/conversions.py#L55-L83
    """
    if isinstance(primitive, (bytes, bytearray)):
        return int.from_bytes(primitive,'big')
    elif isinstance(primitive, (int, bool)):
        return int(primitive)
    else:
        raise TypeError('Primitive must be bytes, bytearray, int or bool.')