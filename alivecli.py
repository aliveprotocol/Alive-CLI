import os
import argparse
import signal
from stream_hls import AliveInstance, AliveDaemon
from alivedb import AliveDB
from alivedb_integrity import version as __version__

def str2bool(v):
    if isinstance(v, bool):
       return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')

parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter, description='Alive Protocol HLS Streamer CLI Tool')
parser.add_argument('-d','--data_dir', help='Data directory for stream recording, AliveDB and log files.', default=os.path.expanduser(os.path.join('~', '.alive')), metavar='')
parser.add_argument('-f','--purge_files', type=str2bool, default=False, help='Purges .ts chunks after upload.', metavar='')
parser.add_argument('-p','--protocol', help='P2P protocol for HLS streams. Valid values: IPFS and Skynet.', metavar='', default='IPFS')
parser.add_argument('-e','--endpoint', help='IPFS/Skynet upload endpoint.', metavar='', default='/ip4/127.0.0.1/tcp/5001/http')
parser.add_argument('-v','--version', help='Print the version', action='version', version=__version__)

required_args = parser.add_argument_group('required arguments')
required_args.add_argument('-n','--network', help='Network (valid values are dtc and hive)', required=True, metavar='', default=argparse.SUPPRESS)
required_args.add_argument('-a','--api', help='API node URL', required=True, metavar='', default=argparse.SUPPRESS)
required_args.add_argument('-u','--user', help='Username', required=True, metavar='', default=argparse.SUPPRESS)
required_args.add_argument('-k','--key', help='Private key (Avalon custom key must have PLAYLIST_JSON and PLAYLIST_PUSH permissions)', required=True, metavar='', default=argparse.SUPPRESS)
required_args.add_argument('-l','--link', help='Livestream permlink, generated at post creation', required=True, metavar='', default=argparse.SUPPRESS)
required_args.add_argument('-bi','--batch_interval', help='Number of seconds of stream segments to bundle into each chunk', required=True, type=int, metavar='', default=300)

alivedb_args = parser.add_argument_group('AliveDB arguments')
alivedb_args.add_argument('-gu','--alivedb_user', help='AliveDB user ID', metavar='', default=None)
alivedb_args.add_argument('-gpuk','--alivedb_public_key', help='AliveDB public key (if no user ID)', metavar='', default=None)
alivedb_args.add_argument('-gk','--alivedb_key', help='AliveDB user key', metavar='', default=None)
alivedb_args.add_argument('-gp','--alivedb_peers', help='AliveDB peer list (comma separated)', metavar='', default=argparse.SUPPRESS)
alivedb_args.add_argument('-gmod','--alivedb_automod', help='AliveDB live chat automod', type=str2bool, metavar='', default=False)

args = parser.parse_args()

if args.alivedb_peers is not None:
    args.alivedb_peers = args.alivedb_peers.split(',')
else:
    args.alivedb_peers = []

alivedb_instance = None

if args.alivedb_user is None and args.alivedb_public_key is None:
    parser.error('Either AliveDB user ID or public key must be present')
if args.alivedb_key is None:
    parser.error('AliveDB user key is missing')
chat_listener = ''
if args.alivedb_automod is True:
    chat_listener = args.network+'/'+args.user+'/'+args.link
alivedb_instance = AliveDB(
    alivedir=args.data_dir+'/AliveDB',
    peers=args.alivedb_peers,
    chat_listener=chat_listener
)
alivedb_instance.start()
if args.alivedb_user is not None:
    alivedb_instance.login(key=args.alivedb_key, id=args.alivedb_user)
elif args.alivedb_public_key is not None:
    alivedb_instance.login(key=args.alivedb_key, pub=args.alivedb_public_key)
alivedb_instance.fetch_participants_keys()

if args.batch_interval > 300 or args.batch_interval < 0:
    parser.error('Batch interval must be between 0 and 300 seconds')

alive_instance = AliveInstance(
    protocol=args.protocol,
    upload_endpoint=args.endpoint,
    network=args.network,
    api=args.api,
    username=args.user,
    private_key=args.key,
    link=args.link,
    data_dir=args.data_dir,
    purge_files=args.purge_files,
    batch_interval=args.batch_interval
)

alive_daemon = AliveDaemon(instance=alive_instance,alivedb_instance=alivedb_instance)
signal.signal(signal.SIGINT,alive_daemon.sigint_handler)
alive_daemon.start_worker()
