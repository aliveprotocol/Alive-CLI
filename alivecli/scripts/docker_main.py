from alivecli.stream_hls import AliveDaemon, AliveInstance
from alivecli.alivedb import AliveDB
from signal import signal, SIGTERM, SIGINT
from os import getenv

def main():
    alivedb_instance = AliveDB(alivedir=getenv('ALIVEDB_ENDPOINT'))

    alive_instance = AliveInstance(
        data_dir=getenv('ALIVE_DATA_DIR'),
        record_folder=getenv('ALIVE_RECORD_FOLDER'),
        purge_files=getenv('ALIVE_PURGE_FILES') == '1',
        protocol='IPFS',
        upload_endpoint=getenv('ALIVE_UPLOAD_ENDPOINT'),
        network='hive',
        api=getenv('ALIVE_BLOCKCHAIN_API'),
        halive_api=getenv('ALIVE_HALIVE_API'),
        username=getenv('ALIVE_STREAMER_USERNAME'),
        private_key=getenv('ALIVE_STREAMER_KEY'),
        link=getenv('ALIVE_STREAM_LINK'),
        batch_interval=int(getenv('ALIVE_BATCH_INTERVAL'))
    )

    alive_daemon = AliveDaemon(instance=alive_instance,alivedb_instance=alivedb_instance)
    signal(SIGTERM,alive_daemon.sigint_handler)
    signal(SIGINT,alive_daemon.sigint_handler)
    alive_daemon.start_worker()