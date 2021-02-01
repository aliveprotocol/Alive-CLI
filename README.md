# Alive-CLI

Core Alive daemon and CLI tool for publishing HLS streams to decentralized networks.

This is the main daemon that is used by streamers to upload .ts chunks of a local HLS stream to IPFS or Skynet and publishes its hash and duration to decentralized networks.

## Pre-requisites

Python 3.7+, `pip3` package manager and AliveDB dependencies are required.

Additionally, the following packages are required for its dependency packages to be installed successfully:

### Debian/Ubuntu

```
sudo apt-get install build-essential libssl-dev python3-dev python3-pip python3-setuptools
```

### Fedora/CentOS

```
sudo yum install gcc openssl-devel python-devel
```

### macOS

```
brew install openssl
export CFLAGS="-I$(brew --prefix openssl)/include $CFLAGS"
export LDFLAGS="-L$(brew --prefix openssl)/lib $LDFLAGS"
```

### Termux on Android

```
pkg install clang openssl python
```

You may also want to install IPFS or Sia node for uploading .ts chunks to your local repo:
* [go-ipfs](https://dist.ipfs.io/#go-ipfs)
* [ipfs-desktop](https://github.com/ipfs-shipyard/ipfs-desktop/releases)
* [siad](https://sia.tech/get-started)

## Installation

```
git clone https://github.com/aliveprotocol/Alive-CLI
cd Alive-CLI
pip3 install -r requirements.txt
python3 alivedb_install.py
```

The default data directory is `~/.alive` where all Alive working files will be stored.

## Starting a new stream

Begin from step 3 if streaming directly on-chain.

1. If not already, create an AliveDB user account.
```
python3 alivedb_usercreate.py <new_alivedb_password>
```

2. Publish your AliveDB public key to your new stream.

**Avalon**
```
python3 stream_configure.py dtc <avalon_api_node> <link> <alivedb_pubkey> <username> <private_key>
```

**Hive**
```
python3 stream_configure.py hive <hive_api_node> <link> <alivedb_pubkey> <username> <posting_key>
```

3. Setup OBS recording output settings according to the config below.

4. Start the Alive daemon. To get CLI usage info:
```
python3 alivecli.py -h
```

5. Start recording in OBS.

## Ending a stream

1. Stop recording in OBS.
2. Let the final chunk to complete processing, then hit `Ctrl+C` on Alive daemon.
3. Let the world know that the stream has ended so that the stream archive will be seekable.

**Avalon**
```
python3 stream_end.py dtc <avalon_api_node> <link> <username> <private_key>
```

**Hive**
```
python3 stream_end.py hive <hive_api_node> <link> <username> <posting_key>
```

## OBS Recording Output Config

**ⓘ Important**
Your recording output configuration must match the settings below. Failing to do so may result in failed uploads or excessive use of bandwidth or resource credits.

- Output mode: **Advanced**
- Type: **Custom output (FFmpeg)**
- FFmpeg output type: **Output to File**
- File path: `~/.alivedb/record_here`
- Container format: **hls**
- Muxer settings: **hls_time=10**
- Keyframe interval: Set this to 10x your framerate. For example, if you're recording at 30fps, set this value to 300.