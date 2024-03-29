# Alive-CLI

Core Alive daemon and CLI tool for publishing HLS streams to decentralized networks.

This is the main daemon that is used by streamers to upload .ts segments of a local HLS stream to IPFS and publishes its hash and duration to decentralized networks.

## Pre-requisites

Python 3.8+, `pip3` package manager and AliveDB dependencies are required.

Additionally, the following packages are required for its dependency packages to be installed successfully:

### Debian/Ubuntu
```bash
sudo apt-get install build-essential libssl-dev python3-dev python3-pip python3-setuptools
```

### Fedora/CentOS
```bash
sudo yum install gcc openssl-devel python-devel
```

### macOS
```bash
brew install openssl
export CFLAGS="-I$(brew --prefix openssl)/include $CFLAGS"
export LDFLAGS="-L$(brew --prefix openssl)/lib $LDFLAGS"
```

### Termux on Android
```bash
pkg install clang openssl python
```

You may also want to install IPFS node for uploading .ts segments to your local repo:
* [go-ipfs](https://dist.ipfs.io/#go-ipfs)
* [ipfs-desktop](https://github.com/ipfs-shipyard/ipfs-desktop/releases)

## Installation

### Clone repository
```bash
git clone https://github.com/aliveprotocol/Alive-CLI
cd Alive-CLI
```

### Setup virtual environment

To create the virtual environment (one-time):
```bash
python3 -m venv .venv --prompt alivecli
```

To enter the virtual environment:
```bash
source .venv/bin/activate
```

### Install in virtual environment
```bash
pip3 install . --use-pep517
alivedb_install
```

The default data directory is `~/.alive` where all Alive working files will be stored.

## Starting a new stream

Begin from step 3 if streaming directly on-chain.

1. If not already, create an AliveDB user account.
```bash
alivedb_usercreate <new_alivedb_password>
```

2. Publish your AliveDB public key to your new stream.
```bash
alive_configure hive <hive_api_node> <link> <alivedb_pubkey> <username> <posting_key>
```

3. Setup OBS recording output settings according to the config below.

4. Start the Alive daemon. To get CLI usage info:
```bash
alivecli --help
```

5. Start recording in OBS.

## Ending a stream

1. Stop recording in OBS.
2. Let the final segment to complete processing, then hit `Ctrl+C` on Alive daemon.
3. Let the world know that the stream has ended so that the stream archive will be seekable.

```bash
alive_end hive <hive_api_node> <link> <username> <posting_key>
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

## Programmatic Usage

The Alive daemon can be invoked programmatically in Python as well. For a detailed guide (including example code snippets), check out the [Streamer SDK](https://aliveprotocol.com/docs/develop/streamer-sdk) developer documentation.