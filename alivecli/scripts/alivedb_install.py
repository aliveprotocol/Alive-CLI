from alivecli.alivedb import alivedb_install, default_data_dir
import sys

install_dir = default_data_dir

if len(sys.argv) > 1:
    install_dir = sys.argv[1]

def main():
    alivedb_install(alivedir=install_dir)