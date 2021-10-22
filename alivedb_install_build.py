from alivedb import alivedb_install_build, default_data_dir
import sys

install_dir = default_data_dir

if len(sys.argv) > 1:
    install_dir = sys.argv[1]

alivedb_install_build(alivedir=install_dir)