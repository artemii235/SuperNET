import ujson
import subprocess
from .mm2proxy import MMProxy
import pycurl
import os
import sys
import certifi


def curldownload(path: str, url="https://raw.githubusercontent.com/KomodoPlatform/coins/master/coins"):
    """Download file from url to path with pycurl"""
    fp = open(os.path.join(path), "wb")
    curl = pycurl.Curl()
    curl.setopt(pycurl.URL, url)
    curl.setopt(pycurl.NOPROGRESS, 0)
    curl.setopt(pycurl.FOLLOWLOCATION, 1)
    curl.setopt(pycurl.MAXREDIRS, 5)
    curl.setopt(pycurl.CONNECTTIMEOUT, 50)
    curl.setopt(pycurl.TIMEOUT, 120)
    curl.setopt(pycurl.FTP_RESPONSE_TIMEOUT, 600)
    curl.setopt(pycurl.NOSIGNAL, 1)
    curl.setopt(pycurl.WRITEDATA, fp)
    curl.setopt(curl.CAINFO, certifi.where())
    try:
        curl.perform()
    except pycurl.error:
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.stderr.flush()
    curl.close()
    fp.close()


class MMnode:
    def __init__(self, seed: str, rpc_port: str, seednodes: list, node_directory: str, ntype: int):
        self.bin_dir = node_directory
        self.rpcport = rpc_port
        self.node_type = ntype
        self.seednodes_array = seednodes
        self.passphrase = seed
        # self.password = tmp disabled
        if os.name == 'posix':
            self.binary = self.bin_dir + "/mm2"
            self.conf = self.bin_dir + "/MM2.json"
            self.logs = self.bin_dir + "/MM2.log"
            self.coinsfile = self.bin_dir + "/coins"
        else:
            self.binary = self.bin_dir + "\\mm2.exe"
            self.conf = self.bin_dir + "\\MM2.json"
            self.logs = self.bin_dir + "\\MM2.log"
            self.coinsfile = self.bin_dir + "\\coins"

    def cleanup(self, full: bool):
        if os.path.isfile(self.coinsfile) and full:
            os.remove(self.coinsfile)
        if os.path.isfile(self.logs):
            os.remove(self.logs)
        if os.path.isfile(self.conf):
            os.remove(self.conf)

    def env_declare(self):
        os.environ['MM_COINS_PATH'] = self.coinsfile
        os.environ['MM_CONF_PATH'] = self.conf
        os.environ['MM_LOG'] = self.logs

    def gen_confile(self) -> str:
        base_conf = {
            'gui': 'nogui',
            'netid': 9012,
            'userhome': os.environ.get('HOME'),
            'passphrase': self.passphrase,
            'rpcip': '0.0.0.0',
            'rpc_password': "RPC_PASSWORD",  # self.password,
            'rpc_local_only': False,
            'rpc_port': self.rpcport,
        }
        if self.node_type == 1:
            base_conf.update({'i_am_seed': True})
        else:
            base_conf.update({'seednodes': self.seednodes_array})
        return ujson.dumps(base_conf)

    def check_local_files(self):
        if not os.path.isfile(self.coinsfile):
            curldownload(self.coinsfile)
        if not os.path.isfile(self.logs):
            open(self.logs, 'a').close()
        if not os.path.isfile(self.conf):
            base_conf = self.gen_confile()
            with open(self.conf, 'w') as cf:
                cf.write(base_conf)

    def start(self):
        """Start MM2 node as configured"""
        self.check_local_files()
        self.env_declare()
        try:
            subprocess.Popen(self.binary, shell=False, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
            return True
        except Exception as e:
            print(e)
            return False

    def rpc_conn(self, host='127.0.0.1') -> MMProxy:
        node_params_dictionary = {
            'userpass': "RPC_PASSWORD",  # userpass to be used in jsonrpc
            'rpchost': host,
            'rpcport': self.rpcport
        }
        proxy = MMProxy(node_params_dictionary, timeout=120)
        return proxy

    def stop(self):
        rpc = self.rpc_conn()
        rpc.stop()
