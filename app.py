import sys

from mitmproxy.tools import _main
from mitmproxy.tools import cmdline
from satellite.proxy import ProxyMaster

if __name__ == '__main__':
    try:
        while True:
            _main.run(ProxyMaster, cmdline.mitmweb, sys.argv[1:])
    except KeyboardInterrupt:
        print("Exiting...")
