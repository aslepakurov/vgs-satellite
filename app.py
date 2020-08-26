import sys

from mitmproxy.tools import _main as main
from mitmproxy.tools import cmdline
from satellite.proxy import ProxyMaster


def main_loop():
    main.run(ProxyMaster, cmdline.mitmweb, sys.argv[1:])


if __name__ == '__main__':
    try:
        main_loop()
    except KeyboardInterrupt:
        print("Exiting...")
