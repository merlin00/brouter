#! /usr/bin/env python
import socket
import time
import configparser
import logging
import logging.config
import json

from multiprocessing import Process
import signal

mrouter_config_file = 'config.ini'
logger_config_file = 'logger.json'
proc = []


def beacon_process(port, info):
    s = socket.socket(socket.AF_INET,
                      socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.settimeout(2)
    s.bind(("", port))

    logger = logging.getLogger('router.net')
    logger.info("Started a beacon server.")

    while True:
        try:
            data, addr = s.recvfrom(1024)

            if b'hello' == data:
                str = json.dumps(info)
                logger.info("A beacon request from %s:%s", addr[0], addr[1])
                s.sendto(str.encode(), addr)
        except socket.timeout:
            time.sleep(2)


def handler(signum, frame):
    for p in proc:
        p.terminate()
        p.join()


def mrouter_main():
    with open(logger_config_file, 'r') as f:
        logger_cfg = json.load(f)

    logging.config.dictConfig(logger_cfg)
    logger = logging.getLogger("router.net")

    config = configparser.ConfigParser()
    config.read(mrouter_config_file)

    port = int(config['ROUTER']['port'])

    info = {
        'id': config['ROUTER']['id'],
        'server': config['SERVER']['ip'],
        'router': config['ROUTER']['bind'],
        'port': int(config['SERVER']['port'])}

    logger.info("IoT Server %s", info['server'])
    logger.info("IP %s:%d", info['router'], port)

    signal.signal(signal.SIGINT, handler)

    p = Process(target=beacon_process, args=(port, info))
    p.start()
    proc.append(p)


if __name__ == '__main__':
    mrouter_main()
