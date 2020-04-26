
import argparse
import asyncio
import logging
import sys

from zmq.asyncio import ZMQEventLoop

from sawtooth_sdk.processor.log import init_console_logging

from aiohttp import web

from rest_api.router_handler import RouteHandler
from rest_api.messaging import Messenger

LOGGER = logging.getLogger(__name__)


def parse_args(args):
    parser = argparse.ArgumentParser(
        description='Starts the Simple Supply REST API')

    parser.add_argument(
        '-B', '--bind',
        help='identify host and port for api to run on',
        default='localhost:8000')
    parser.add_argument(
        '-C', '--connect',
        help='specify URL to connect to a running validator',
        default='tcp://localhost:4004')
    parser.add_argument(
        '-t', '--timeout',
        help='set time (in seconds) to wait for a validator response',
        default=500)
    parser.add_argument(
        '-v', '--verbose',
        action='count',
        default=0,
        help='enable more verbose output to stderr')

    return parser.parse_args(args)


def start_rest_api(host, port, messenger):
    loop = asyncio.get_event_loop()

    app = web.Application(loop=loop,client_max_size=20*1024**2)
    # WARNING: UNSAFE KEY STORAGE
    # In a production application these keys should be passed in more securely
    app['aes_key'] = 'ffffffffffffffffffffffffffffffff'
    app['secret_key'] = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'

    messenger.open_validator_connection()

    handler = RouteHandler(loop, messenger)

    app.router.add_post('/user', handler.create_user)
    app.router.add_get('/transactions', handler.all_transactions)
    
    LOGGER.info('Starting Simple Supply REST API on %s:%s', host, port)
    web.run_app(
        app,
        host=host,
        port=port,
        access_log=LOGGER,
        access_log_format='%r: %s status, %b size, in %Tf s')


def main():
    loop = ZMQEventLoop()
    asyncio.set_event_loop(loop)

    messenger = None
    try:
        opts = parse_args(sys.argv[1:])

        init_console_logging(verbose_level=opts.verbose)

        validator_url = opts.connect
        if "tcp://" not in validator_url:
            validator_url = "tcp://" + validator_url
        messenger = Messenger(validator_url)

        try:
            host, port = opts.bind.split(":")
            port = int(port)
        except ValueError:
            print("Unable to parse binding {}: Must be in the format"
                  " host:port".format(opts.bind))
            sys.exit(1)

        start_rest_api(host, port, messenger)
    except Exception as err:  # pylint: disable=broad-except
        LOGGER.exception(err)
        sys.exit(1)
    finally:
        if messenger is not None:
        messenger.close_validator_connection()