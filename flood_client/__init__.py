from lib.flood._exceptions import FloodConnectionException, FloodException, FloodRequestError
from lib.flood.api import Client, FloodTorrent


__all__ = (
    "Client",
    "FloodConnectionException",
    "FloodException",
    "FloodRequestError",
    "FloodTorrent",
    "default",
    "get_torrent_file",
)

default = Client()


def get_torrent_file(client: Client, hash: str):
    return client.export_torrent_file(hash.upper())
