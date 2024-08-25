import base64
import io
import json
import logging
import tarfile
from collections.abc import Generator, Iterable
from pathlib import Path

import httpx
import sseclient
from httpx import USE_CLIENT_DEFAULT
from httpx._config import DEFAULT_TIMEOUT_CONFIG

from ._exceptions import FloodConnectionException, FloodRequestError
from .models import File, FloodTorrent


logger = logging.getLogger("flood_client")


class TooManyRequestsError(Exception):
    pass


Timeout = httpx.Timeout | type[USE_CLIENT_DEFAULT]


def _process_file(file: bytes | Path) -> str:
    if isinstance(file, bytes):
        return base64.b64encode(file).decode("utf-8")
    if isinstance(file, Path):
        return base64.b64encode(file.read_bytes()).decode("utf-8")
    raise ValueError(
        f"can't process {file}, only support torrent file content in bytes or pathlib.Path",
    )


class Client:
    def __init__(
        self,
        endpoint: str,
        username: str | None = None,
        password: str | None = None,
        *,
        timeout: httpx.Timeout | None = DEFAULT_TIMEOUT_CONFIG,
        httpx_extra_kwargs=None,
    ):
        if httpx_extra_kwargs is None:
            httpx_extra_kwargs = {}
        self.http_client = httpx.Client(
            base_url=endpoint,
            proxies={},
            timeout=timeout,
            **httpx_extra_kwargs,
        )

        if username or password:
            self.auth(username, password)

    def auth(self, username, password):
        self._post(
            "/auth/authenticate",
            data={
                "username": username,
                "password": password,
            },
        )

    def get_torrents(self, timeout=USE_CLIENT_DEFAULT) -> dict[str, FloodTorrent]:
        torrents = self._get("/torrents", timeout=timeout)
        return {h: FloodTorrent(**d) for h, d in torrents.json()["torrents"].items()}

    def check_hash_torrents(self, *hashes: str, timeout: Timeout = USE_CLIENT_DEFAULT) -> None:
        if not hashes:
            raise ValueError("must give at least one hashes")
        self._post("/torrents/check-hash", data={"hashes": hashes}, timeout=timeout)

    def list_contents(self, info_hash: str, timeout: Timeout = USE_CLIENT_DEFAULT) -> list[File]:
        data = self._get(f"/torrents/{info_hash}/contents", timeout=timeout)
        return [File(**x) for x in data.json()]

    def delete_torrents(
        self,
        *hashes: str,
        delete_data=False,
        timeout: Timeout = USE_CLIENT_DEFAULT,
    ):
        if not hashes:
            raise ValueError("must give at least one hashes")
        # try:
        self._post(
            "/torrents/delete",
            data={"hashes": hashes, "deleteData": delete_data},
            timeout=timeout,
        )
        # except httpx.HTTPError:
        #     raise FloodConnectionException from None

        # if resp.is_error:
        #     data = resp.json()
        #     raise FloodRequestError(data["code"], data["message"])

    def add_files(
        self,
        *files: bytes | Path,
        destination: str | None = None,
        start: bool | None = None,
        is_base_path: bool | None = None,
        is_completed: bool | None = None,
        is_sequential: bool | None = None,
        is_initial_seeding: bool | None = None,
        tags: list[str] | None = None,
        timeout: Timeout = USE_CLIENT_DEFAULT,
    ) -> list[str]:
        """https://flood-api.netlify.app/#operation/torrents.addFiles"""
        if not files:
            raise ValueError("need at least 1 files to add")
        data = {
            "files": [_process_file(file) for file in files],
            "start": start,
            "tags": tags,
            "destination": destination,
            "isBasePath": is_base_path,
            "isCompleted": is_completed,
            "isSequential": is_sequential,
            "isInitialSeeding": is_initial_seeding,
        }
        data = {key: value for key, value in data.items() if value is not None}

        return self._post("/torrents/add-files", data=data, timeout=timeout).json()

    def add_urls(
        self,
        *urls: str,
        cookies: list[str] | None = None,
        destination: str | None = None,
        start: bool | None = None,
        is_base_path: bool | None = None,
        is_completed: bool | None = None,
        is_sequential: bool | None = None,
        is_initial_seeding: bool | None = None,
        tags: list[str] | None = None,
        timeout: Timeout = USE_CLIENT_DEFAULT,
    ) -> list[str]:
        """https://flood-api.netlify.app/#operation/torrents.addUrls"""
        if not urls:
            raise ValueError("need at least 1 urls to add")

        data = {
            "urls": urls,
            "cookies": cookies,
            "start": start,
            "tags": tags,
            "destination": destination,
            "isBasePath": is_base_path,
            "isCompleted": is_completed,
            "isSequential": is_sequential,
            "isInitialSeeding": is_initial_seeding,
        }
        data = {key: value for key, value in data.items() if value is not None}
        return self._post("/torrents/add-urls", data=data, timeout=timeout).json()

    def re_announce(self, *hashes: str, timeout: Timeout = USE_CLIENT_DEFAULT):
        return self._post("/torrents/reannounce", data={"hashes": hashes}, timeout=timeout)

    def export_torrent_file(self, info_hash: str, timeout: Timeout = USE_CLIENT_DEFAULT) -> bytes:
        r = self._get(f"/torrents/{info_hash}/metainfo", timeout=timeout)
        return r.content

    def export_torrent_files(
        self,
        *hashes: str,
        timeout: Timeout = USE_CLIENT_DEFAULT,
    ) -> dict[str, bytes]:
        info_hash = ",".join(hashes)
        r = self._get(f"/torrents/{info_hash}/metainfo", timeout=timeout)
        b = {}
        with io.BytesIO(r.content) as f, tarfile.open(fileobj=f, mode="r") as tar:
            for file in tar.getmembers():
                m = tar.extractfile(file)
                if not m:
                    continue
                b[file.name.split(".")[0]] = m.read()
                m.close()
        return b

    def start_torrents(self, *info_hashes: str, timeout: Timeout = USE_CLIENT_DEFAULT):
        self._post("/torrents/start", data={"hashes": info_hashes}, timeout=timeout)

    def stop_torrents(self, *info_hashes: str, timeout: Timeout = USE_CLIENT_DEFAULT):
        return self._post("/torrents/stop", data={"hashes": info_hashes}, timeout=timeout)

    def move(
        self,
        *hashes: str,
        destination: str,
        move_files: bool,
        is_base_path: bool,
        is_check_hash: bool,
        timeout: Timeout = USE_CLIENT_DEFAULT,
    ) -> None:
        data = {
            "hashes": hashes,
            "destination": destination,
            "moveFiles": move_files,
            "isBasePath": is_base_path,
            "isCheckHash": is_check_hash,
        }

        self._post("/torrents/move", data=data, timeout=timeout)

    def update_tags(self, *hashes: str, tags: Iterable[str], timeout: Timeout = USE_CLIENT_DEFAULT):
        data = {
            "hashes": hashes,
            "tags": list(tags),
        }

        return self._patch("/torrents/tags", data=data, timeout=timeout)

    def _request(
        self,
        method: str,
        path: str,
        data=None,
        timeout: Timeout = USE_CLIENT_DEFAULT,
    ) -> httpx.Response:
        try:
            logger.debug("flood req: %s %s %s", method, path, data)
            resp = self.http_client.request(method, path, json=data, timeout=timeout)
            logger.debug("flood res: %d %s", method, resp.status_code)
        except httpx.HTTPError as e:
            raise FloodConnectionException(str(e)) from None

        if resp.status_code == 429:
            raise TooManyRequestsError

        if resp.is_error:
            try:
                data = resp.json()
                raise FloodRequestError(data["code"], data["message"])
            except json.decoder.JSONDecodeError as e:
                raise FloodRequestError(
                    -1,
                    f"failed to parse response as json {resp.text!r}",
                ) from e

        return resp

    def _get(self, path, timeout: Timeout = USE_CLIENT_DEFAULT) -> httpx.Response:
        return self._request("GET", path, timeout=timeout)

    def _patch(self, path, *, data, timeout: Timeout = USE_CLIENT_DEFAULT) -> httpx.Response:
        return self._request("PATCH", path, data=data, timeout=timeout)

    def _post(self, path, *, data, timeout: Timeout = USE_CLIENT_DEFAULT) -> httpx.Response:
        return self._request("POST", path, data=data, timeout=timeout)

    def _stream(self) -> Generator[bytes, None, None]:
        with self.http_client.stream("GET", "/activity-stream") as s:
            yield from s.iter_bytes()

    def events(self) -> Generator[sseclient.Event, None, None]:
        client = sseclient.SSEClient(self._stream())
        yield from client.events()
