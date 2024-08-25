import dataclasses
import enum


@enum.unique
class Status(enum.StrEnum):
    complete = "complete"
    seeding = "seeding"
    inactive = "inactive"


@dataclasses.dataclass
class FloodTorrent:
    name: str

    bytesDone: int
    dateActive: int
    dateAdded: int
    dateCreated: int
    dateFinished: int
    directory: str

    # download speed
    downRate: int

    downTotal: int
    eta: float
    hash: str
    isPrivate: bool
    isInitialSeeding: bool
    isSequential: bool
    message: str
    peersConnected: int
    peersTotal: int
    percentComplete: float
    priority: int
    ratio: float
    seedsConnected: int
    seedsTotal: int
    sizeBytes: int
    status: set[str]  # checking seeding complete downloading ... etc
    tags: list[str]
    trackerURIs: list[str]
    upRate: int
    upTotal: int

    @property
    def checking(self) -> bool:
        return "checking" in self.status


@dataclasses.dataclass
class Torrents:
    id: int
    torrents: dict[str, FloodTorrent]


@dataclasses.dataclass
class File:
    index: int
    path: str
    filename: str
    percentComplete: float | None  # None for empty file
    priority: int
    sizeBytes: int
