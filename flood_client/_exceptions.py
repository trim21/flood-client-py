class FloodException(Exception):
    pass


class FloodConnectionException(FloodException):
    pass


class FloodRequestError(FloodException):
    """code maybe xml error code -32602 or os error code `EACCES`"""

    code: int | str
    message: str

    def __init__(self, code: int | str, message: str):
        self.code = code
        self.message = message
