"""Error codes safe to print without leaking image metadata."""


class ImageScanError(ValueError):
    """A trusted local image scan failed; message is a fixed reason code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code
