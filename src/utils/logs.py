import logging
from pathlib import Path


class LoggerFactory:
    _instances = {}
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s][%(name)s][%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(filename=Path(__file__).parent.parent.parent / "net.log", mode="a"),
            logging.StreamHandler()
        ]
    )
    logging.FileHandler(Path(__file__).parent.parent.parent / "net.log")

    @classmethod
    def new_logger(cls, name: str | None = None) -> logging.Logger:
        if cls._instances.get(name) is None:
            cls._instances[name] = logging.getLogger(name=name)

        return cls._instances[name]

    @classmethod
    def del_logger(cls, name: str | None = None) -> bool:
        return bool(cls._instances.pop(name) if name in cls._instances else False)