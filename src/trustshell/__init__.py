import importlib.metadata
import logging
from rich.console import Console
from rich.logging import RichHandler

console = Console(color_system="auto")
version = importlib.metadata.version("trustshell")

def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    console.print(f"Current version: {version}")
    ctx.exit()

def config_logging(level="INFO"):
    message_format = "%(asctime)s %(name)s %(levelname)s %(message)s"
    logging.basicConfig(
        level=level, format=message_format, datefmt="[%X]", handlers=[RichHandler()]
    )

    logging.basicConfig(level=level)
    httpx_logger = logging.getLogger("httpx")
    httpcore_logger = logging.getLogger("httpcore")
    httpx_logger.setLevel("WARNING")
    if level == "DEBUG":
        httpx_logger.setLevel("INFO")
        httpcore_logger.setLevel("INFO")



