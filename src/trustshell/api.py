import click
import httpx
import json
import logging

from rich.console import Console
from rich.theme import Theme

from trustshell import (
    AUTH_ENABLED,
    TRUSTIFY_URL,
    check_or_get_access_token,
    config_logging,
)

custom_theme = Theme({"warning": "magenta", "error": "bold red"})
console = Console(color_system="auto", theme=custom_theme)
logger = logging.getLogger("trustshell")


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--debug", "-d", is_flag=True, help="Debug log level.")
@click.argument("endpoint", type=click.STRING)
@click.argument("params", nargs=-1, type=click.STRING)
def api(endpoint: str, params: tuple[str], debug: bool):
    """Make direct API calls to Trustify endpoints

    ENDPOINT: API endpoint path (e.g., 'analysis/latest/component', 'analysis/status')
    PARAMS: Query parameters in key=value format (e.g., q=cpe~enterprise_linux limit=10)
    """
    if not debug:
        config_logging(level="INFO")
    else:
        config_logging(level="DEBUG")

    auth_header = {}
    if AUTH_ENABLED:
        access_token = check_or_get_access_token()
        auth_header = {"Authorization": f"Bearer {access_token}"}

    query_params = {}
    for param in params:
        if "=" in param:
            key, value = param.split("=", 1)
            query_params[key] = value
        else:
            console.print(
                f"Invalid parameter format: {param}. Use key=value format.",
                style="error",
            )
            return

    url = f"{TRUSTIFY_URL}{endpoint.lstrip('/')}"
    try:
        response = httpx.get(url, params=query_params, headers=auth_header, timeout=300)
        response.raise_for_status()

        data = response.json()
        console.print(json.dumps(data, indent=2))

    except httpx.HTTPStatusError as exc:
        console.print(
            f"HTTP error {exc.response.status_code}: {exc.response.text}", style="error"
        )
    except httpx.RequestError as exc:
        console.print(f"Request error: {str(exc)}", style="error")
    except json.JSONDecodeError:
        console.print("Response is not valid JSON:", style="warning")
        console.print(response.text)
    except Exception as exc:
        console.print(f"Unexpected error: {str(exc)}", style="error")
