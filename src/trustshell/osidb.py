from collections import defaultdict
import logging
import os
import subprocess
import sys
import tempfile
from typing import Any, Union

import click

from trustshell.models import Affect
from requests import HTTPError
from trustshell import console
import osidb_bindings
from osidb_bindings.bindings.python_client.models import Flaw

logger = logging.getLogger(__name__)


class OSIDB:
    def __init__(self) -> None:
        endpoint = os.getenv("OSIDB_ENDPOINT")
        if endpoint is None:
            raise EnvironmentError(
                "The environment variable 'OSIDB_ENDPOINT' is not set."
            )
        self.session = osidb_bindings.new_session(osidb_server_uri=endpoint)  # type: ignore[attr-defined]

    @staticmethod
    def parse_stream_purl_tuples(tuples_list: list[str]) -> set[tuple[str, str]]:
        """
        Parses a list of "ps_update_stream,purl" strings into a set of (ps_update_stream, purl) tuples.
        """
        parsed_tuples = set()
        for item in tuples_list:
            parts = item.split(",", 1)  # Split only on the first comma
            if len(parts) != 2:
                console.print(
                    f"Error: Invalid tuple format '{item}'. Expected 'ps_update_stream,purl'.",
                    style="error",
                )
                sys.exit(1)
            ps_update_stream, purl = parts[0].strip(), parts[1].strip()
            if not ps_update_stream or not purl:
                console.print(
                    f"Error: ps_update_stream or purl cannot be empty in '{item}'.",
                    style="error",
                )
                sys.exit(1)
            parsed_tuples.add((ps_update_stream, purl))
        return parsed_tuples

    @staticmethod
    def edit_tuples_in_editor(
        current_tuples: Union[list[tuple[str, str]], set[tuple[str, str]]],
    ) -> list[tuple[str, str]]:
        """
        Opens the default text editor for the user to modify the ps_update_stream/purl tuples.
        Returns the modified list of tuples, sorted by (ps_update_stream, purl).
        """
        editor = os.environ.get("EDITOR", "vi")
        original_content = "\n".join([f"{m},{p}" for m, p in current_tuples])

        with tempfile.NamedTemporaryFile(mode="w+", suffix=".txt", delete=False) as tf:
            tf.write(original_content)
            temp_filepath = tf.name

        console.print(f"Opening editor '{editor}' for file: {temp_filepath}")
        console.print(
            "Please modify the ps_update_stream,purl tuples and save the file."
        )
        console.print("Each tuple should be on a new line.")

        try:
            subprocess.run([editor, temp_filepath], check=True)
        except FileNotFoundError:
            console.print(
                f"Error: Editor '{editor}' not found. Please set your EDITOR environment variable.",
                style="error",
            )
            exit(1)
        except subprocess.CalledProcessError:
            console.print(
                "Editor exited with an error. Changes might not be saved.",
                style="error",
            )
            exit(1)

        with open(temp_filepath, "r") as file:
            modified_content = file.read()

        os.remove(temp_filepath)  # Clean up the temporary file

        # Parse the modified content
        modified_lines = [
            line.strip() for line in modified_content.splitlines() if line.strip()
        ]
        parsed = OSIDB.parse_stream_purl_tuples(modified_lines)
        return sorted(parsed, key=lambda x: (x[0], x[1]))

    def _affects_to_tuples(self, affects: list[Affect]) -> list[tuple[str, str]]:
        """Convert list[Affect] to list of (ps_update_stream, purl) tuples for display."""
        return [(a.ps_update_stream, a.purl) for a in affects]

    def add_affects(self, flaw: Flaw, affects_to_add: list[Affect]) -> None:
        console.print("Adding affects...")
        affects_data: list[dict[str, Any]] = []
        for ps_update_stream, purl in self._affects_to_tuples(affects_to_add):
            osidb_affect = {
                "flaw": flaw.uuid,
                "embargoed": flaw.embargoed,
                "ps_update_stream": ps_update_stream.strip(),
                "ps_component": None,
                "purl": purl.strip(),
            }
            affects_data.append(osidb_affect)
        try:
            bulk_create_response = self.session.affects.bulk_create(
                form_data=affects_data
            )
        except HTTPError as e:
            msg = e.response.text
            console.print(f"Failed to update flaw: {e}: {msg}")
            exit(1)
        console.print(f"Added {len(bulk_create_response.results)} new affects")

    def edit_flaw_affects(
        self,
        flaw_id: str,
        ps_stream_purls: list[Affect],
        replace_mode: bool = False,
    ) -> None:
        ps_stream_purls_list = self._affects_to_tuples(ps_stream_purls)
        if not ps_stream_purls_list:
            console.print("No new affects to add", style="warning")
            return

        console.print(f"Processing flaw affects for flaw: {flaw_id}")

        try:
            flaw = self.session.flaws.retrieve(id=flaw_id)
        except Exception as e:
            console.print(f"Could not retrieve flaw {flaw_id}: {e}")
            return

        affects_by_state: dict[str, set[tuple[str, str]]] = defaultdict(set)
        for affect in flaw.affects:
            affects_by_state[affect.affectedness].add(
                (affect.ps_update_stream, affect.purl)
            )

        console.print("\n--- Existing Flaw Affects ---")
        if affects_by_state:
            for state, affects_list in affects_by_state.items():
                console.print(f"State: {state}")
                for affect_str in sorted(affects_list, key=lambda x: (x[0], x[1])):
                    console.print(affect_str)
        else:
            console.print("  No affects found for this flaw.")
        console.print("-----------------------------\n")

        console.print("New affects:")
        for ps_stream_purl in ps_stream_purls_list:
            console.print(ps_stream_purl)

        # Optionally edit tuples in editor
        if click.confirm("Do you want to edit these affects?"):
            console.print("Entering editor mode to modify input tuples...")
            ps_stream_purls_list = self.edit_tuples_in_editor(ps_stream_purls_list)
            console.print("\n--- Modified Tuples from Editor ---")
            if ps_stream_purls_list:
                for m, p in ps_stream_purls_list:
                    console.print(f"  - {m},{p}")
            else:
                console.print("  (No tuples provided after editing)")
            console.print("-----------------------------------\n")

        ps_stream_purls_set = set(ps_stream_purls_list)
        if not replace_mode:
            affects_to_add = (
                ps_stream_purls_set - affects_by_state["NEW"]
            )  # Only truly new ones
            if not affects_to_add:
                console.print(
                    "No new ps_update_stream/purl tuples to add. All provided are already present or in different states."
                )
                return

            console.print("\n--- Affects to be ADDED ---")
            affects_to_add_list = [
                Affect(ps_update_stream=ps, purl=p) for ps, p in affects_to_add
            ]
            for affect in affects_to_add_list:
                console.print(f"  - {affect.ps_update_stream},{affect.purl}")
            console.print("---------------------------\n")

            click.confirm("Confirm adding the above affects?", abort=True)
            self.add_affects(flaw, affects_to_add_list)

        else:
            if not affects_by_state["NEW"] and not ps_stream_purls_list:
                console.print(
                    "No existing 'NEW' affects to replace and no new affects provided. Nothing to do."
                )
                return

            console.print("\n--- Existing 'NEW' Affects to be REPLACED ---")
            if affects_by_state["NEW"]:
                for affect in sorted(
                    affects_by_state["NEW"], key=lambda x: (x[0], x[1])
                ):
                    console.print(affect)
            else:
                console.print("  (No existing affects with state 'NEW')")
            console.print("--------------------------------------------\n")

            console.print("\n--- New Affects that will REPLACE the above ---")
            if ps_stream_purls_list:
                for affect in ps_stream_purls_list:
                    console.print(affect)
            else:
                console.print("  (No new affects provided)")
            console.print("---------------------------------------------\n")

            click.confirm(
                "Confirm replacing existing 'NEW' affects with the new set?", abort=True
            )

            console.print("Replacing affects...")
            existing_affects: dict[tuple[str, str], tuple[str, str]] = {}
            for affect in flaw.affects:
                if affect.purl:
                    existing_affects[(affect.ps_update_stream, affect.purl)] = (
                        affect.uuid,
                        affect.affectedness,
                    )

            # Check for existing affects in new state to remove
            for existing_key, existing_value in existing_affects.items():
                existing_uuid, existing_affectedness = existing_value
                # Don't delete and re-add existing new affects
                if (
                    existing_key not in ps_stream_purls_set
                    and existing_affectedness == "NEW"
                ):
                    try:
                        self.session.affects.delete(id=existing_uuid)
                    except HTTPError as e:
                        msg = e.response.text
                        console.print(
                            f"Failed to delete flaw affect {existing_key}: {e}: {msg}",
                            style="error",
                        )
                        exit(1)

            # Add any new affects not already on the flaw in NEW state
            ps_stream_purls_as_affects = [
                Affect(ps_update_stream=ps, purl=p) for ps, p in ps_stream_purls_list
            ]
            self.add_affects(flaw, ps_stream_purls_as_affects)
