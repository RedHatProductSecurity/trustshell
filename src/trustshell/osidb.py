from collections import defaultdict
import logging
import os
import subprocess
import sys
import tempfile

import click
from requests import HTTPError
from trustshell import console
import osidb_bindings
from osidb_bindings.bindings.python_client.models import Flaw

logger = logging.getLogger(__name__)


class OSIDB:
    def __init__(self):
        endpoint = os.getenv("OSIDB_ENDPOINT")
        if endpoint is None:
            raise EnvironmentError(
                "The environment variable 'OSIDB_ENDPOINT' is not set."
            )
        self.session = osidb_bindings.new_session(osidb_server_uri=endpoint)

    @staticmethod
    def parse_module_purl_tuples(tuples_list: list[str]) -> set[tuple[str, str]]:
        """
        Parses a list of "ps_module,purl" strings into a set of (ps_module, purl) tuples.
        """
        parsed_tuples = set()
        for item in tuples_list:
            parts = item.split(",", 1)  # Split only on the first comma
            if len(parts) != 2:
                console.print(
                    f"Error: Invalid tuple format '{item}'. Expected 'ps_module,purl'.",
                    style="error",
                )
                sys.exit(1)
            ps_module, purl = parts[0].strip(), parts[1].strip()
            if not ps_module or not purl:
                console.print(
                    f"Error: ps_module or purl cannot be empty in '{item}'.",
                    style="error",
                )
                sys.exit(1)
            parsed_tuples.add((ps_module, purl))
        return parsed_tuples

    @staticmethod
    def edit_tuples_in_editor(
        current_tuples: set[tuple[str, str]],
    ) -> set[tuple[str, str]]:
        """
        Opens the default text editor for the user to modify the ps_module/purl tuples.
        Returns the modified set of tuples.
        """
        editor = os.environ.get("EDITOR", "vi")
        original_content = "\n".join([f"{m},{p}" for m, p in current_tuples])

        with tempfile.NamedTemporaryFile(mode="w+", suffix=".txt", delete=False) as tf:
            tf.write(original_content)
            temp_filepath = tf.name
        tf.close()  # Ensure file is closed before opening with external editor

        console.print(f"Opening editor '{editor}' for file: {temp_filepath}")
        console.print("Please modify the ps_module,purl tuples and save the file.")
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

        with open(temp_filepath, "r") as tf:
            modified_content = tf.read()

        os.remove(temp_filepath)  # Clean up the temporary file

        # Parse the modified content
        modified_lines = [
            line.strip() for line in modified_content.splitlines() if line.strip()
        ]
        return OSIDB.parse_module_purl_tuples(modified_lines)

    def add_affects(self, flaw: Flaw, affects_to_add: set[tuple[str, str]]) -> None:
        console.print("Adding affects...")
        affects_data = []
        for affect in affects_to_add:
            osidb_affect = {
                "flaw": flaw.uuid,
                "embargoed": flaw.embargoed,
                "ps_module": affect[0],
                "ps_component": None,
                "purl": affect[1],
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
        self, flaw_id: str, ps_module_purls: set[tuple[str, str]], replace_mode=False
    ):
        if not ps_module_purls:
            console.print("No new affects to add", style="warning")
            return

        console.print(f"Processing flaw affects for flaw: {flaw_id}")

        try:
            flaw = self.session.flaws.retrieve(id=flaw_id)
        except Exception as e:
            console.print(f"Could not retrieve flaw {flaw_id}: {e}")
            return

        affects_by_state = defaultdict(set)
        for affect in flaw.affects:
            affects_by_state[affect.affectedness].add(
                (
                    affect.ps_module,
                    affect.purl,
                )
            )

        console.print("\n--- Existing Flaw Affects ---")
        if affects_by_state:
            for state, affects_list in affects_by_state.items():
                console.print(f"State: {state}")
                for affect_str in affects_list:
                    console.print(affect_str)
        else:
            console.print("  No affects found for this flaw.")
        console.print("-----------------------------\n")

        console.print("New affects:")
        for ps_module_purl in ps_module_purls:
            console.print(ps_module_purl)

        # Optionally edit tuples in editor
        if click.confirm("Do you want to edit these affects?"):
            console.print("Entering editor mode to modify input tuples...")
            ps_module_purls = self.edit_tuples_in_editor(ps_module_purls)
            console.print("\n--- Modified Tuples from Editor ---")
            if ps_module_purls:
                for m, p in ps_module_purls:
                    console.print(f"  - {m},{p}")
            else:
                console.print("  (No tuples provided after editing)")
            console.print("-----------------------------------\n")

        if not replace_mode:
            affects_to_add = (
                ps_module_purls - affects_by_state["NEW"]
            )  # Only truly new ones
            if not affects_to_add:
                console.print(
                    "No new ps_module/purl tuples to add. All provided are already present or in different states."
                )
                return

            console.print("\n--- Affects to be ADDED ---")
            for affect in affects_to_add:
                console.print(f"  - {affect[0]},{affect[1]}")
            console.print("---------------------------\n")

            click.confirm("Confirm adding the above affects?", abort=True)
            self.add_affects(flaw, affects_to_add)

        else:
            if not affects_by_state["NEW"] and not ps_module_purls:
                console.print(
                    "No existing 'NEW' affects to replace and no new affects provided. Nothing to do."
                )
                return

            console.print("\n--- Existing 'NEW' Affects to be REPLACED ---")
            if affects_by_state["NEW"]:
                for affect in affects_by_state["NEW"]:
                    console.print(affect)
            else:
                console.print("  (No existing affects with state 'NEW')")
            console.print("--------------------------------------------\n")

            console.print("\n--- New Affects that will REPLACE the above ---")
            if ps_module_purls:
                for affect in ps_module_purls:
                    console.print(affect)
            else:
                console.print("  (No new affects provided)")
            console.print("---------------------------------------------\n")

            click.confirm(
                "Confirm replacing existing 'NEW' affects with the new set?", abort=True
            )

            console.print("Replacing affects...")
            existing_affects = {}
            for affect in flaw.affects:
                if affect.purl:
                    existing_affects[(affect.ps_module, affect.purl)] = (
                        affect.uuid,
                        affect.affectedness,
                    )

            # Check for existing affects in new state to remove
            for existing_key, existing_value in existing_affects.items():
                existing_uuid, existing_affectedness = existing_value
                # Don't delete and re-add existing new affects
                if (
                    existing_key not in ps_module_purls
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
            self.add_affects(flaw, ps_module_purls)
