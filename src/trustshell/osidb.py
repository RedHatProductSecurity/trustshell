from collections import defaultdict
import logging
import os
import subprocess
import sys
import tempfile

import click
from trustshell import console
import osidb_bindings
from osidb_bindings.bindings.python_client.models.affect import Affect

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
            print(
                f"Error: Editor '{editor}' not found. Please set your EDITOR environment variable.",
                file=sys.stderr,
            )
            sys.exit(1)
        except subprocess.CalledProcessError:
            print(
                "Editor exited with an error. Changes might not be saved.",
                file=sys.stderr,
            )
            sys.exit(1)

        with open(temp_filepath, "r") as tf:
            modified_content = tf.read()

        os.remove(temp_filepath)  # Clean up the temporary file

        # Parse the modified content
        modified_lines = [
            line.strip() for line in modified_content.splitlines() if line.strip()
        ]
        return OSIDB.parse_module_purl_tuples(modified_lines)

    def edit_flaw_affects(
        self, flaw_id: str, ps_module_purls: list[tuple[str, str]], replace_mode=False
    ):
        """
        Handles the 'flaw affects' command for trustshell.

        Args:
            args: An argparse.Namespace object containing command-line arguments.
            osidb_api: An instance of the OsidbApi client (or a mock for testing).
        """
        console.print(f"Processing flaw affects for flaw: {flaw_id}")

        try:
            flaw = self.session.flaws.retrieve(id=flaw_id)
        except Exception as e:
            console.print(f"Could not retrieve flaw {flaw_id}: {e}")
            return

        # TODO fix unhashable type error
        existing_affects: set[Affect] = set(flaw.affects)
        existing_new_affects: set[Affect] = {
            a for a in existing_affects if a.state == "NEW"
        }
        existing_non_new_affects: set[Affect] = existing_affects - existing_new_affects

        console.print("\n--- Existing Flaw Affects ---")
        if existing_affects:
            # Group by state for better readability
            affects_by_state = defaultdict(list)
            for affect in existing_affects:
                affects_by_state[affect.state].append(
                    f"  - {affect.ps_module},{affect.purl}"
                )

            for state, affects_list in affects_by_state.items():
                console.print(f"State: {state}")
                for affect_str in affects_list:
                    console.print(affect_str)
        else:
            console.print("  No affects found for this flaw.")
        console.print("-----------------------------\n")

        # Parse input tuples
        input_tuples = self.parse_module_purl_tuples(ps_module_purls)

        # Optionally edit tuples in editor
        if click.confirm("Do you want to edit these affects?"):
            console.print("Entering editor mode to modify input tuples...")
            input_tuples = self.edit_tuples_in_editor(input_tuples)
            console.print("\n--- Modified Tuples from Editor ---")
            if input_tuples:
                for m, p in input_tuples:
                    console.print(f"  - {m},{p}")
            else:
                console.print("  (No tuples provided after editing)")
            console.print("-----------------------------------\n")

        # Convert input tuples to MockAffect objects (state is always NEW for new affects)
        desired_new_affects_from_input: set[Affect] = {
            Affect(m, p, state="NEW") for m, p in input_tuples
        }

        final_affects_to_update: list[Affect] = []

        if not replace_mode:
            affects_to_add = (
                desired_new_affects_from_input - existing_affects
            )  # Only truly new ones
            if not affects_to_add:
                console.print(
                    "No new ps_module/purl tuples to add. All provided are already present or in different states."
                )
                return

            console.print("\n--- Affects to be ADDED ---")
            for affect in affects_to_add:
                console.print(f"  - {affect.ps_module},{affect.purl}")
            console.print("---------------------------\n")

            click.confirm("Confirm adding the above affects?", abort=True)

            final_affects_to_update = list(
                existing_affects | affects_to_add
            )  # Combine existing and new
            console.print("Adding affects...")

        else:
            if not existing_new_affects and not desired_new_affects_from_input:
                console.print(
                    "No existing 'NEW' affects to replace and no new affects provided. Nothing to do."
                )
                return

            console.print("\n--- Existing 'NEW' Affects to be REPLACED ---")
            if existing_new_affects:
                for affect in existing_new_affects:
                    console.print(f"  - {affect.ps_module},{affect.purl}")
            else:
                console.print("  (No existing affects with state 'NEW')")
            console.print("--------------------------------------------\n")

            console.print("\n--- New Affects that will REPLACE the above ---")
            if desired_new_affects_from_input:
                for affect in desired_new_affects_from_input:
                    console.print(f"  - {affect.ps_module},{affect.purl}")
            else:
                console.print("  (No new affects provided)")
            console.print("---------------------------------------------\n")

            click.confirm(
                "Confirm replacing existing 'NEW' affects with the new set?", abort=True
            )

            # Replace existing 'NEW' affects with the desired new ones, keep others as is
            final_affects_to_update = list(
                existing_non_new_affects | desired_new_affects_from_input
            )
            console.print("Replacing affects...")

        # Perform the update
        updated_flaw = self.osidb_api.update_flaw(flaw, affects=final_affects_to_update)
        console.print(f"\nSuccessfully updated flaw {updated_flaw.uuid}.")
        console.print("Current Affects on Flaw after update:")
        for affect in updated_flaw.affects:
            console.print(
                f"  - {affect.ps_module},{affect.purl} (State: {affect.state})"
            )
        console.print("\n")
