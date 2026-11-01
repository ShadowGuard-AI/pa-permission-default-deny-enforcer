import argparse
import logging
import os
import pwd
import json
import stat  # Import the stat module
import sys

from pathspec import PathSpec
from pathspec.patterns import GitWildMatchPattern
from rich.console import Console
from rich.table import Column, Table

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

console = Console()


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(
        description="Analyzes permissions and generates draft 'default deny' rule text templates. The rules are not applied by this tool; they must be adapted and applied by hand."
    )

    parser.add_argument(
        "--path",
        type=str,
        required=True,
        help="The path to the directory or file to analyze.",
    )
    parser.add_argument(
        "--output",
        type=str,
        required=False,
        help="The path to the output file where default deny rules will be written. If not specified, rules will be printed to the console.",
    )
    parser.add_argument(
        "--exclude",
        type=str,
        required=False,
        help="Path to a file containing exclusion patterns (e.g., .gitignore syntax).",
    )
    parser.add_argument(
        "--format",
        type=str,
        choices=["acl", "iam"],
        default="acl",
        help="The format of the default deny rules to generate (acl or iam).",
    )
    parser.add_argument(
        "--owner",
        type=str,
        required=False,
        help="The owner for the default deny rules. Required for certain formats like IAM.",
    )

    return parser.parse_args()


def is_excluded(path, exclude_spec):
    """
    Checks if a given path is excluded based on the provided PathSpec.
    """
    if exclude_spec is None:
        return False
    return exclude_spec.match_file(path)


def analyze_permissions(path, exclude_spec=None):
    """
    Analyzes permissions for the given path and its subdirectories/files.

    Args:
        path (str): The path to analyze.
        exclude_spec (PathSpec, optional): A PathSpec object containing exclusion patterns. Defaults to None.

    Returns:
        list: A list of resources that lack specific permission grants (potential default deny candidates).
    """

    denied_resources = []
    scanned = 0

    if not os.path.exists(path):
        logging.error(f"Path '{path}' does not exist.")
        return denied_resources, scanned

    if os.path.isfile(path):
        if not is_excluded(path, exclude_spec):
            scanned += 1
            if is_default_deny_candidate(path):
                denied_resources.append(path)
        return denied_resources, scanned

    if os.path.isdir(path):
        # The target directory itself is the scan root, not a scanned
        # resource: an empty directory therefore scans nothing and the
        # caller exits 1. Subdirectories found in the walk are scanned
        # resources and are tested as candidates like files.
        for root, dirs, files in os.walk(path):
            for name in dirs:
                full_path = os.path.join(root, name)
                if not is_excluded(full_path, exclude_spec):
                    scanned += 1
                    if is_default_deny_candidate(full_path):
                        denied_resources.append(full_path)
            for file in files:
                full_path = os.path.join(root, file)
                if not is_excluded(full_path, exclude_spec):
                    scanned += 1
                    if is_default_deny_candidate(full_path):
                        denied_resources.append(full_path)

    return denied_resources, scanned


def is_default_deny_candidate(resource_path):
    """
    Caller independent candidate test, computed from mode bits and
    ownership read with os.stat. A resource is a candidate when it
    carries broad implicit access: write or execute permission bits
    for the group or for others (mode bits 0o033). Read only access
    for group and others, such as mode 0444, is not a candidate.
    Directories are tested the same way as files.
    """
    try:
        info = os.stat(resource_path)
    except OSError as e:
        logging.error(f"Error checking permissions for {resource_path}: {e}")
        return False
    mode = stat.S_IMODE(info.st_mode)
    try:
        owner = pwd.getpwuid(info.st_uid).pw_name
    except KeyError:
        owner = str(info.st_uid)
    logging.debug(f"{resource_path}: mode {oct(mode)}, owner {owner}")
    return bool(mode & 0o033)


def check_file_permissions(file_path):
    """
    Returns the mode bits and owner for a given resource, read with
    os.stat. Kept for callers that need the raw facts; the candidate
    test above does not use the calling user's access.
    """
    try:
        info = os.stat(file_path)
        try:
            owner = pwd.getpwuid(info.st_uid).pw_name
        except KeyError:
            owner = str(info.st_uid)
        return {'mode': stat.S_IMODE(info.st_mode), 'owner': owner}
    except OSError as e:
        logging.error(f"Error checking permissions for {file_path}: {e}")
        return {'mode': 0, 'owner': None}


def load_exclude_patterns(exclude_file):
    """
    Loads exclusion patterns from a file (e.g., .gitignore).
    """
    try:
        with open(exclude_file, "r") as f:
            patterns = [GitWildMatchPattern(line.strip()) for line in f if line.strip()]
        return PathSpec.from_patterns(patterns)
    except FileNotFoundError:
        logging.warning(f"Exclude file '{exclude_file}' not found.  Continuing without exclusions.")
        return None
    except Exception as e:
        logging.error(f"Error reading exclude file '{exclude_file}': {e}")
        return None


def generate_default_deny_rule(resource, format, owner=None):
    """
    Generates a default deny rule in the specified format.

    Args:
        resource (str): The resource to deny access to.
        format (str): The format of the rule (acl or iam).
        owner (str, optional): The owner of the resource (required for IAM). Defaults to None.

    Returns:
        str: The generated default deny rule.
    """

    if format == "acl":
        return f"# Draft text template, default deny ACL sketch for {resource}. Not a valid rule for any named system as written; adapt and apply by hand." + os.linesep + f"deny all@{os.path.dirname(resource)} {os.path.basename(resource)}"
    elif format == "iam":
        if owner is None:
            raise ValueError("Owner must be specified for IAM format.")
        return "# Draft text template: the IAM sketch below is not a valid IAM policy as written, because a local path is not an ARN. Adapt it and apply it by hand." + os.linesep + json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Principal": {"AWS": f"arn:aws:iam::{owner}:root"},
                    "Action": "*",
                    "Resource": resource,
                }
            ],
        }, indent=4)
    else:
        raise ValueError(f"Unsupported format: {format}")


DRAFT_HEADER = "# Draft text template: generated by pa-permission-default-deny-enforcer. These are draft rule sketches, not valid rules for a named system as written, and nothing was applied. Adapt and apply them by hand.\n"


def main():
    """
    Main function to orchestrate the permission analysis and rule generation.
    Returns an exit code: 1 on errors and on scans that scanned nothing,
    0 otherwise.
    """
    args = setup_argparse()

    # Input validation
    if not os.path.exists(args.path):
        console.print(f"[red]Error: Path '{args.path}' does not exist.[/red]")
        return 1

    if args.format == "iam" and args.owner is None:
        console.print("[red]Error: --owner must be specified when using IAM format.[/red]")
        return 1

    try:
        exclude_spec = load_exclude_patterns(args.exclude) if args.exclude else None
    except Exception as e:
        console.print(f"[red]Error loading exclude patterns: {e}[/red]")
        return 1

    try:
        denied_resources, scanned = analyze_permissions(args.path, exclude_spec)

        if scanned == 0:
            console.print("[red]Error: Nothing was scanned at the named path.[/red]")
            return 1

        if not denied_resources:
            console.print("[green]No resources found carrying broad implicit access. No rules were generated.[/green]")
            if args.output:
                try:
                    with open(args.output, "w") as f:
                        f.write(DRAFT_HEADER)
                        f.write("# No rules were generated: no candidate resources were found in this scan.\n")
                    console.print(f"[green]Comment only rules file written to '{args.output}'.[/green]")
                except Exception as e:
                    console.print(f"[red]Error writing to output file: {e}[/red]")
                    return 1
            return 0

        rules = []
        for resource in denied_resources:
            try:
                rule = generate_default_deny_rule(resource, args.format, args.owner)
                rules.append(rule)
            except ValueError as e:
                console.print(f"[red]Error generating rule for {resource}: {e}[/red]")
                continue

        if args.output:
            try:
                with open(args.output, "w") as f:
                    f.write(DRAFT_HEADER)
                    for rule in rules:
                        f.write(rule + os.linesep)
                console.print(f"[green]Draft default deny rule templates written to '{args.output}'. Nothing was applied.[/green]")
            except Exception as e:
                console.print(f"[red]Error writing to output file: {e}[/red]")
                return 1
        else:
            console.print("Draft text templates only. Nothing was applied; adapt and apply by hand.")
            table = Table(title="Default Deny Rules (draft templates)", show_header=True, header_style="bold magenta")
            table.add_column("Resource", style="dim")
            table.add_column("Rule", style="green")

            for i, resource in enumerate(denied_resources):
              table.add_row(resource, rules[i])

            console.print(table)

    except Exception as e:
        console.print(f"[red]An unexpected error occurred: {e}[/red]")
        logging.exception("An unexpected error occurred")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())