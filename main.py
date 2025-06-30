import argparse
import logging
import os
import json
import stat  # Import the stat module

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
        description="Analyzes permissions and generates 'default deny' rules."
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

    if not os.path.exists(path):
        logging.error(f"Path '{path}' does not exist.")
        return denied_resources

    if os.path.isfile(path):
        if not is_excluded(path, exclude_spec):
            permissions = check_file_permissions(path)
            if not permissions['read'] or not permissions['write']:
              denied_resources.append(path)
        return denied_resources

    for root, _, files in os.walk(path):
        for file in files:
            full_path = os.path.join(root, file)
            if not is_excluded(full_path, exclude_spec):
                permissions = check_file_permissions(full_path)
                if not permissions['read'] or not permissions['write']:
                    denied_resources.append(full_path)

    return denied_resources


def check_file_permissions(file_path):
    """
    Checks read and write permissions for a given file.
    """
    permissions = {'read': False, 'write': False}

    try:
        # Check if the file is readable
        if os.access(file_path, os.R_OK):
            permissions['read'] = True

        # Check if the file is writable
        if os.access(file_path, os.W_OK):
            permissions['write'] = True

    except OSError as e:
        logging.error(f"Error checking permissions for {file_path}: {e}")

    return permissions


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
        return f"# Default Deny ACL for {resource}" + os.linesep + f"deny all@{os.path.dirname(resource)} {os.path.basename(resource)}"
    elif format == "iam":
        if owner is None:
            raise ValueError("Owner must be specified for IAM format.")
        return json.dumps({
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


def main():
    """
    Main function to orchestrate the permission analysis and rule generation.
    """
    args = setup_argparse()

    # Input validation
    if not os.path.exists(args.path):
        console.print(f"[red]Error: Path '{args.path}' does not exist.[/red]")
        return

    if args.format == "iam" and args.owner is None:
        console.print("[red]Error: --owner must be specified when using IAM format.[/red]")
        return

    try:
        exclude_spec = load_exclude_patterns(args.exclude) if args.exclude else None
    except Exception as e:
        console.print(f"[red]Error loading exclude patterns: {e}[/red]")
        return
    
    try:
        denied_resources = analyze_permissions(args.path, exclude_spec)

        if not denied_resources:
            console.print("[green]No resources found lacking explicit permission grants.[/green]")
            return

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
                    for rule in rules:
                        f.write(rule + os.linesep)
                console.print(f"[green]Default deny rules written to '{args.output}'.[/green]")
            except Exception as e:
                console.print(f"[red]Error writing to output file: {e}[/red]")
        else:
            table = Table(title="Default Deny Rules", show_header=True, header_style="bold magenta")
            table.add_column("Resource", style="dim")
            table.add_column("Rule", style="green")

            for i, resource in enumerate(denied_resources):
              table.add_row(resource, rules[i])

            console.print(table)

    except Exception as e:
        console.print(f"[red]An unexpected error occurred: {e}[/red]")
        logging.exception("An unexpected error occurred")


if __name__ == "__main__":
    main()