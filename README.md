# pa-permission-default-deny-enforcer
A rule generator. It analyzes existing permissions and generates draft 'default deny' rule text for resources that carry broad implicit access. It enforces nothing and applies nothing: the rules it writes must be adapted and applied by hand. Both output formats (ACL and IAM) are draft text templates, labelled as such in this README and in the header of every generated file. They are not valid rules for a named system as written: in particular, a verified correct IAM rule cannot be built from a local path alone, because an IAM ARN cannot be honestly built from one.

A resource is a candidate when, from its mode bits and ownership read with os.stat, it carries broad implicit access: write or execute permission bits for the group or for others (mode bits 0o033). Read only access for group and others, such as a file at mode 0444, is not a candidate. A file at mode 0666 is a candidate. Directories are tested the same way as files and are included as candidates. The test does not depend on the calling user.

Scanning an empty or missing target exits 1. A missing path and IAM format without an owner also exit 1. When --output is named and a real scan finds no candidates, a comment only rules file stating that no rules were generated is written and the run exits 0. - Focused on Tools for analyzing and assessing file system permissions

## Install
`git clone https://github.com/ShadowGuardAI/pa-permission-default-deny-enforcer`

## Usage
`python main.py --path /path/to/analyze --output rules.txt --format acl`

## Parameters
- `-h`: Show help message and exit
- `--path`: The path to the directory or file to analyze.
- `--output`: The path to the output file where default deny rules will be written. If not specified, rules will be printed to the console.
- `--exclude`: Path to a file containing exclusion patterns (e.g., .gitignore syntax).
- `--format`: The format of the default deny rules to generate (acl or iam).
- `--owner`: The owner for the default deny rules. Required for certain formats like IAM.

## License
Copyright (c) ShadowGuardAI
