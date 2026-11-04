# pa-permission-default-deny-enforcer

A rule generator. It analyzes existing permissions and generates draft 'default deny' rule text for resources that carry broad implicit access. It enforces nothing and applies nothing: the rules it writes must be adapted and applied by hand. Both output formats (ACL and IAM) are draft text templates, labelled as such in this README and in the header of every generated file. They are not valid rules for a named system as written: in particular, a verified correct IAM rule cannot be built from a local path alone, because an IAM ARN cannot be honestly built from one.

A resource is a candidate when, from its mode bits and ownership read with os.stat, it carries broad implicit access: write or execute permission bits for the group or for others (mode bits 0o033). Read only access for group and others, such as a file at mode 0444, is not a candidate. A file at mode 0666 is a candidate. Directories are tested the same way as files and are included as candidates. The test does not depend on the calling user.

Scanning an empty or missing target exits 1. A missing path and IAM format without an owner also exit 1. When --output is named and a real scan finds no candidates, a comment only rules file stating that no rules were generated is written and the run exits 0. Focused on tools for analyzing and assessing file system permissions.

## Install

```
git clone https://github.com/ShadowGuard-AI/pa-permission-default-deny-enforcer.git
cd pa-permission-default-deny-enforcer
pip install -r requirements.txt
```

## Usage

```
python3 main.py --path /path/to/analyze [options]
```

## Parameters

- `--path`: Required. The path to the directory or file to analyze.
- `--output`: Optional. The path to the output file where default deny rules will be written. If not specified, rules will be printed to the console.
- `--exclude`: Optional. Path to a file containing exclusion patterns (for example, .gitignore syntax).
- `--format`: The format of the default deny rules to generate, one of `acl` or `iam`, default `acl`.
- `--owner`: Optional, but required for IAM format. The owner for the default deny rules.

## Verified in this wave

`python3 main.py --help` could not run in this sandbox: it exits 1 at import with `ModuleNotFoundError: No module named 'pathspec'`, because `pathspec` is not installed and installs are not made in this wave. Parameters above are taken from the argument parser in `main.py`, and `main.py` passes `py_compile`. No live rule generation run is claimed.

## License

See LICENSE.
