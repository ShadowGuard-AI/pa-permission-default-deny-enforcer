# pa-permission-default-deny-enforcer
Analyzes existing permissions and automatically generates 'default deny' rules for any resource lacking specific permission grants. This helps enforce a least privilege model where everything is implicitly denied unless explicitly allowed. Supports different default deny rule formats (e.g., ACLs, IAM policies). - Focused on Tools for analyzing and assessing file system permissions

## Install
`git clone https://github.com/ShadowGuardAI/pa-permission-default-deny-enforcer`

## Usage
`./pa-permission-default-deny-enforcer [params]`

## Parameters
- `-h`: Show help message and exit
- `--path`: The path to the directory or file to analyze.
- `--output`: The path to the output file where default deny rules will be written. If not specified, rules will be printed to the console.
- `--exclude`: No description provided
- `--format`: No description provided
- `--owner`: The owner for the default deny rules. Required for certain formats like IAM.

## License
Copyright (c) ShadowGuardAI
