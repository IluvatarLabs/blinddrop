# Security policy

## Supported versions

Security fixes are applied to the latest released `0.3.x` version. Development
snapshots and older versions are not supported release lines.

## Reporting a vulnerability

Use GitHub's **Report a vulnerability** link in the repository Security tab to
send a private report. Include the affected version, operating system, client
(stdio MCP, HTTP MCP or `run`), reproduction steps, impact and any safe
diagnostic output. Do not include real API keys, vault archives, passphrases,
session tokens or use logs. Do not open a public issue for an unpatched
vulnerability.

If private vulnerability reporting is not enabled, contact the maintainers
through the private contact method listed on the owning GitHub organization.
Public issue comments are not a confidential channel.

## Security boundary

BlindDrop is responsible for encrypted storage, restrictive file permissions,
separating owner operations from agent tools, authorized credential use, and
keeping credentials out of its request, response, error and logging paths.
The promise is that stored credentials remain unavailable through its agent
interfaces and those paths, assuming the agent harness and operating system
enforce the configured host permissions and the destination service is
trusted with the credential it receives.

The harness and OS are responsible for restricting the agent's access to
owner files, unlock input, the executable and its configuration, process
memory and administrative authority. BlindDrop does not implement a sandbox,
audit harness permissions, or detect an unrestricted agent mode. Literal
reflection checks block a credential echoed by the destination; they do not
defeat arbitrary transformations by a malicious recipient, and they do not
prevent misuse of an authorized API action. Streaming responses release
checked bytes incrementally; a later failure truncates delivery but cannot
recall bytes already delivered.
