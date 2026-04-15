# Privacy Policy

Last updated: April 2026

Runic is a self-hosted firewall management system designed with a "local-first" philosophy. Because the system is hosted on your own infrastructure, we do not have access to your data, and the software is not designed to share it.

## Data Handling and Storage

Runic does not collect or transmit user data. There is no telemetry, usage tracking, or automated crash reporting built into the system. Aside from optional SMTP connections for email alerts you configure yourself, the software does not make outbound API calls.

Everything stays on your server. Your configuration, keys, and secrets are stored as local files, and the system uses an on-disk SQLite database for management. Firewall logs are pulled from iptables or nftables solely for the local interface and never leave your network.

## Security and Authentication

We use industry-standard methods to protect your local installation. User passwords are hashed using bcrypt with a cost factor of 12 and a unique salt. For sensitive credentials like SMTP or API keys, we use AES-256-GCM encryption with keys derived via PBKDF2. These values are never stored in plain text.

Authentication is handled entirely on your hardware; Runic does not use third-party providers or OAuth integrations. Session management is handled through JWTs using signing keys stored locally on your server.

## Local Logging

Runic maintains several types of logs to help you manage your environment, including audit logs for configuration changes, agent heartbeats for connectivity, and alert histories. These remain on your system and are not transmitted to any external services.

## Network Communication

Communication is restricted to your own environment. Agents communicate with the Runic server over HTTPS, and neither the agents nor the server initiate external connections unless you have specifically set up an external alert destination.

## Open Source and Contact

Because Runic is open source, its behavior is fully transparent. You are encouraged to review the codebase to verify how data and security are handled. If you have questions or find an issue, please open a report in the repository.