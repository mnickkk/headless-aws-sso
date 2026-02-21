# headless-aws-sso

Headless AWS SSO login with 1Password MFA automation. Automates the browser-based SSO device authorization flow using credentials and TOTP codes from 1Password.

## Prerequisites

- [Bun](https://bun.sh) runtime
- [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
- [Playwright Chromium](https://playwright.dev/) — installed automatically or via `bunx playwright install chromium`
- An AWS SSO session configured in `~/.aws/config`

**Mode 1 (op CLI)** additionally requires:
- [1Password CLI (`op`)](https://developer.1password.com/docs/cli/get-started/)

**Mode 2 (share link)** requires:
- A 1Password share link with "Anyone with the link" access containing username, password, and TOTP fields

## Install

```sh
npm install -g headless-aws-sso
# or run directly without installing
npx headless-aws-sso --help
```

Then install the Playwright Chromium browser:

```sh
npx playwright install chromium
```

### From source (with Bun)

```sh
bun install
bun run index.ts --help
```

## Quick start

### Mode 1: `op` CLI

Use this when you have the 1Password CLI installed and configured.

```sh
eval "$(headless-aws-sso \
  --profile MyOrg/MyRole \
  --sso-session MySession \
  --op-item my-1password-item)"
```

### Mode 2: share link

Use this when you don't have `op` CLI — ideal for LLM agents and CI environments. Create a share link in 1Password with "Anyone with the link" access.

```sh
eval "$(headless-aws-sso \
  --profile MyOrg/MyRole \
  --sso-session MySession \
  --op-share-link 'https://share.1password.com/s#...')"
```

### Using environment variables

All options can be set via env vars. Bun automatically loads `.env` files.

```sh
cp .env.example .env
# Edit .env with your values
eval "$(headless-aws-sso)"
```

## Configuration

Options are resolved in order: defaults → environment variables → CLI arguments.

| CLI flag | Env var | Description | Required |
|---|---|---|---|
| `--profile <name>` | `AWS_SSO_PROFILE` | AWS profile to export credentials for | Yes |
| `--sso-session <name>` | `AWS_SSO_SESSION` | AWS SSO session name (from `~/.aws/config`) | Yes |
| `--op-item <id>` | `OP_ITEM` | 1Password item name or ID (Mode 1) | One of these |
| `--op-share-link <url>` | `OP_SHARE_LINK` | 1Password share link URL (Mode 2) | two required |
| `--sso-region <region>` | `AWS_SSO_REGION` | SSO region (default: `us-east-1`) | No |
| `--aws-region <region>` | `AWS_REGION` | Region for credential exports (default: `us-east-1`) | No |
| `--op-vault <id>` | `OP_VAULT` | 1Password vault (Mode 1 only) | No |
| `--op-account <id>` | `OP_ACCOUNT` | 1Password account (Mode 1 only) | No |
| `--json` | `OUTPUT_FORMAT=json` | Output credentials as JSON | No |
| `--env` | `OUTPUT_FORMAT=env` | Output as shell export statements (default) | No |
| `--headed` | `HEADLESS=false` | Show browser window (useful for debugging) | No |
| `--headless` | | Run browser headless (default) | No |

## How it works

1. Starts `aws sso login --sso-session <name> --use-device-code --no-browser` and captures the device authorization URL
2. Fetches credentials and TOTP from 1Password (via `op` CLI or by scraping a share link)
3. Opens the device authorization URL in a headless Chromium browser
4. Automates the SSO login flow: fills username → password → TOTP → approves device
5. Waits for `aws sso login` to complete, then exports session credentials

### Share link mode

In share link mode, the 1Password share page stays open as a live TOTP source — each time a TOTP code is needed, it reads the current rotating code directly from the page. No local TOTP generation is needed.

This mode is designed for LLM/agent use cases where installing and authenticating the `op` CLI is impractical.

## Output formats

**Shell exports (default):**
```sh
export AWS_ACCESS_KEY_ID='ASIA...'
export AWS_SECRET_ACCESS_KEY='...'
export AWS_SESSION_TOKEN='...'
export AWS_REGION='us-east-1'
export AWS_DEFAULT_REGION='us-east-1'
export AWS_SESSION_EXPIRATION='2024-01-01T12:00:00Z'
```

**JSON (`--json`):**
```json
{
  "profile": "MyOrg/MyRole",
  "region": "us-east-1",
  "accessKeyId": "ASIA...",
  "secretAccessKey": "...",
  "sessionToken": "...",
  "expiration": "2024-01-01T12:00:00Z"
}
```

## License

MIT
