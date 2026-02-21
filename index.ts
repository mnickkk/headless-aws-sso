import { chromium, type Browser, type Page } from 'playwright'

type OutputFormat = 'env' | 'json'

type Options = {
  profile: string
  ssoSession: string
  ssoRegion: string
  awsRegion: string
  opItem: string | null
  opVault: string | null
  opAccount: string | null
  opShareLink: string | null
  outputFormat: OutputFormat
  headless: boolean
  deviceUrlTimeoutMs: number
  automationTimeoutMs: number
  loginCompleteTimeoutMs: number
}

type LoginSecrets = {
  username: string
  password: string
  getOtp: () => Promise<string>
}

type CommandResult = {
  exitCode: number
  stdout: string
  stderr: string
}

type AwsProcessCredentials = {
  Version: number
  AccessKeyId: string
  SecretAccessKey: string
  SessionToken: string
  Expiration: string
}

type SsoLogin = {
  output: string[]
  deviceUrl: string | null
  exitCodePromise: Promise<number>
}

const DEFAULTS: Options = {
  profile: '',
  ssoSession: '',
  ssoRegion: 'us-east-1',
  awsRegion: 'us-east-1',
  opItem: null,
  opVault: null,
  opAccount: null,
  opShareLink: null,
  outputFormat: 'env',
  headless: true,
  deviceUrlTimeoutMs: 20_000,
  automationTimeoutMs: 90_000,
  loginCompleteTimeoutMs: 120_000,
}

// Entry point is at the bottom of the file to avoid TDZ issues with const declarations.

function resolveEnvVars(defaults: Options): Options {
  const opts = { ...defaults }
  opts.profile = process.env.AWS_SSO_PROFILE ?? opts.profile
  opts.ssoSession = process.env.AWS_SSO_SESSION ?? opts.ssoSession
  opts.ssoRegion = process.env.AWS_SSO_REGION ?? opts.ssoRegion
  opts.awsRegion = process.env.AWS_REGION ?? opts.awsRegion
  opts.opItem = process.env.OP_ITEM ?? opts.opItem
  opts.opVault = process.env.OP_VAULT ?? opts.opVault
  opts.opAccount = process.env.OP_ACCOUNT ?? opts.opAccount
  opts.opShareLink = process.env.OP_SHARE_LINK ?? opts.opShareLink
  if (process.env.OUTPUT_FORMAT === 'json' || process.env.OUTPUT_FORMAT === 'env') {
    opts.outputFormat = process.env.OUTPUT_FORMAT
  }
  if (process.env.HEADLESS === 'false') opts.headless = false
  if (process.env.DEVICE_URL_TIMEOUT_MS) {
    const v = Number(process.env.DEVICE_URL_TIMEOUT_MS)
    if (Number.isFinite(v) && v > 0) opts.deviceUrlTimeoutMs = Math.floor(v)
  }
  if (process.env.AUTOMATION_TIMEOUT_MS) {
    const v = Number(process.env.AUTOMATION_TIMEOUT_MS)
    if (Number.isFinite(v) && v > 0) opts.automationTimeoutMs = Math.floor(v)
  }
  if (process.env.LOGIN_COMPLETE_TIMEOUT_MS) {
    const v = Number(process.env.LOGIN_COMPLETE_TIMEOUT_MS)
    if (Number.isFinite(v) && v > 0) opts.loginCompleteTimeoutMs = Math.floor(v)
  }
  return opts
}

function validateOptions(opts: Options): void {
  const errors: string[] = []

  if (!opts.profile) {
    errors.push('--profile is required (or set AWS_SSO_PROFILE)')
  }
  if (!opts.ssoSession) {
    errors.push('--sso-session is required (or set AWS_SSO_SESSION)')
  }
  if (opts.opItem && opts.opShareLink) {
    errors.push('--op-item and --op-share-link are mutually exclusive; use one or the other')
  }
  if (!opts.opItem && !opts.opShareLink) {
    errors.push('One of --op-item (or OP_ITEM) or --op-share-link (or OP_SHARE_LINK) is required')
  }
  if (opts.opShareLink && !opts.opShareLink.startsWith('https://share.1password.com/')) {
    errors.push('--op-share-link must start with https://share.1password.com/')
  }

  if (errors.length > 0) {
    throw new Error(`Configuration errors:\n  ${errors.join('\n  ')}`)
  }
}

async function main(opts: Options): Promise<void> {
  validateOptions(opts)

  const isShareLinkMode = opts.opShareLink !== null

  ensureBinary('bun')
  if (!isShareLinkMode) ensureBinary('op')
  ensureBinary('aws')

  let secrets: LoginSecrets
  let browser: Browser | null = null
  let shareLinkCleanup: (() => Promise<void>) | null = null

  try {
    if (isShareLinkMode) {
      browser = await chromium.launch({ headless: opts.headless })
      const result = await getShareLinkSecrets(opts.opShareLink!, browser)
      secrets = result.secrets
      shareLinkCleanup = result.cleanup
    } else {
      secrets = await getOnePasswordSecrets(opts)
    }

    const ssoLogin = await startAwsSsoLogin(opts)

    if (ssoLogin.deviceUrl !== null) {
      if (browser) {
        await authorizeAwsDeviceWithBrowser(ssoLogin.deviceUrl, secrets, opts, browser)
      } else {
        await authorizeAwsDevice(ssoLogin.deviceUrl, secrets, opts)
      }
    }

    const loginExitCode = await withTimeout(
      ssoLogin.exitCodePromise,
      opts.loginCompleteTimeoutMs,
      'Timed out waiting for aws sso login to complete',
    )

    if (loginExitCode !== 0) {
      const tail = ssoLogin.output.slice(-40).join('\n')
      throw new Error(
        `aws sso login failed with exit code ${loginExitCode}\n\n${tail}`,
      )
    }

    const awsCreds = await exportAwsCredentials(opts.profile)
    printCredentials(awsCreds, opts)

    if (shareLinkCleanup) await shareLinkCleanup()
  } finally {
    if (browser) await browser.close()
  }
}

function parseArgs(argv: string[], defaults: Options): Options {
  const next = (i: number, flag: string): string => {
    const value = argv[i + 1]
    if (value === undefined || value.startsWith('-')) {
      throw new Error(`Missing value for ${flag}`)
    }
    return value
  }

  const nextMs = (i: number, flag: string): number => {
    const value = next(i, flag)
    const parsed = Number(value)
    if (!Number.isFinite(parsed) || parsed <= 0) {
      throw new Error(`Invalid number for ${flag}: ${value}`)
    }
    return Math.floor(parsed)
  }

  const opts: Options = { ...defaults }

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]

    if (arg === '--help' || arg === '-h') {
      process.stdout.write(renderHelp(defaults))
      process.exit(0)
    }

    if (arg === '--profile') {
      opts.profile = next(i, arg)
      i++
      continue
    }

    if (arg === '--sso-session') {
      opts.ssoSession = next(i, arg)
      i++
      continue
    }

    if (arg === '--sso-region') {
      opts.ssoRegion = next(i, arg)
      i++
      continue
    }

    if (arg === '--aws-region') {
      opts.awsRegion = next(i, arg)
      i++
      continue
    }

    if (arg === '--op-item') {
      opts.opItem = next(i, arg)
      i++
      continue
    }

    if (arg === '--op-vault') {
      opts.opVault = next(i, arg)
      i++
      continue
    }

    if (arg === '--op-account') {
      opts.opAccount = next(i, arg)
      i++
      continue
    }

    if (arg === '--op-share-link') {
      opts.opShareLink = next(i, arg)
      i++
      continue
    }

    if (arg === '--json') {
      opts.outputFormat = 'json'
      continue
    }

    if (arg === '--env') {
      opts.outputFormat = 'env'
      continue
    }

    if (arg === '--headed') {
      opts.headless = false
      continue
    }

    if (arg === '--headless') {
      opts.headless = true
      continue
    }

    if (arg === '--device-url-timeout-ms') {
      opts.deviceUrlTimeoutMs = nextMs(i, arg)
      i++
      continue
    }

    if (arg === '--automation-timeout-ms') {
      opts.automationTimeoutMs = nextMs(i, arg)
      i++
      continue
    }

    if (arg === '--login-complete-timeout-ms') {
      opts.loginCompleteTimeoutMs = nextMs(i, arg)
      i++
      continue
    }

    throw new Error(`Unknown argument: ${arg}`)
  }

  return opts
}

function renderHelp(defaults: Options): string {
  const lines = [
    'headless-aws-sso — Headless AWS SSO login with 1Password MFA automation',
    '',
    'Usage:',
    '  headless-aws-sso [options]',
    '  bun run index.ts [options]',
    '',
    'Required:',
    '  --profile <name>                    AWS profile to export                     [env: AWS_SSO_PROFILE]',
    '  --sso-session <name>                AWS SSO session name                      [env: AWS_SSO_SESSION]',
    '',
    '1Password mode (use exactly one):',
    '  --op-item <itemNameOrId>            1Password item (requires `op` CLI)        [env: OP_ITEM]',
    '  --op-share-link <url>               1Password share link URL (no `op` needed) [env: OP_SHARE_LINK]',
    '',
    'Optional:',
    `  --sso-region <region>               SSO region (default: ${defaults.ssoRegion})                [env: AWS_SSO_REGION]`,
    `  --aws-region <region>               Region for exports (default: ${defaults.awsRegion})        [env: AWS_REGION]`,
    '  --op-vault <vaultNameOrId>          1Password vault (op mode only)            [env: OP_VAULT]',
    '  --op-account <shorthandOrId>        1Password account (op mode only)          [env: OP_ACCOUNT]',
    '  --json                              Print credentials as JSON                 [env: OUTPUT_FORMAT=json]',
    '  --env                               Print credentials as export statements    (default)',
    '  --headed                            Run browser visibly (debug)               [env: HEADLESS=false]',
    '  --headless                          Run browser headless (default)',
    `  --device-url-timeout-ms <ms>        Wait for device URL (default: ${defaults.deviceUrlTimeoutMs})`,
    `  --automation-timeout-ms <ms>        Browser automation timeout (default: ${defaults.automationTimeoutMs})`,
    `  --login-complete-timeout-ms <ms>    Wait for login to finish (default: ${defaults.loginCompleteTimeoutMs})`,
    '',
    'Examples:',
    '  # Mode 1: op CLI',
    '  eval "$(headless-aws-sso --profile MyOrg/MyRole --sso-session MySession --op-item my-item)"',
    '',
    '  # Mode 2: share link (for LLM agents without op CLI)',
    '  eval "$(headless-aws-sso --profile MyOrg/MyRole --sso-session MySession --op-share-link https://share.1password.com/s#...)"',
    '',
    '  # Using env vars (e.g. from .env file)',
    '  eval "$(headless-aws-sso)"',
    '',
  ]
  return `${lines.join('\n')}\n`
}

function ensureBinary(binary: string): void {
  if (binary === 'bun') {
    return
  }

  if (Bun.which(binary) === null) {
    throw new Error(`Required binary not found in PATH: ${binary}`)
  }
}


async function getShareLinkSecrets(
  shareUrl: string,
  browser: Browser,
): Promise<{ secrets: LoginSecrets; cleanup: () => Promise<void> }> {
  const context = await browser.newContext()
  const page = await context.newPage()

  await page.goto(shareUrl, { waitUntil: 'networkidle', timeout: 30_000 })

  // Wait for the SPA to decrypt and render fields
  const deadline = Date.now() + 30_000
  let fields: { username: string; password: string } | null = null

  while (Date.now() < deadline) {
    // Check for error states
    const pageText = await page.innerText('body').catch(() => '')
    const lowerText = pageText.toLowerCase()
    if (lowerText.includes('expired') || lowerText.includes('no longer available')) {
      await context.close()
      throw new Error('1Password share link has expired or is no longer available')
    }
    if (lowerText.includes('enter your email') || lowerText.includes('verify your email')) {
      await context.close()
      throw new Error(
        '1Password share link requires email verification. ' +
        'Please recreate the link with "Anyone with the link" access.',
      )
    }

    fields = await page.evaluate(() => {
      // Walk the DOM looking for label-value pairs
      const getText = (el: Element): string => el.textContent?.trim() ?? ''

      // Strategy: find all elements that look like field containers
      // 1Password share pages render fields as label + value pairs
      let username = ''
      let password = ''

      // Look for elements with specific data attributes or class patterns
      const allElements = document.querySelectorAll('*')
      const labelValuePairs: { label: string; value: string }[] = []

      for (const el of allElements) {
        const text = getText(el)
        // Skip elements with too much text (they're containers)
        if (text.length > 500 || text.length === 0) continue

        const lowerText = text.toLowerCase()
        // Look for labels
        if (
          (lowerText === 'username' || lowerText === 'email' || lowerText === 'password') &&
          el.nextElementSibling
        ) {
          const valueText = getText(el.nextElementSibling)
          if (valueText.length > 0 && valueText.length < 300) {
            labelValuePairs.push({ label: lowerText, value: valueText })
          }
        }
      }

      for (const pair of labelValuePairs) {
        if ((pair.label === 'username' || pair.label === 'email') && !username) {
          username = pair.value
        }
        if (pair.label === 'password' && !password) {
          password = pair.value
        }
      }

      // Fallback: look for input elements with values
      if (!username) {
        const inputs = document.querySelectorAll('input[type="text"], input[type="email"]')
        for (const input of inputs) {
          const val = (input as HTMLInputElement).value
          if (val && val.includes('@')) {
            username = val
            break
          }
        }
      }

      if (!username || !password) return null
      return { username, password }
    }).catch(() => null)

    if (fields) break

    // Try clicking "Reveal" buttons to expose hidden password
    const revealBtn = page.locator('button:has-text("Reveal"), button:has-text("Show"), [aria-label*="reveal" i], [aria-label*="show" i]').first()
    const revealVisible = await revealBtn.isVisible().catch(() => false)
    if (revealVisible) {
      await revealBtn.click({ timeout: 2_000 }).catch(() => {})
      await page.waitForTimeout(500)
      continue
    }

    await page.waitForTimeout(1_000)
  }

  if (!fields) {
    const preview = await page.innerText('body').catch(() => '').then((t) => t.slice(0, 500))
    await context.close()
    throw new Error(
      `Failed to scrape credentials from 1Password share page.\n\nPage content preview:\n${preview}`,
    )
  }

  process.stderr.write(`[share-link] scraped username: ${fields.username}\n`)

  const getOtp = async (): Promise<string> => {
    // Read the live rotating TOTP code from the still-open page
    const otp = await page.evaluate(() => {
      // Look for elements containing exactly 6 digits (TOTP codes)
      const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT)
      let node: Text | null
      while ((node = walker.nextNode() as Text | null)) {
        const text = node.textContent?.trim() ?? ''
        // Match 6-digit codes, possibly with spaces (e.g. "123 456")
        const digits = text.replace(/\s/g, '')
        if (/^\d{6}$/.test(digits)) {
          return digits
        }
      }
      return null
    }).catch(() => null)

    if (!otp) {
      throw new Error('Failed to read TOTP code from 1Password share page')
    }
    return otp
  }

  // Verify we can read an OTP
  await getOtp()
  process.stderr.write('[share-link] verified TOTP code readable\n')

  return {
    secrets: { username: fields.username, password: fields.password, getOtp },
    cleanup: async () => { await context.close() },
  }
}

async function getOnePasswordSecrets(opts: Options): Promise<LoginSecrets> {
  const env = buildOpEnv(opts)

  const itemFieldsArgs = [
    'item',
    'get',
    opts.opItem!,
    '--format',
    'json',
    '--fields',
    'label=username,label=password',
  ]

  if (opts.opVault !== null) {
    itemFieldsArgs.push('--vault', opts.opVault)
  }

  const itemFields = await runCommandCapture('op', itemFieldsArgs, {
    env,
    teeStderr: true,
    teeStdout: false,
  })

  const fields = parseOpFields(itemFields.stdout)
  const username = getFirstField(fields, ['username', 'email'])
  const password = getFirstField(fields, ['password'])

  let otpCache: { otp: string; fetchedAtMs: number } | null = null

  const getOtp = async (): Promise<string> => {
    const now = Date.now()
    if (otpCache !== null && now - otpCache.fetchedAtMs < 5_000) {
      return otpCache.otp
    }

    const otpArgs = ['item', 'get', opts.opItem!, '--otp']
    if (opts.opVault !== null) {
      otpArgs.push('--vault', opts.opVault)
    }

    const otpResult = await runCommandCapture('op', otpArgs, {
      env,
      teeStderr: true,
      teeStdout: false,
    })

    const otp = otpResult.stdout.replace(/\s+/g, '')
    if (!/^\d{6,10}$/.test(otp)) {
      throw new Error('Failed to read OTP from 1Password item')
    }

    otpCache = { otp, fetchedAtMs: now }
    return otp
  }

  return { username, password, getOtp }
}

function buildOpEnv(opts: Options): Record<string, string | undefined> {
  const env: Record<string, string | undefined> = { ...process.env }
  if (opts.opAccount !== null) {
    env.OP_ACCOUNT = opts.opAccount
  }
  return env
}

type OpFieldObject = {
  id?: string
  label?: string
  purpose?: string
  reference?: string
  type?: string
  value?: string
}

type OpFieldsOutput =
  | Record<string, string | number | boolean | null>
  | OpFieldObject[]

function parseOpFields(text: string): Record<string, string> {
  const trimmed = text.trim()
  if (trimmed.length === 0) {
    throw new Error('Expected JSON, got empty output')
  }

  const parsed = JSON.parse(trimmed) as OpFieldsOutput

  if (Array.isArray(parsed)) {
    const record: Record<string, string> = {}

    for (const field of parsed) {
      const value = field.value
      if (typeof value !== 'string' || value.length === 0) {
        continue
      }

      const purpose = field.purpose
      if (typeof purpose === 'string') {
        const normalizedPurpose = purpose.toLowerCase()
        if (normalizedPurpose === 'username') {
          record.username = value
        }
        if (normalizedPurpose === 'password') {
          record.password = value
        }
      }

      const label = field.label
      if (typeof label === 'string' && label.length > 0) {
        record[label] = value
      }
    }

    return record
  }

  const record: Record<string, string> = {}
  for (const [key, value] of Object.entries(parsed)) {
    if (typeof value === 'string') {
      record[key] = value
    }
  }
  return record
}

function getFirstField(
  record: Record<string, string>,
  candidates: string[],
): string {
  for (const key of candidates) {
    const value = record[key]
    if (typeof value === 'string' && value.length > 0) {
      return value
    }
  }

  const lowered = new Map<string, string>()
  for (const [key, value] of Object.entries(record)) {
    lowered.set(key.toLowerCase(), value)
  }

  for (const key of candidates) {
    const value = lowered.get(key.toLowerCase())
    if (typeof value === 'string' && value.length > 0) {
      return value
    }
  }

  const keys = Object.keys(record)
  const preview = keys.slice(0, 30).join(', ')
  const suffix = keys.length > 30 ? ', ...' : ''
  const available = preview.length > 0 ? `${preview}${suffix}` : '(none)'

  throw new Error(
    `Missing expected 1Password field: ${candidates.join(', ')} (available keys: ${available})`,
  )
}


async function startAwsSsoLogin(opts: Options): Promise<SsoLogin> {
  const proc = Bun.spawn(
    ['aws', 'sso', 'login', '--sso-session', opts.ssoSession, '--use-device-code', '--no-browser'],
    {
      stdin: 'inherit',
      stdout: 'pipe',
      stderr: 'pipe',
    },
  )

  const output: string[] = []
  let deviceUrl: string | null = null

  const onLine = (line: string): void => {
    output.push(line)
    process.stderr.write(`[aws-sso] ${line}\n`)
    if (deviceUrl === null) {
      const match = line.match(
        /https:\/\/[^\s]+user_code=[A-Z0-9-]+/i,
      )
      if (match) {
        deviceUrl = match[0]
      }
    }
  }

  readLines(proc.stdout, onLine).catch(() => {})
  readLines(proc.stderr, onLine).catch(() => {})

  const firstEvent = await Promise.race([
    waitForDeviceUrl(() => deviceUrl).then((url) => ({ kind: 'url' as const, url })),
    proc.exited.then((code) => ({ kind: 'exit' as const, code })),
    sleep(opts.deviceUrlTimeoutMs).then(() => ({ kind: 'timeout' as const })),
  ])

  if (firstEvent.kind === 'exit') {
    if (firstEvent.code !== 0) {
      const tail = output.slice(-40).join('\n')
      throw new Error(
        `aws sso login exited before emitting device URL (exit code ${firstEvent.code})\n\n${tail}`,
      )
    }

    return { output, deviceUrl: null, exitCodePromise: proc.exited }
  }

  if (firstEvent.kind === 'timeout') {
    const tail = output.slice(-40).join('\n')
    throw new Error(
      `Timed out waiting for device URL from aws sso login\n\n${tail}`,
    )
  }

  return { output, deviceUrl: firstEvent.url, exitCodePromise: proc.exited }
}

async function authorizeAwsDeviceWithBrowser(
  deviceUrl: string,
  secrets: LoginSecrets,
  opts: Options,
  browser: Browser,
): Promise<void> {
  const page = await browser.newPage()
  try {
    await page.goto(deviceUrl, {
      waitUntil: 'networkidle',
      timeout: 30_000,
    })
    // Wait for the SPA to render an input or a button
    await page.locator('input, button').first().waitFor({ timeout: 15_000 }).catch(() => {})

    const deadline = Date.now() + opts.automationTimeoutMs
    while (Date.now() < deadline) {
      if (await looksAuthorized(page)) {
        return
      }

      await dismissCookieBanner(page)

      const didSomething =
        (await handleUsername(page, secrets.username)) ||
        (await handlePassword(page, secrets.password)) ||
        (await handleOtp(page, secrets.getOtp)) ||
        (await handleAllow(page))

      await page.waitForTimeout(didSomething ? 350 : 700)
    }

    throw new Error('Timed out waiting for device authorization')
  } finally {
    await page.close()
  }
}

async function authorizeAwsDevice(
  deviceUrl: string,
  secrets: LoginSecrets,
  opts: Options,
): Promise<void> {
  const browser = await chromium.launch({ headless: opts.headless })
  try {
    await authorizeAwsDeviceWithBrowser(deviceUrl, secrets, opts, browser)
  } finally {
    await browser.close()
  }
}

async function looksAuthorized(page: Page): Promise<boolean> {
  const url = page.url()
  if (url.includes('success') || url.includes('approved')) {
    return true
  }

  const markers = [
    'You have signed in',
    'Request approved',
    'Successfully signed in',
    'You can close this window',
  ]

  for (const marker of markers) {
    const visible = await page
      .getByText(marker, { exact: false })
      .first()
      .isVisible()
      .catch(() => false)
    if (visible) {
      return true
    }
  }

  return false
}

const USERNAME_SELECTORS = [
  'input#username',
  'input[name="username"]',
  'input[type="email"]',
  'input[name="email"]',
  'input.awsui-input[type="text"]',
]

const PASSWORD_SELECTORS = [
  'input#password',
  'input[name="password"]',
  'input[type="password"]',
]

const OTP_SELECTORS = [
  'input#otpCode',
  'input[name="otpCode"]',
  'input[name="verificationCode"]',
  'input[name="mfaCode"]',
  'input[id*="otp"]',
  'input[id*="mfa"]',
  'input[inputmode="numeric"]',
  'input.awsui-input[type="text"]',
]

const SUBMIT_SELECTORS = [
  'button:has-text("Next")',
  'button:has-text("Sign in")',
  'button:has-text("Verify")',
  'button:has-text("Continue")',
  'button:has-text("Submit")',
  'button[type="submit"]',
  'input[type="submit"]',
]

const ALLOW_SELECTORS = [
  'button:has-text("Allow")',
  'button:has-text("Authorize")',
  'button:has-text("Approve")',
  'button:has-text("Continue")',
  'button:has-text("Confirm")',
]

async function handleUsername(page: Page, username: string): Promise<boolean> {
  // Don't fill username into MFA/verification fields
  const isMfaPage = await page
    .getByText(/MFA|verification|authenticator/i)
    .first()
    .isVisible()
    .catch(() => false)
  if (isMfaPage) return false

  const filled = await fillVisible(page, USERNAME_SELECTORS, username)
  if (!filled) {
    return false
  }

  const clicked = await clickVisible(page, SUBMIT_SELECTORS)
  if (!clicked) {
    await page.keyboard.press('Enter').catch(() => undefined)
  }
  return true
}

async function dismissCookieBanner(page: Page): Promise<void> {
  const banner = page.locator('#awsccc-cb-buttons button:first-child, button:has-text("Accept cookies"), button:has-text("Accept")').first()
  const visible = await banner.isVisible().catch(() => false)
  if (visible) {
    // Only click "Accept" inside a cookie banner context, not a generic page button
    const text = await banner.innerText().catch(() => '')
    if (/accept/i.test(text)) {
      await banner.click({ timeout: 2_000 }).catch(() => {})
      process.stderr.write('[auth] dismissed cookie banner\n')
    }
  }
}

async function handlePassword(page: Page, password: string): Promise<boolean> {
  const filled = await fillVisible(page, PASSWORD_SELECTORS, password)
  if (!filled) {
    return false
  }

  const clicked = await clickVisible(page, SUBMIT_SELECTORS)
  if (!clicked) {
    await page.keyboard.press('Enter').catch(() => undefined)
  }
  return true
}

async function handleOtp(
  page: Page,
  getOtp: () => Promise<string>,
): Promise<boolean> {
  for (const selector of OTP_SELECTORS) {
    const locator = page.locator(selector).first()
    const exists = await locator.count().then((n) => n > 0)
    if (!exists) {
      continue
    }

    const visible = await locator.isVisible().catch(() => false)
    if (!visible) {
      continue
    }

    const otp = await getOtp()
    try {
      await locator.fill(otp)
    } catch {
      continue
    }

    const clicked = await clickVisible(page, SUBMIT_SELECTORS)
    if (!clicked) {
      await page.keyboard.press('Enter').catch(() => undefined)
    }
    return true
  }

  return false
}

async function handleAllow(page: Page): Promise<boolean> {
  const clicked = await clickVisible(page, ALLOW_SELECTORS)
  if (clicked) {
    return true
  }

  const allowByRole = await clickRoleButton(page, [
    'Allow',
    'Authorize',
    'Approve',
    'Continue',
    'Confirm',
  ])
  return allowByRole
}

async function fillVisible(
  page: Page,
  selectors: string[],
  value: string,
): Promise<boolean> {
  for (const selector of selectors) {
    const locator = page.locator(selector).first()
    const exists = await locator.count().then((n) => n > 0)
    if (!exists) {
      continue
    }

    const visible = await locator.isVisible().catch(() => false)
    if (!visible) {
      continue
    }

    try {
      await locator.fill(value)
      return true
    } catch {
      continue
    }
  }

  return false
}

async function clickVisible(page: Page, selectors: string[]): Promise<boolean> {
  for (const selector of selectors) {
    const locator = page.locator(selector).first()
    const exists = await locator.count().then((n) => n > 0)
    if (!exists) {
      continue
    }

    const visible = await locator.isVisible().catch(() => false)
    if (!visible) {
      continue
    }

    try {
      await locator.click({ timeout: 2_000 })
      return true
    } catch {
      continue
    }
  }

  return false
}

async function clickRoleButton(
  page: Page,
  labels: string[],
): Promise<boolean> {
  for (const label of labels) {
    const locator = page
      .getByRole('button', {
        name: new RegExp(`^\\s*${escapeRegExp(label)}\\s*$`, 'i'),
      })
      .first()

    const exists = await locator.count().then((n) => n > 0)
    if (!exists) {
      continue
    }

    const visible = await locator.isVisible().catch(() => false)
    if (!visible) {
      continue
    }

    try {
      await locator.click({ timeout: 2_000 })
      return true
    } catch {
      continue
    }
  }

  return false
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

async function exportAwsCredentials(
  profile: string,
): Promise<AwsProcessCredentials> {
  const result = await runCommandCapture(
    'aws',
    ['configure', 'export-credentials', '--profile', profile, '--format', 'process'],
    { teeStdout: false, teeStderr: true },
  )

  const data = JSON.parse(result.stdout.trim()) as Partial<AwsProcessCredentials>

  if (
    typeof data.Version !== 'number' ||
    typeof data.AccessKeyId !== 'string' ||
    typeof data.SecretAccessKey !== 'string' ||
    typeof data.SessionToken !== 'string' ||
    typeof data.Expiration !== 'string'
  ) {
    throw new Error('Unexpected credential format from aws configure export-credentials')
  }

  return {
    Version: data.Version,
    AccessKeyId: data.AccessKeyId,
    SecretAccessKey: data.SecretAccessKey,
    SessionToken: data.SessionToken,
    Expiration: data.Expiration,
  }
}

function printCredentials(creds: AwsProcessCredentials, opts: Options): void {
  if (opts.outputFormat === 'json') {
    process.stdout.write(
      `${JSON.stringify(
        {
          profile: opts.profile,
          region: opts.awsRegion,
          accessKeyId: creds.AccessKeyId,
          secretAccessKey: creds.SecretAccessKey,
          sessionToken: creds.SessionToken,
          expiration: creds.Expiration,
        },
        null,
        2,
      )}\n`,
    )
    return
  }

  const lines = [
    `export AWS_ACCESS_KEY_ID=${shellEscape(creds.AccessKeyId)}`,
    `export AWS_SECRET_ACCESS_KEY=${shellEscape(creds.SecretAccessKey)}`,
    `export AWS_SESSION_TOKEN=${shellEscape(creds.SessionToken)}`,
    `export AWS_REGION=${shellEscape(opts.awsRegion)}`,
    `export AWS_DEFAULT_REGION=${shellEscape(opts.awsRegion)}`,
    `export AWS_SESSION_EXPIRATION=${shellEscape(creds.Expiration)}`,
  ]

  process.stdout.write(`${lines.join('\n')}\n`)
}

function shellEscape(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`
}

async function runCommandCapture(
  command: string,
  args: string[],
  options: {
    env?: Record<string, string | undefined>
    teeStdout: boolean
    teeStderr: boolean
  },
): Promise<CommandResult> {
  const proc = Bun.spawn([command, ...args], {
    stdin: 'inherit',
    stdout: 'pipe',
    stderr: 'pipe',
    env: options.env,
  })

  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ])

  if (options.teeStdout) process.stdout.write(stdout)
  if (options.teeStderr) process.stderr.write(stderr)

  if (exitCode !== 0) {
    throw new Error(
      `${command} ${args.join(' ')} failed with exit code ${exitCode}`,
    )
  }

  return { exitCode, stdout, stderr }
}

async function readLines(
  stream: ReadableStream<Uint8Array>,
  onLine: (line: string) => void,
): Promise<void> {
  const reader = stream.getReader()
  const decoder = new TextDecoder()
  let buffer = ''

  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })
    let idx: number
    while ((idx = buffer.indexOf('\n')) !== -1) {
      onLine(buffer.slice(0, idx).replace(/\r$/, ''))
      buffer = buffer.slice(idx + 1)
    }
  }

  if (buffer.length > 0) {
    onLine(buffer.replace(/\r$/, ''))
  }
}

async function waitForDeviceUrl(get: () => string | null): Promise<string> {
  while (true) {
    const url = get()
    if (url !== null) {
      return url
    }
    await sleep(100)
  }
}

async function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  message: string,
): Promise<T> {
  let timeoutId: ReturnType<typeof setTimeout> | null = null
  const timeoutPromise = new Promise<T>((_, reject) => {
    timeoutId = setTimeout(() => reject(new Error(message)), timeoutMs)
  })

  try {
    return await Promise.race([promise, timeoutPromise])
  } finally {
    if (timeoutId !== null) {
      clearTimeout(timeoutId)
    }
  }
}

async function sleep(ms: number): Promise<void> {
  await new Promise<void>((resolve) => setTimeout(resolve, ms))
}

const options = parseArgs(Bun.argv.slice(2), resolveEnvVars(DEFAULTS))
await main(options)
