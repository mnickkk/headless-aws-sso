// Playwright internally requires these optional packages (electron, chromium-bidi)
// which are not installed and not needed for our Chromium-only usage.
// Marking them external lets the bundler skip them; Playwright catches the
// require errors at runtime and only fails if you actually use those codepaths.
const playwrightExternals = [
  'electron',
  'chromium-bidi/lib/cjs/bidiMapper/BidiMapper',
  'chromium-bidi/lib/cjs/cdp/CdpConnection',
]

type BunTarget = 'bun-darwin-arm64' | 'bun-linux-x64' | 'bun-linux-arm64'

const ALL_TARGETS: BunTarget[] = [
  'bun-darwin-arm64',
  'bun-linux-x64',
  'bun-linux-arm64',
]

// Parse CLI args for single-target mode (used by CI)
function parseArgs(argv: string[]): { targets: BunTarget[]; outfile: string | null } {
  let target: string | null = null
  let outfile: string | null = null

  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--target' && argv[i + 1]) {
      target = argv[++i]!
    } else if (argv[i] === '--outfile' && argv[i + 1]) {
      outfile = argv[++i]!
    }
  }

  if (target) {
    if (!ALL_TARGETS.includes(target as BunTarget)) {
      process.stderr.write(`Unknown target: ${target}\nValid targets: ${ALL_TARGETS.join(', ')}\n`)
      process.exit(1)
    }
    return { targets: [target as BunTarget], outfile }
  }

  return { targets: ALL_TARGETS, outfile: null }
}

const { targets, outfile } = parseArgs(Bun.argv.slice(2))

for (const target of targets) {
  const out = outfile ?? `dist/headless-aws-sso-${target.replace('bun-', '')}`
  process.stderr.write(`Building ${target} → ${out}\n`)

  const result = await Bun.build({
    entrypoints: ['./index.ts'],
    compile: {
      target,
      outfile: out,
    },
    external: playwrightExternals,
    minify: true,
    sourcemap: 'linked',
  })

  if (!result.success) {
    process.stderr.write(`Failed to build ${target}:\n`)
    for (const log of result.logs) {
      process.stderr.write(`  ${log}\n`)
    }
    process.exit(1)
  }

  process.stderr.write(`  ✓ ${out}\n`)
}

process.stderr.write('\nAll targets built successfully.\n')
