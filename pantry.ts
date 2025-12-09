import type { PantryConfig } from 'ts-pantry'

/**
 * Pantry configuration for the mail server project
 *
 * This handles:
 * - Zig dependency management (zig-tls)
 * - Build automation for all platforms
 * - Release workflow with zig-bump
 */
export default {
  dependencies: {
    'ziglang.org': '^0.16.0-dev',
  },

  // Auto-install zig when needed
  autoInstall: true,

  // Post-setup lifecycle for building the project
  postSetup: {
    enabled: true,
    commands: [
      {
        name: 'fetch-deps',
        command: 'zig',
        args: ['build', '--fetch'],
        description: 'Fetch Zig dependencies (zig-tls)',
      },
    ],
  },

  // Service configuration for local development
  services: {
    enabled: true,
    autoStart: false,
  },

  verbose: true,
} satisfies PantryConfig

/**
 * Build targets for cross-compilation
 */
export const BUILD_TARGETS = [
  { target: 'x86_64-linux-gnu', name: 'x86_64-linux' },
  { target: 'aarch64-linux-gnu', name: 'aarch64-linux' },
  { target: 'x86_64-macos', name: 'x86_64-macos' },
  { target: 'aarch64-macos', name: 'aarch64-macos' },
] as const

/**
 * Scripts for common operations
 * These can be run with: pantry run <script-name>
 */
export const scripts = {
  // Build for native platform
  build: 'zig build -Doptimize=ReleaseFast',

  // Build for all platforms
  'build:all': async () => {
    const { $ } = await import('bun')
    for (const { target, name } of BUILD_TARGETS) {
      console.log(`Building for ${name}...`)
      await $`zig build -Doptimize=ReleaseFast -Dtarget=${target}`
    }
  },

  // Package all binaries into tarballs
  'package:all': async () => {
    const { $ } = await import('bun')
    const fs = await import('fs/promises')

    await fs.mkdir('dist', { recursive: true })

    for (const { name } of BUILD_TARGETS) {
      const binaryPath = `zig-out/bin/${name}/smtp-server-${name}`
      const tarPath = `dist/smtp-server-${name}.tar.gz`
      await $`tar -czvf ${tarPath} -C zig-out/bin/${name} smtp-server-${name}`
      console.log(`Packaged: ${tarPath}`)
    }
  },

  // Release workflow using zig-bump
  release: async (releaseType: 'patch' | 'minor' | 'major' = 'patch') => {
    const { $ } = await import('bun')

    // 1. Bump version with zig-bump (commits, tags, pushes)
    console.log(`Bumping ${releaseType} version...`)
    await $`bump ${releaseType} --all`

    // The push triggers GitHub Actions which builds and uploads binaries
    console.log('Release tag pushed. GitHub Actions will build and publish binaries.')
  },

  // Local release (build + package locally, upload to existing release)
  'release:local': async () => {
    const { $ } = await import('bun')
    const fs = await import('fs/promises')

    // Get current version from build.zig.zon
    const content = await fs.readFile('build.zig.zon', 'utf-8')
    const versionMatch = content.match(/\.version\s*=\s*"([^"]+)"/)
    const version = versionMatch?.[1] ?? '0.0.0'

    console.log(`Building release for v${version}...`)

    // Build all platforms
    for (const { target, name } of BUILD_TARGETS) {
      console.log(`Building for ${name}...`)
      await $`zig build -Doptimize=ReleaseFast -Dtarget=${target}`
    }

    // Package
    await fs.mkdir('dist', { recursive: true })
    for (const { name } of BUILD_TARGETS) {
      const tarPath = `dist/smtp-server-${name}.tar.gz`
      await $`tar -czvf ${tarPath} -C zig-out/bin/${name} smtp-server-${name}`
    }

    // Upload to GitHub release
    console.log(`Uploading binaries to v${version} release...`)
    await $`gh release upload v${version} dist/*.tar.gz --clobber`

    console.log('Release complete!')
  },

  // Test the mail server
  test: 'zig build test',

  // Run the mail server locally
  dev: 'zig build run',
}
