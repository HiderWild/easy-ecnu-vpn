const path = require('node:path')

function normalizeBuildPlatform(input = process.env.EXV_BUILD_PLATFORM || process.platform) {
  switch ((input || '').toLowerCase()) {
    case 'win32':
    case 'windows':
      return 'windows'
    case 'darwin':
    case 'mac':
    case 'macos':
      return 'macos'
    case 'linux':
      return 'linux'
    default:
      return input || process.platform
  }
}

function normalizeRendererTarget(input = process.env.EXV_RENDERER_TARGET || 'webview') {
  switch ((input || '').toLowerCase()) {
    case 'webview':
    case 'native':
    case 'desktop':
    default:
      return 'webview'
  }
}

function getBuildLayout() {
  const repoRoot = path.resolve(__dirname, '..', '..')
  const webuiRoot = path.resolve(__dirname, '..')
  const buildPlatform = normalizeBuildPlatform()
  const rendererTarget = normalizeRendererTarget()
  const buildRoot = path.join(repoRoot, 'build', buildPlatform)
  const webviewRoot = path.join(buildRoot, 'webview')
  const webviewRendererOutDir = path.join(webviewRoot, 'dist')
  const defaultCppBuildDir = buildPlatform === 'windows'
    ? path.join(repoRoot, 'build-windows', 'cpp')
    : path.join(buildRoot, 'cpp')

  return {
    repoRoot,
    webuiRoot,
    buildPlatform,
    rendererTarget,
    buildRoot,
    cppBuildDir: process.env.EXV_CPP_BUILD_DIR || defaultCppBuildDir,
    webviewRoot,
    rendererOutDir: webviewRendererOutDir,
    webviewRendererOutDir,
    webviewPackageDir: path.join(webviewRoot, 'package'),
  }
}

module.exports = {
  getBuildLayout,
  normalizeBuildPlatform,
  normalizeRendererTarget,
}
