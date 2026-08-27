$ErrorActionPreference = 'Stop'

$install = Get-Content -Raw 'install_engine.cpp'
$elevate = Get-Content -Raw 'elevate.cpp'
$service = Get-Content -Raw 'service_control.cpp'
$service_header = Get-Content -Raw 'service_control.hpp'
$ui = Get-Content -Raw 'ui/setup_window.cpp'

function Assert-Contains([string] $text, [string] $pattern, [string] $message) {
  if ($text -notmatch $pattern) {
    throw "EXPECT FAILED: $message"
  }
}

function Assert-NotContains([string] $text, [string] $pattern, [string] $message) {
  if ($text -match $pattern) {
    throw "EXPECT FAILED: $message"
  }
}

# 覆盖安装必须先停止服务，但不能删除原有 SCM 安装记录。
Assert-Contains $service_header 'bool StopService\(' 'service control exposes stop-only operation'
Assert-Contains $service 'bool StopService\(' 'stop-only service operation is implemented'
Assert-Contains $elevate 'StopService\(' 'elevated worker performs stop-only operation'
Assert-Contains $install 'EnsureServiceStopped\(' 'install preflight stops the installed service'
Assert-Contains $install 'return EnsureServiceStopped\(\)' 'install preflight returns stop result'

# 解压失败必须把实际原因传到错误页，不能只显示固定占位文案。
Assert-Contains $install 'extraction_error' 'install keeps extraction diagnostic'
Assert-Contains $install 'result\.error \+= L"："' 'install appends extraction diagnostic'

# 错误页控件必须受卡片底部约束，不能再用固定 y 导致按钮溢出。
Assert-Contains $ui 'card\.bottom' 'error page layout uses card bottom boundary'
Assert-NotContains $ui 'ButtonRect\(cx, card\.top \+ 300\.0f\)' 'error close button is not positioned past the card'
Assert-Contains $ui 'card\.top \+ 7[0-9]\.0f' 'error title is moved upward'

Write-Output 'p1_overwrite_install_contract_test: ok'
