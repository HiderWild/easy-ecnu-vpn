$ErrorActionPreference = 'Stop'

$service = Get-Content -Raw 'service_control.cpp'
$service_header = Get-Content -Raw 'service_control.hpp'
$uninstall = Get-Content -Raw 'uninstall_engine.cpp'

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

Assert-Contains $service_header 'enum class ServicePresence' 'SCM lookup exposes an error state'
Assert-Contains $service 'ERROR_SERVICE_DOES_NOT_EXIST' 'missing service is classified as idempotent absence'
Assert-NotContains $service 'return !IsServiceInstalled\(service_name\)' 'SCM open failure is not treated as service absence'
Assert-Contains $service 'ControlService\(' 'stop result is examined by service removal'
Assert-Contains $service 'QueryServiceStatus\(' 'service stop polling remains observable'
Assert-Contains $service 'DeleteService\(' 'delete result is examined by service removal'
Assert-Contains $service 'ERROR_SERVICE_MARKED_FOR_DELETE' 'marked-for-delete is only accepted with verification'
Assert-Contains $service 'QueryServicePresence' 'wait path distinguishes absent from SCM query failure'

Assert-Contains $uninstall 'ServicePresence::Error' 'uninstall reports SCM query failure'
Assert-Contains $uninstall 'StopAndDeleteService' 'uninstall consumes service removal failure'
Assert-Contains $uninstall 'DeleteTreeResult' 'file cleanup returns an aggregate result'
Assert-Contains $uninstall 'MoveFileExW' 'delayed deletion is accepted only through an explicit API result'
Assert-Contains $uninstall 'result.error' 'uninstall exposes cleanup failures'
Assert-Contains $uninstall 'if \(!errors\.empty\(\)\)' 'uninstall gates success on the aggregate error list'

Write-Output 'p1_service_cleanup_contract_test: ok'
