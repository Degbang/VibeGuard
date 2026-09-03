<#!
.SYNOPSIS
Sets local-only configuration for the VibeGuard Java sample services.

.DESCRIPTION
Generates missing process-scoped secrets without writing them to disk. Dot-source
this script from the PowerShell session that will start a sample service.
#>

function Set-LocalSecret {
    param([Parameter(Mandatory)][string]$Name)

    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($Name, "Process"))) {
        $bytes = [byte[]]::new(32)
        [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
        $value = [Convert]::ToBase64String($bytes)
        [Environment]::SetEnvironmentVariable($Name, $value, "Process")
    }
}

function Set-LocalValue {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Value
    )

    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($Name, "Process"))) {
        [Environment]::SetEnvironmentVariable($Name, $Value, "Process")
    }
}

@(
    "INTERNAL_STAFF_KEY",
    "ACCOUNT_API_KEY",
    "ROLE_ADMIN_KEY",
    "AUDIT_STAFF_KEY",
    "LOGIN_EVENTS_KEY",
    "TWO_FACTOR_SERVICE_KEY",
    "STAFF_TIMESHEET_KEY",
    "PAYMENT_VAULT_KEY",
    "PAYMENT_PROVIDER_API_KEY",
    "NOTIFICATION_WEBHOOK_SIGNING_SECRET",
    "ADMIN_API_KEY",
    "SPRING_SECURITY_USER_PASSWORD"
) | ForEach-Object { Set-LocalSecret -Name $_ }

Set-LocalValue -Name "ACCOUNT_OWNER_ID" -Value "demo-user"
Set-LocalValue -Name "SPRING_SECURITY_USER_NAME" -Value "demo"

if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable("TWO_FACTOR_DEMO_CODE", "Process"))) {
    $code = [Security.Cryptography.RandomNumberGenerator]::GetInt32(100000, 1000000).ToString()
    [Environment]::SetEnvironmentVariable("TWO_FACTOR_DEMO_CODE", $code, "Process")
}

Write-Host "Local sample-service configuration is ready for this PowerShell session."
Write-Host "NOTIFICATION_WEBHOOK_URL remains unset; configure it only with a trusted test receiver."
