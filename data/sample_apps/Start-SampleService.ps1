<#!
.SYNOPSIS
Starts one VibeGuard Java sample service with local-only configuration.
#>

param(
    [Parameter(Mandatory)]
    [ValidateSet(
        "runnable-ai-orders-service",
        "ai-user-accounts-service",
        "ai-payments-service",
        "ai-file-upload-service",
        "ai-notifications-service",
        "ai-admin-dashboard-service",
        "ai-product-catalog-service",
        "ai-payment-refunds-service",
        "ai-billing-service",
        "ai-password-reset-service",
        "ai-account-deletion-service",
        "ai-role-management-service",
        "ai-audit-log-service",
        "ai-login-sessions-service",
        "ai-two-factor-service",
        "ai-staff-timesheet-service",
        "ai-card-storage-service",
        "ai-payment-webhooks-service",
        "ai-invoice-service",
        "ai-email-verification-service",
        "ai-account-linking-service",
        "ai-feature-flags-service",
        "ai-system-health-service",
        "ai-bulk-user-import-service",
        "ai-api-key-service",
        "ai-oauth-refresh-service",
        "ai-account-lockout-service"
    )]
    [string]$Service,

    [int]$Port = 8080
)

. "$PSScriptRoot/Set-SampleServiceEnvironment.ps1"

Push-Location "$PSScriptRoot/$Service"
try {
    mvn spring-boot:run "-Dspring-boot.run.arguments=--server.port=$Port"
}
finally {
    Pop-Location
}
