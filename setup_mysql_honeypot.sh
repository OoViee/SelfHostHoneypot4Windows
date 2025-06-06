# Path to MySQL configuration file (typically found in ProgramData on Windows)
$mysqlConfPath = "C:\ProgramData\MySQL\MySQL Server X.X\my.ini"

# Path to SSL certificates (optional)
$sslCertPath = "C:\path\to\ssl\certificates"
$sslCa = "$sslCertPath\ca-cert.pem"
$sslCert = "$sslCertPath\server-cert.pem"
$sslKey = "$sslCertPath\server-key.pem"

# MySQL service name (might vary based on the version, usually 'MySQL' or 'MySQL80')
$mysqlServiceName = "MySQL"

# Function to update MySQL configuration
function Update-MySQLConfig {
    Write-Host "Updating MySQL configuration to allow lenient SSL handling..."

    # Backup the original MySQL config
    Copy-Item -Path $mysqlConfPath -Destination "$mysqlConfPath.bak" -Force

    # Append the SSL settings (or disable SSL completely)
    Add-Content -Path $mysqlConfPath -Value @"
[mysqld]
# Enable SSL but allow unverified SSL connections
ssl-ca = $sslCa
ssl-cert = $sslCert
ssl-key = $sslKey
ssl-mode = PREFERRED  # Allow SSL but don't enforce strict SSL requirement
# To disable SSL entirely, uncomment the next line:
# skip-ssl
"@

    # Restart the MySQL service to apply the changes
    Write-Host "Restarting MySQL service..."
    Restart-Service -Name $mysqlServiceName

    Write-Host "MySQL configuration updated and service restarted."
}

# Function to ensure MySQL is running
function Ensure-MySQLRunning {
    Write-Host "Checking if MySQL service is running..."
    $serviceStatus = Get-Service -Name $mysqlServiceName
    if ($serviceStatus.Status -ne 'Running') {
        Write-Host "MySQL service is not running. Starting MySQL..."
        Start-Service -Name $mysqlServiceName
    }
}

# Main script execution
Ensure-MySQLRunning
Update-MySQLConfig
