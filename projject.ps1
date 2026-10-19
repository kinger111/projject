if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process PowerShell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"irm 'https://raw.githubusercontent.com/kinger111/projject/refs/heads/main/projject.ps1' | iex`"" -Verb RunAs
    exit
}
$Host.UI.RawUI.WindowTitle = "Администратор: Windows Security Analyzer"

function Wait-Key {
    $Host.UI.RawUI.FlushInputBuffer()
    $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    return $key.Character
}

function Show-Menu {
    Clear-Host
    Write-Host "`n"
    Write-Host "                Windows Security Analyzer v1.0" -ForegroundColor Cyan
    Write-Host "    ------------------------------------------------------"
    Write-Host ""
    Write-Host "    [1] Быстрая проверка       - UAC, Defender, Обновления"
    Write-Host "    [2] Глубокий аудит         - Ключи реестра и телеметрия"
    Write-Host "    [3] Проверка сетевого стека - Файл hosts и DNS"
    Write-Host ""
    Write-Host "    ------------------------------------------------------"
    Write-Host ""
    Write-Host "    [0] Выход"
    Write-Host "    ------------------------------------------------------"
    Write-Host "`n    Выберите опцию на клавиатуре [1,2,3,0] : " -NoNewline -ForegroundColor Green
}

function Check-BasicSecurity {
    Clear-Host
    Write-Host "`n[+] Запуск базовой проверки..." -ForegroundColor Magenta
    $riskScore = 0

    $uac = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
    if ($uac.EnableLUA -eq 0) { Write-Host " [!] UAC полностью отключен!" -ForegroundColor Red; $riskScore += 30 } 
    else { Write-Host " [OK] UAC активен." -ForegroundColor Green }

    $defender = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
    if ($null -eq $defender -or$defender.Status -ne 'Running') { Write-Host " [!] Защитник Windows остановлен!" -ForegroundColor Red; $riskScore += 40 } 
    else { Write-Host " [OK] Защитник функционирует." -ForegroundColor Green }

    Write-Host "`nИндекс риска: $riskScore" -ForegroundColor Yellow
    Write-Host "`nНажмите любую клавишу для возврата в меню..." -ForegroundColor DarkGray
    Wait-Key | Out-Null
}

function Check-Registry {
    Clear-Host
    Write-Host "`n[+] Запуск глубокого аудита реестра..." -ForegroundColor Magenta
    
    $regDef = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
    if ($regDef.DisableAntiSpyware -eq 1) { Write-Host " [!] Defender заблокирован политиками!" -ForegroundColor Red } 
    else { Write-Host " [OK] Политики Defender в норме." -ForegroundColor Green }

    Write-Host "`nНажмите любую клавишу для возврата в меню..." -ForegroundColor DarkGray
    Wait-Key | Out-Null
}

function Check-Network {
    Clear-Host
    Write-Host "`n[+] Проверка сетевого стека..." -ForegroundColor Magenta
    $hostsPath = "$env:windir\System32\drivers\etc\hosts"
    $hostsContent = Get-Content $hostsPath -ErrorAction SilentlyContinue
    
    if ($hostsContent.Length -gt 25) { Write-Host " [!] Файл hosts модифицирован!" -ForegroundColor Red } 
    else { Write-Host " [OK] Файл hosts имеет стандартный размер." -ForegroundColor Green }
    
    Write-Host "`nНажмите любую клавишу для возврата в меню..." -ForegroundColor DarkGray
    Wait-Key | Out-Null
}

while ($true) {
    Show-Menu
    $choice = Wait-Key
    
    switch ($choice) {
        '1' { Check-BasicSecurity }
        '2' { Check-Registry }
        '3' { Check-Network }
        '0' { Clear-Host; exit }
    }
}
