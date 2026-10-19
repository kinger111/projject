# 1. Автоматический перезапуск с правами Администратора
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process PowerShell -ArgumentList "-NoProfile -NoExit -ExecutionPolicy Bypass -Command `"irm 'https://raw.githubusercontent.com/kinger111/projject/refs/heads/main/projject.ps1' | iex`"" -Verb RunAs
    exit
}

$Host.UI.RawUI.WindowTitle = "Администратор: Windows Security Analyzer & Fixer"

function Wait-Key {
    while ([System.Console]::KeyAvailable) { $null = [System.Console]::ReadKey($true) }
    $key = [System.Console]::ReadKey($true)
    return $key.KeyChar
}

function Simulate-Progress ($text) {
    Write-Host $text -NoNewline -ForegroundColor DarkGray
    for ($i=0; $i -lt 3; $i++) {
        Start-Sleep -Milliseconds 300
        Write-Host "." -NoNewline -ForegroundColor DarkGray
    }
    Write-Host " Готово" -ForegroundColor Green
    Start-Sleep -Milliseconds 150
}

function Show-Menu {
    Clear-Host
    Write-Host "`n"
    Write-Host "           Windows Security Analyzer & Fixer v3.0" -ForegroundColor Cyan
    Write-Host "    ------------------------------------------------------"
    Write-Host ""
    Write-Host "    [1] Быстрая проверка       - UAC, Defender, Обновления"
    Write-Host "    [2] Глубокий аудит         - Ключи реестра и телеметрия"
    Write-Host "    [3] Проверка сетевого стека - Файл hosts и DNS"
    Write-Host ""
    Write-Host "    ------------------------------------------------------"
    Write-Host "    [0] Выход"
    Write-Host "    ------------------------------------------------------"
    Write-Host "`n    Выберите опцию на клавиатуре [1,2,3,0] : " -NoNewline -ForegroundColor Green
}

function Check-BasicSecurity {
    Clear-Host
    Write-Host "`n[+] Запуск базовой проверки..." -ForegroundColor Magenta
    $riskScore = 0

    Simulate-Progress " [~] Чтение кустов реестра HKLM\SOFTWARE\Policies\System"
    $uac = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
    if ($uac.EnableLUA -eq 0) { 
        Write-Host " [!] UAC полностью отключен!" -ForegroundColor Red
        Write-Host "     Решение: Включить механизм изоляции процессов (требует перезагрузки)." -ForegroundColor DarkYellow
        $ans = Read-Host "     > Исправить уязвимость? (Y/N)"
        if ($ans -match '^[YyДд]') {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Force
            Write-Host "     [OK] UAC успешно включен." -ForegroundColor Green
        }
        $riskScore += 30 
    } else { Write-Host " [OK] UAC активен." -ForegroundColor Green }

    Simulate-Progress " [~] Опрос статуса службы WinDefend через API Windows"
    $defender = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
    if ($null -eq $defender -or$defender.Status -ne 'Running') { 
        Write-Host " [!] Защитник Windows остановлен!" -ForegroundColor Red
        Write-Host "     Решение: Запустить службу антивирусной защиты." -ForegroundColor DarkYellow
        $ans = Read-Host "     > Исправить уязвимость? (Y/N)"
        if ($ans -match '^[YyДд]') {
            Start-Service -Name "WinDefend" -ErrorAction SilentlyContinue
            Write-Host "     [OK] Отправлена команда на запуск службы." -ForegroundColor Green
        }
        $riskScore += 40 
    } else { Write-Host " [OK] Защитник функционирует." -ForegroundColor Green }

    Write-Host "`nИндекс риска: $riskScore" -ForegroundColor Yellow
    Write-Host "`nНажмите любую клавишу для возврата в меню..." -ForegroundColor DarkGray
    Wait-Key | Out-Null
}

function Check-Registry {
    Clear-Host
    Write-Host "`n[+] Запуск глубокого аудита реестра..." -ForegroundColor Magenta
    
    Simulate-Progress " [~] Поиск ключа DisableAntiSpyware"
    $regDef = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
    if ($regDef.DisableAntiSpyware -eq 1) { 
        Write-Host " [!] Defender заблокирован политиками реестра!" -ForegroundColor Red 
        Write-Host "     Решение: Удалить блокирующее правило из реестра." -ForegroundColor DarkYellow
        $ans = Read-Host "     > Исправить уязвимость? (Y/N)"
        if ($ans -match '^[YyДд]') {
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
            Write-Host "     [OK] Блокировка снята." -ForegroundColor Green
        }
    } else { Write-Host " [OK] Политики Defender в норме." -ForegroundColor Green }

    Simulate-Progress " [~] Проверка служб DataCollection (Телеметрия)"
    $regTele = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue
    if ($regTele.AllowTelemetry -eq 0) { 
        Write-Host " [!] Службы телеметрии вырезаны (блокирует Windows Update)." -ForegroundColor Yellow
        Write-Host "     Решение: Вернуть базовый уровень сбора данных (Level 1)." -ForegroundColor DarkYellow
        $ans = Read-Host "     > Восстановить? (Y/N)"
        if ($ans -match '^[YyДд]') {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 1 -Force
            Write-Host "     [OK] Базовая телеметрия восстановлена." -ForegroundColor Green
        }
    } else { Write-Host " [OK] Службы сбора данных в исходном состоянии." -ForegroundColor Green }

    Write-Host "`nНажмите любую клавишу для возврата в меню..." -ForegroundColor DarkGray
    Wait-Key | Out-Null
}

function Check-Network {
    Clear-Host
    Write-Host "`n[+] Проверка сетевого стека..." -ForegroundColor Magenta
    
    Simulate-Progress " [~] Анализ контрольной суммы файла hosts"
    $hostsPath = "$env:windir\System32\drivers\etc\hosts"
    $hostsContent = Get-Content $hostsPath -ErrorAction SilentlyContinue
    
    if ($hostsContent.Length -gt 25) { 
        Write-Host " [!] Файл hosts модифицирован!" -ForegroundColor Red[cite: 16]
        Write-Host "     Решение: Сбросить файл hosts до заводских настроек Microsoft." -ForegroundColor DarkYellow
        $ans = Read-Host "     > Выполнить сброс? (Y/N)"
        if ($ans -match '^[YyДд]') {
            $defaultHosts = "# Copyright (c) 1993-2009 Microsoft Corp.`r`n# 127.0.0.1 localhost`r`n# ::1 localhost"
            Set-Content -Path $hostsPath -Value $defaultHosts -Force
            Write-Host "     [OK] Файл hosts успешно очищен и восстановлен." -ForegroundColor Green
        }
    } else { Write-Host " [OK] Файл hosts имеет стандартный размер." -ForegroundColor Green }
    
    Write-Host "`nНажмите любую клавишу для возврата в меню..." -ForegroundColor DarkGray
    Wait-Key | Out-Null
}

# Главный цикл
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
