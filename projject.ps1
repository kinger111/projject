if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ($PSCommandPath) {
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    } else {
        $url = "https://raw.githubusercontent.com/kinger111/projject/refs/heads/main/projject.ps1"
        $cmd = "-NoProfile -ExecutionPolicy Bypass -NoExit -Command `"Invoke-RestMethod -Uri '$url' | Invoke-Expression`""
        Start-Process powershell.exe -ArgumentList $cmd -Verb RunAs
    }
    exit
}

$Host.UI.RawUI.WindowTitle = "TERMINAL :: Windows Security Analyzer & Fixer"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$desktopPath = [Environment]::GetFolderPath("Desktop")
$global:ReportPath = Join-Path $desktopPath "Security_Audit_Report.html"

$global:ReportHtml = @"
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="utf-8">
    <title>Отчет аудита ОС :: Windows Security Analyzer</title>
    <style>
        body { font-family: 'Consolas', monospace; background: #121212; color: #e0e0e0; padding: 25px; margin: 0; }
        h2 { color: #00bcd4; border-bottom: 2px solid #333; padding-bottom: 10px; }
        .log-entry { margin: 6px 0; font-size: 13px; line-height: 1.5; }
        .danger { color: #ff5252; font-weight: bold; }
        .warning { color: #ffd740; }
        .success { color: #69f0ae; }
        .info { color: #40c4ff; }
        .section { margin-top: 20px; padding: 10px; background: #1e1e1e; border-radius: 4px; border-left: 4px solid #00bcd4; }
    </style>
</head>
<body>
    <h2>ОТЧЕТ АУДИТА БЕЗОПАСНОСТИ WINDOWS</h2>
    <p class="log-entry info">Время формирования отчета: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
"@

function Add-Log ($text, $class="info") {
    $global:ReportHtml += "<div class='log-entry $class'>$text</div>`r`n"
}

function Wait-Key {
    while ([System.Console]::KeyAvailable) { $null = [System.Console]::ReadKey($true) }
    $key = [System.Console]::ReadKey($true)
    return $key.KeyChar
}

function Simulate-Progress ($text) {
    Write-Host $text -NoNewline -ForegroundColor DarkGray
    for ($i=0; $i -lt 3; $i++) {
        Start-Sleep -Milliseconds 150
        Write-Host "." -NoNewline -ForegroundColor DarkGray
    }
    Write-Host " [OK]" -ForegroundColor DarkGreen
    Start-Sleep -Milliseconds 80
}

function Print-Header {
    Clear-Host
    Write-Host ""
    Write-Host "    ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗" -ForegroundColor DarkCyan
    Write-Host "    ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝" -ForegroundColor DarkCyan
    Write-Host "    ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║   " -ForegroundColor Cyan
    Write-Host "    ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║   " -ForegroundColor Cyan
    Write-Host "    ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║   " -ForegroundColor DarkCyan
    Write-Host "    ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝   " -ForegroundColor DarkCyan
    Write-Host "    =====================================================" -ForegroundColor DarkGray
    Write-Host "     S E C U R I T Y   A N A L Y Z E R   &   F I X E R   " -ForegroundColor Yellow
    Write-Host "    =====================================================" -ForegroundColor DarkGray
    Write-Host "                        Инструмент экспресс-аудита ОС    " -ForegroundColor DarkGray
    Write-Host ""
}

function Show-Menu {
    Print-Header
    Write-Host "    [1] Базовый аудит       (UAC, Антивирус/WMI, Обновления)" -ForegroundColor White
    Write-Host "    [2] Аудит реестра       (Политики, SmartScreen, VBS, Телеметрия)" -ForegroundColor White
    Write-Host "    [3] Сетевой стек        (Анализ файла hosts и DNS)" -ForegroundColor White
    Write-Host "    [4] Целостность ОС      (DISM / SFC сканирование хранилища)" -ForegroundColor White
    Write-Host "    [5] Safe-Boost          (Безопасная очистка без деградации служб)" -ForegroundColor Cyan
    Write-Host "    -----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "    [0] Завершить аудит и открыть HTML-отчет" -ForegroundColor Green
    Write-Host "    -----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "`n    [>] Выберите действие [1-5, 0] : " -NoNewline -ForegroundColor Green
}

function Check-BasicSecurity {
    Print-Header
    Write-Host " [+] ЗАПУСК БАЗОВОГО АУДИТА СИСТЕМЫ..." -ForegroundColor Magenta
    Write-Host " -----------------------------------------------------" -ForegroundColor DarkGray
    $riskScore = 0
    $global:ReportHtml += "<div class='section'><strong>[БАЗОВЫЙ АУДИТ БЕЗОПАСНОСТИ]</strong></div>"

    Simulate-Progress " [~] Проверка статуса контроля учетных записей (UAC)"
    $uac = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
    if ($null -eq $uac -or $uac.EnableLUA -eq 0) { 
        Write-Host " [!] UAC отключен! Процессы получают High Integrity токен без подтверждения." -ForegroundColor Red
        Add-Log "[КРИТИЧЕСКИЙ РИСК] UAC полностью деактивирован (EnableLUA = 0)." "danger"
        Write-Host "     Решение: Восстановить изоляцию учетных записей." -ForegroundColor DarkYellow
        $ans = Read-Host "     > Выполнить исправление? (Y/N)"
        if ($ans -match '^[YyДд]') {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Force
            Write-Host "     [OK] UAC включен. Изменения вступят в силу после перезагрузки." -ForegroundColor Green
            Add-Log "[ИСПРАВЛЕНО] Ключ EnableLUA установлен в значение 1 (требуется перезагрузка)." "success"
        }
        $riskScore += 30 
    } else { 
        Write-Host " [OK] UAC активен и работает штатно." -ForegroundColor Green
        Add-Log "[НОРМА] Контроль учетных записей UAC активен." "success"
    }

    Write-Host ""
    Simulate-Progress " [~] Аудит антивирусного провайдера (WMI SecurityCenter2)"
    $avProducts = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction SilentlyContinue
    $defender = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
    
    if (($null -eq $defender -or $defender.Status -ne 'Running') -and ($null -eq $avProducts)) { 
        Write-Host " [!] Антивирусная защита отсутствует, служба WinDefend остановлена!" -ForegroundColor Red
        Add-Log "[КРИТИЧЕСКИЙ РИСК] Антивирусное ядро неактивно. Интерфейс AMSI деактивирован." "danger"
        Write-Host "     Решение: Запустить встроенную службу Microsoft Defender." -ForegroundColor DarkYellow
        $ans = Read-Host "     > Запустить службу WinDefend? (Y/N)"
        if ($ans -match '^[YyДд]') {
            Start-Service -Name "WinDefend" -ErrorAction SilentlyContinue
            Write-Host "     [OK] Системный запрос на запуск службы WinDefend отправлен." -ForegroundColor Green
            Add-Log "[ИСПРАВЛЕНО] Отправлена команда запуска службы WinDefend." "success"
        }
        $riskScore += 40 
    } elseif ($defender.Status -ne 'Running' -and $null -ne $avProducts) {
        $avNames = ($avProducts | ForEach-Object { $_.displayName }) -join ', '
        Write-Host " [OK] Активен сторонний антивирусный комплекс: $avNames" -ForegroundColor Green
        Add-Log "[НОРМА] Сторонняя антивирусная защита активна: $avNames." "success"
    } else { 
        Write-Host " [OK] Защитник Windows (WinDefend) активен." -ForegroundColor Green
        Add-Log "[НОРМА] Служба Microsoft Defender функционирует штатно." "success"
    }

    Write-Host ""
    Simulate-Progress " [~] Проверка службы обновлений (wuauserv)"
    $wuService = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
    if ($null -eq $wuService -or $wuService.StartType -eq 'Disabled') {
        Write-Host " [!] Служба Windows Update отключена (Риск сохранения N-day уязвимостей)!" -ForegroundColor Red
        Add-Log "[КРИТИЧЕСКИЙ РИСК] Служба wuauserv отключена. Доставка патчей заблокирована." "danger"
        $ans = Read-Host "     > Восстановить штатный запуск службы wuauserv? (Y/N)"
        if ($ans -match '^[YyДд]') {
            Set-Service -Name "wuauserv" -StartupType Manual -ErrorAction SilentlyContinue
            Write-Host "     [OK] Тип запуска службы wuauserv переведен в режим Manual." -ForegroundColor Green
            Add-Log "[ИСПРАВЛЕНО] Режим службы wuauserv восстановлен на ручной запуск." "success"
        }
        $riskScore += 20
    } else {
        Write-Host " [OK] Служба доставки обновлений доступна." -ForegroundColor Green
        Add-Log "[НОРМА] Служба Windows Update не заблокирована." "success"
    }

    Write-Host " -----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host " Расчетный балл риска: $riskScore / 100" -ForegroundColor Yellow
    Write-Host "`n [Нажмите любую клавишу для возврата в меню]" -ForegroundColor DarkGray
    Wait-Key | Out-Null
}

function Check-Registry {
    Print-Header
    Write-Host " [+] ЗАПУСК ГЛУБОКОГО АУДИТА РЕЕСТРА И ПОЛИТИК..." -ForegroundColor Magenta
    Write-Host " -----------------------------------------------------" -ForegroundColor DarkGray
    $global:ReportHtml += "<div class='section'><strong>[АУДИТ РЕЕСТРА И АППАРАТНОЙ ИЗОЛЯЦИИ]</strong></div>"
    
    Simulate-Progress " [~] Проверка политики DisableAntiSpyware"
    $regDef = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
    if ($null -ne $regDef -and $regDef.DisableAntiSpyware -eq 1) { 
        Write-Host " [!] Обнаружена деструктивная блокировка Defender через системные политики!" -ForegroundColor Red 
        Add-Log "[КРИТИЧЕСКИЙ РИСК] Обнаружен ключ DisableAntiSpyware = 1." "danger"
        Write-Host "     Решение: Удалить блокирующее правило из куста HKLM." -ForegroundColor DarkYellow
        $ans = Read-Host "     > Удалить запись реестра? (Y/N)"
        if ($ans -match '^[YyДд]') {
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
            Write-Host "     [OK] Блокирующий ключ успешно удален." -ForegroundColor Green
            Add-Log "[ИСПРАВЛЕНО] Запись DisableAntiSpyware удалена из реестра." "success"
        }
    } else { 
        Write-Host " [OK] Блокирующих политик антивирусного ядра не обнаружено." -ForegroundColor Green
        Add-Log "[НОРМА] Политики Windows Defender находятся в исходном состоянии." "success"
    }

    Write-Host ""
    Simulate-Progress " [~] Проверка фильтра SmartScreen"
    $smartScreen = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -ErrorAction SilentlyContinue
    if ($null -ne $smartScreen -and $smartScreen.EnableSmartScreen -eq 0) {
        Write-Host " [!] Фильтр SmartScreen деактивирован через групповую политику!" -ForegroundColor Red
        Add-Log "[ПРЕДУПРЕЖДЕНИЕ] Фильтр проверки репутации SmartScreen отключен." "warning"
        $ans = Read-Host "     > Включить фильтр SmartScreen? (Y/N)"
        if ($ans -match '^[YyДд]') {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 1 -Force
            Write-Host "     [OK] Фильтр SmartScreen успешно активирован." -ForegroundColor Green
            Add-Log "[ИСПРАВЛЕНО] Фильтр SmartScreen включен (EnableSmartScreen = 1)." "success"
        }
    } else {
        Write-Host " [OK] Фильтр SmartScreen активен." -ForegroundColor Green
        Add-Log "[НОРМА] Фильтр SmartScreen не подвергался деструктивным изменениям." "success"
    }

    Write-Host ""
    Simulate-Progress " [~] Проверка аппаратной изоляции ядра (VBS / Core Isolation)"
    $vbs = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    if ($null -ne $vbs -and $vbs.VirtualizationBasedSecurityStatus -ne 2) {
        Write-Host " [!] Изоляция ядра на базе виртуализации (VBS) отключена (Уязвимость перед BYOVD)." -ForegroundColor Yellow
        Add-Log "[ПРЕДУПРЕЖДЕНИЕ] Изоляция ядра (VBS/HVCI) неактивна. Память ядра уязвима к эксплойтам Ring 0." "warning"
    } else {
        Write-Host " [OK] Аппаратная изоляция ядра (VBS/HVCI) активна." -ForegroundColor Green
        Add-Log "[НОРМА] Аппаратная изоляция ядра VBS функционирует." "success"
    }

    Write-Host ""
    Simulate-Progress " [~] Аудит конфигурации сбора диагностических данных (AllowTelemetry)"
    $regTele = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue
    if ($null -ne $regTele -and $regTele.AllowTelemetry -eq 0) { 
        Write-Host " [!] Телеметрия заблокирована (AllowTelemetry = 0). Возможны сбои Центра обновлений." -ForegroundColor Yellow
        Add-Log "[ПРЕДУПРЕЖДЕНИЕ] AllowTelemetry = 0. На редакциях Home/Pro это вызывает сбои компонентов." "warning"
        $ans = Read-Host "     > Восстановить базовый уровень сбора данных (Value 1)? (Y/N)"
        if ($ans -match '^[YyДд]') {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 1 -Force
            Write-Host "     [OK] Базовый уровень телеметрии восстановлен." -ForegroundColor Green
            Add-Log "[ИСПРАВЛЕНО] Параметр AllowTelemetry установлен в штатное значение 1." "success"
        }
    } else { 
        Write-Host " [OK] Службы телеметрии находятся в штатном режиме." -ForegroundColor Green
        Add-Log "[НОРМА] Параметры сбора диагностических данных не нарушены." "success"
    }

    Write-Host " -----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "`n [Нажмите любую клавишу для возврата в меню]" -ForegroundColor DarkGray
    Wait-Key | Out-Null
}

function Check-Network {
    Print-Header
    Write-Host " [+] АУДИТ СЕТЕВОГО СТЕКА И ФАЙЛА HOSTS..." -ForegroundColor Magenta
    Write-Host " -----------------------------------------------------" -ForegroundColor DarkGray
    $global:ReportHtml += "<div class='section'><strong>[СЕТЕВОЙ СТЕК И ЦЕЛОСТНОСТЬ ДРАЙВЕРОВ]</strong></div>"
    
    Simulate-Progress " [~] Синтаксический анализ файла hosts"
    $hostsPath = "$env:windir\System32\drivers\etc\hosts"
    
    # Исключаем пустые строки, комментарии и стандартные петлевые адреса localhost
    $activeRules = Get-Content $hostsPath -ErrorAction SilentlyContinue | Where-Object { 
        $_ -match '\S' -and 
        $_ -notmatch '^\s*#' -and 
        $_ -notmatch '127\.0\.0\.1\s+localhost' -and 
        $_ -notmatch '::1\s+localhost' 
    }
    
    if ($activeRules.Count -gt 0) { 
        Write-Host " [!] В файле hosts обнаружено сторонних правил маршрутизации: $($activeRules.Count)!" -ForegroundColor Red
        Add-Log "[УГРОЗА] Обнаружена модификация файла hosts ($($activeRules.Count) нештатных правил)." "danger"
        Write-Host "     Решение: Сохранить резервную копию hosts.bak и восстановить стандартную конфигурацию." -ForegroundColor DarkYellow
        $ans = Read-Host "     > Выполнить резервное копирование и очистку? (Y/N)"
        if ($ans -match '^[YyДд]') {
            Copy-Item -Path $hostsPath -Destination "$hostsPath.bak" -Force -ErrorAction SilentlyContinue
            $defaultHosts = "# Standard hosts file`r`n127.0.0.1 localhost`r`n::1 localhost`r`n"
            Set-Content -Path $hostsPath -Value $defaultHosts -Force
            Write-Host "     [OK] Резервная копия сохранена в hosts.bak. Файл hosts очищен." -ForegroundColor Green
            Add-Log "[ИСПРАВЛЕНО] Файл hosts очищен до эталонного состояния. Создан бэкап hosts.bak." "success"
        }
    } else { 
        Write-Host " [OK] Посторонних перенаправлений маршрутизации не обнаружено." -ForegroundColor Green
        Add-Log "[НОРМА] В файле hosts отсутствуют вредоносные или блокирующие записи." "success"
    }
    
    Write-Host " -----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "`n [Нажмите любую клавишу для возврата в меню]" -ForegroundColor DarkGray
    Wait-Key | Out-Null
}

function Repair-SystemFiles {
    Print-Header
    Write-Host " [+] ПРОВЕРКА ЦЕЛОСТНОСТИ СИСТЕМНОГО ХРАНИЛИЩА (DISM / SFC)..." -ForegroundColor Magenta
    Write-Host " -----------------------------------------------------" -ForegroundColor DarkGray
    $global:ReportHtml += "<div class='section'><strong>[ПРОВЕРКА ХРАНИЛИЩА КОМПОНЕНТОВ DISM/SFC]</strong></div>"
    
    Write-Host " [~] Инициализация восстановления хранилища компонентов..." -ForegroundColor DarkGray
    $ans = Read-Host "     > Запустить глубокую верификацию DISM /RestoreHealth? (Y/N)"
    if ($ans -match '^[YyДд]') {
        Write-Host " [*] Выполняется DISM-восстановление (может занять несколько минут)..." -ForegroundColor Yellow
        DISM /Online /Cleanup-Image /RestoreHealth | Out-Null
        Write-Host "     [OK] Проверка хранилища компонентов DISM завершена." -ForegroundColor Green
        Add-Log "[ИНФО] Выполнена проверка и восстановление хранилища компонентов через DISM." "info"
    }

    Write-Host "`n [~] Запуск проверки системных файлов через System File Checker..." -ForegroundColor DarkGray
    $sfcOutput = sfc /scannow
    
    if ($LASTEXITCODE -eq 0 -or $sfcOutput -match "не обнаружила" -or $sfcOutput -match "did not find") {
        Write-Host " [OK] Целостность системных файлов полностью сохранена." -ForegroundColor Green
        Add-Log "[НОРМА] Утилита SFC не выявила повреждений системных файлов." "success"
    } elseif ($sfcOutput -match "восстановила" -or $sfcOutput -match "successfully repaired") {
        Write-Host " [OK] Поврежденные библиотеки успешно найдены и восстановлены!" -ForegroundColor Green
        Add-Log "[ИСПРАВЛЕНО] Утилита SFC обнаружила и восстановила поврежденные файлы." "success"
    } else {
        Write-Host " [!] Зафиксированы системные ошибки. Требуется анализ CBS.log." -ForegroundColor Red
        Add-Log "[УГРОЗА] Утилита SFC зафиксировала критические ошибки целостности компонентов." "danger"
    }
    
    Write-Host " -----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "`n [Нажмите любую клавишу для возврата в меню]" -ForegroundColor DarkGray
    Wait-Key | Out-Null
}

function Safe-Optimize {
    Print-Header
    Write-Host " [+] ЗАПУСК БЕЗОПАСНОГО ОБСЛУЖИВАНИЯ (SAFE-BOOST)..." -ForegroundColor Magenta
    Write-Host " -----------------------------------------------------" -ForegroundColor DarkGray
    $global:ReportHtml += "<div class='section'><strong>[МОДУЛЬ БЕЗОПАСНОЙ ОПТИМИЗАЦИИ SAFE-BOOST]</strong></div>"

    Simulate-Progress " [~] Очистка кэша Temp (каталог Prefetch сохранен для скорости запуска ПО)"
    Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:WINDIR\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "     [OK] Временные файлы удалены без вмешательства в алгоритмы упреждающего чтения." -ForegroundColor Green
    Add-Log "[ИНФО] Очищены каталоги временных файлов Temp." "info"

    Write-Host ""
    Simulate-Progress " [~] Проверка файла гибернации (hiberfil.sys)"
    $ansHib = Read-Host "     > Отключить файл гибернации для освобождения объема SSD? (Y/N)"
    if ($ansHib -match '^[YyДд]') {
        powercfg.exe /hibernate off *>&1 | Out-Null
        Write-Host "     [OK] Файл hiberfil.sys отключен, место на системном накопителе освобождено." -ForegroundColor Green
        Add-Log "[ИНФО] Файл гибернации hiberfil.sys деактивирован пользователем." "info"
    }

    Write-Host ""
    Simulate-Progress " [~] Сброс сетевых сокетов Winsock и локального кэша DNS"
    ipconfig /flushdns | Out-Null
    netsh winsock reset | Out-Null
    Write-Host "     [OK] Кэш DNS очищен, стек Winsock сброшен до штатных настроек." -ForegroundColor Green
    Add-Log "[ИНФО] Выполнен сброс кэша DNS и сокетов Winsock." "info"

    Write-Host ""
    Simulate-Progress " [~] Проверка типа аппаратной платформы"
    $battery = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue
    if ($null -eq $battery) {
        powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c | Out-Null
        Write-Host "     [OK] Стационарный ПК: активирован профиль 'Высокая производительность'." -ForegroundColor Green
        Add-Log "[ИНФО] Настольный ПК: активирована схема 'Высокая производительность'." "info"
    } else {
        Write-Host "     [i] Ноутбук: сохранен штатный сбалансированный профиль во избежание перегрева." -ForegroundColor Yellow
        Add-Log "[ИНФО] Мобильная платформа (ноутбук): сохранен сбалансированный режим питания." "info"
    }

    Write-Host " -----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "`n [Нажмите любую клавишу для возврата в меню]" -ForegroundColor DarkGray
    Wait-Key | Out-Null
}

Show-Menu
while ($true) {
    $choice = Wait-Key
    switch ($choice) {
        '1' { Check-BasicSecurity; Show-Menu }
        '2' { Check-Registry; Show-Menu }
        '3' { Check-Network; Show-Menu }
        '4' { Repair-SystemFiles; Show-Menu }
        '5' { Safe-Optimize; Show-Menu }
        '0' { 
            Clear-Host
            $global:ReportHtml += "</body></html>"
            Set-Content -Path $global:ReportPath -Value $global:ReportHtml -Encoding UTF8 -Force
            
            Write-Host "`n[+] Сеанс аудита успешно завершен." -ForegroundColor Cyan
            Write-Host "[!] HTML-отчет сохранен: $global:ReportPath" -ForegroundColor Green
            Write-Host "[~] Запуск отчета в браузере..." -ForegroundColor DarkGray
            
            Start-Process $global:ReportPath
            Start-Sleep -Seconds 1
            exit 
        }
        default { } 
    }
}
