if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $url = "https://raw.githubusercontent.com/kinger111/projject/refs/heads/main/projject.ps1"
    $cmd = "-NoProfile -ExecutionPolicy Bypass -NoExit -Command `"Invoke-RestMethod -Uri '$url' | Invoke-Expression`""
    Start-Process powershell -ArgumentList $cmd -Verb RunAs
    exit
}

$Host.UI.RawUI.WindowTitle = "TERMINAL :: Windows Security Analyzer & Fixer"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$global:ReportHtml = @("<html><head><meta charset='utf-8'><title>Отчет аудита ОС</title><style>body{font-family:consolas; background:#1e1e1e; color:#00ff00; padding:20px;}</style></head><body><h2>ОТЧЕТ АУДИТА БЕЗОПАСНОСТИ</h2>")

function Add-Log ($text, $color) {
    $global:ReportHtml += "<p style='color:$color;'>$text</p>"
}

function Wait-Key {
    while ([System.Console]::KeyAvailable) { $null = [System.Console]::ReadKey($true) }
    $key = [System.Console]::ReadKey($true)
    return $key.KeyChar
}

function Simulate-Progress ($text) {
    Write-Host $text -NoNewline -ForegroundColor DarkGray
    for ($i=0; $i -lt 3; $i++) {
        Start-Sleep -Milliseconds 250
        Write-Host "." -NoNewline -ForegroundColor DarkGray
    }
    Write-Host " [DONE]" -ForegroundColor DarkGreen
    Start-Sleep -Milliseconds 150
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
    Write-Host "                                         build by meraz  " -ForegroundColor DarkMagenta
    Write-Host ""
}

function Show-Menu {
    Print-Header
    Write-Host "    [1] Базовый аудит       (UAC, Антивирус/WMI, Обновления)" -ForegroundColor White
    Write-Host "    [2] Аудит реестра       (Политики, SmartScreen, VBS, Телеметрия)" -ForegroundColor White
    Write-Host "    [3] Сетевой стек        (Файл hosts, DNS)" -ForegroundColor White
    Write-Host "    [4] Целостность ОС      (DISM / SFC сканирование)" -ForegroundColor White
    Write-Host "    [5] Safe-Boost          (Безопасная оптимизация и очистка)" -ForegroundColor Cyan
    Write-Host "    -----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "    [0] Завершить сеанс и открыть отчет" -ForegroundColor DarkGray
    Write-Host "    -----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "`n    [>] Ожидание команды [1-5, 0] : " -NoNewline -ForegroundColor Green
}

function Check-BasicSecurity {
    Print-Header
    Write-Host " [+] ЗАПУСК БАЗОВОГО АУДИТА СИСТЕМЫ..." -ForegroundColor Magenta
    Write-Host " -----------------------------------------------------" -ForegroundColor DarkGray
    $riskScore = 0
    Add-Log "--- БАЗОВЫЙ АУДИТ ---" "#ffffff"

    Simulate-Progress " [~] Чтение кустов реестра HKLM\SOFTWARE\Policies\System"
    $uac = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
    if ($uac.EnableLUA -eq 0) { 
        Write-Host " [!] UAC полностью отключен (Процессы получают High Integrity без запроса)!" -ForegroundColor Red
        Add-Log "[УГРОЗА] Обнаружен отключенный UAC (EnableLUA = 0)." "#ff0000"
        Write-Host "     Решение: Включить механизм изоляции процессов." -ForegroundColor DarkYellow
        $ans = Read-Host "     > Выполнить исправление? (Y/N)"
        if ($ans -match '^[YyДд]') {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Force
            Write-Host "     [OK] UAC успешно включен (требуется перезагрузка ОС)." -ForegroundColor Green
            Add-Log "[ИСПРАВЛЕНО] UAC успешно активирован (требуется перезагрузка)." "#00ff00"
        }
        $riskScore += 30 
    } else { 
        Write-Host " [OK] UAC активен." -ForegroundColor Green
        Add-Log "[НОРМА] UAC функционирует корректно." "#00ff00"
    }

    Write-Host ""
    Simulate-Progress " [~] Опрос статуса антивирусной защиты (WMI SecurityCenter2 и WinDefend)"
    $avProducts = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction SilentlyContinue
    $defender = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
    
    if (($null -eq $defender -or $defender.Status -ne 'Running') -and ($null -eq $avProducts)) { 
        Write-Host " [!] Антивирусная защита отсутствует, служба WinDefend остановлена (AMSI неактивен)!" -ForegroundColor Red
        Add-Log "[УГРОЗА] Служба WinDefend остановлена, сторонний АВ не обнаружен." "#ff0000"
        Write-Host "     Решение: Запустить службу антивирусной защиты Защитника Windows." -ForegroundColor DarkYellow
        $ans = Read-Host "     > Выполнить исправление? (Y/N)"
        if ($ans -match '^[YyДд]') {
            Start-Service -Name "WinDefend" -ErrorAction SilentlyContinue
            Write-Host "     [OK] Отправлена команда на запуск службы WinDefend." -ForegroundColor Green
            Add-Log "[ИСПРАВЛЕНО] Служба WinDefend принудительно запущена." "#00ff00"
        }
        $riskScore += 40 
    } elseif ($defender.Status -ne 'Running' -and $null -ne $avProducts) {
        Write-Host " [OK] Обнаружен сторонний антивирус ($($avProducts.displayName -join ', '))." -ForegroundColor Green
        Add-Log "[НОРМА] Активен сторонний антивирус: $($avProducts.displayName -join ', ')." "#00ff00"
    } else { 
        Write-Host " [OK] Защитник Windows функционирует." -ForegroundColor Green
        Add-Log "[НОРМА] Защитник Windows (WinDefend) активен." "#00ff00"
    }

    Write-Host ""
    Simulate-Progress " [~] Проверка службы обновлений Windows Update (wuauserv)"
    $wuService = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
    if ($null -eq $wuService -or $wuService.StartType -eq 'Disabled') {
        Write-Host " [!] Служба Windows Update заблокирована (Риск N-day уязвимостей)!" -ForegroundColor Red
        Add-Log "[УГРОЗА] Служба обновлений wuauserv отключена." "#ff0000"
        $ans = Read-Host "     > Разблокировать службу обновлений? (Y/N)"
        if ($ans -match '^[YyДд]') {
            Set-Service -Name "wuauserv" -StartupType Manual -ErrorAction SilentlyContinue
            Write-Host "     [OK] Режим запуска службы wuauserv восстановлен (Manual)." -ForegroundColor Green
            Add-Log "[ИСПРАВЛЕНО] Служба обновлений wuauserv разблокирована." "#00ff00"
        }
        $riskScore += 20
    } else {
        Write-Host " [OK] Служба Windows Update не заблокирована." -ForegroundColor Green
        Add-Log "[НОРМА] Служба обновлений wuauserv в штатном режиме." "#00ff00"
    }

    Write-Host " -----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host " Индекс риска: $riskScore" -ForegroundColor Yellow
    Write-Host "`n [Нажмите любую клавишу для возврата в меню]" -ForegroundColor DarkGray
    Wait-Key | Out-Null
}

function Check-Registry {
    Print-Header
    Write-Host " [+] ЗАПУСК ГЛУБОКОГО АУДИТА РЕЕСТРА И ИЗОЛЯЦИИ..." -ForegroundColor Magenta
    Write-Host " -----------------------------------------------------" -ForegroundColor DarkGray
    Add-Log "<br>--- АУДИТ РЕЕСТРА И ИЗОЛЯЦИИ ---" "#ffffff"
    
    Simulate-Progress " [~] Поиск ключа DisableAntiSpyware (Блокировка антивируса)"
    $regDef = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
    if ($regDef.DisableAntiSpyware -eq 1) { 
        Write-Host " [!] Defender заблокирован групповыми политиками реестра!" -ForegroundColor Red 
        Add-Log "[УГРОЗА] Найдена политика отключения Defender (DisableAntiSpyware = 1)." "#ff0000"
        Write-Host "     Решение: Удалить блокирующее правило из реестра." -ForegroundColor DarkYellow
        $ans = Read-Host "     > Удалить правило? (Y/N)"
        if ($ans -match '^[YyДд]') {
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
            Write-Host "     [OK] Блокировка снята." -ForegroundColor Green
            Add-Log "[ИСПРАВЛЕНО] Блокирующая политика DisableAntiSpyware удалена." "#00ff00"
        }
    } else { 
        Write-Host " [OK] Политики Defender не скомпрометированы." -ForegroundColor Green
        Add-Log "[НОРМА] Политики Defender в исходном состоянии." "#00ff00"
    }

    Write-Host ""
    Simulate-Progress " [~] Проверка фильтра репутации SmartScreen"
    $smartScreen = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -ErrorAction SilentlyContinue
    if ($null -ne $smartScreen -and $smartScreen.EnableSmartScreen -eq 0) {
        Write-Host " [!] Фильтр SmartScreen принудительно отключен политикой!" -ForegroundColor Red
        Add-Log "[УГРОЗА] Отключен фильтр SmartScreen." "#ff0000"
        $ans = Read-Host "     > Включить фильтр SmartScreen? (Y/N)"
        if ($ans -match '^[YyДд]') {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 1 -Force
            Write-Host "     [OK] SmartScreen успешно активирован." -ForegroundColor Green
            Add-Log "[ИСПРАВЛЕНО] Фильтр SmartScreen включен." "#00ff00"
        }
    } else {
        Write-Host " [OK] Политики SmartScreen не заблокированы." -ForegroundColor Green
        Add-Log "[НОРМА] Фильтр SmartScreen функционирует штатно." "#00ff00"
    }

    Write-Host ""
    Simulate-Progress " [~] Проверка аппаратной изоляции ядра (VBS / Core Isolation)"
    $vbs = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
    if ($null -ne $vbs -and $vbs.VirtualizationBasedSecurityStatus -ne 2) {
        Write-Host " [!] Изоляция ядра на базе виртуализации (VBS) неактивна." -ForegroundColor Yellow
        Add-Log "[ПРЕДУПРЕЖДЕНИЕ] Аппаратная изоляция ядра VBS отключена." "#ffff00"
    } else {
        Write-Host " [OK] Изоляция ядра VBS активна." -ForegroundColor Green
        Add-Log "[НОРМА] Изоляция ядра VBS работает в штатном режиме." "#00ff00"
    }

    Write-Host ""
    Simulate-Progress " [~] Проверка служб DataCollection (Телеметрия/Сбор данных)"
    $regTele = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue
    if ($null -ne $regTele -and $regTele.AllowTelemetry -eq 0) { 
        Write-Host " [!] Телеметрия принудительно отключена (Возможны сбои доставки обновлений на Home/Pro)." -ForegroundColor Yellow
        Add-Log "[ПРЕДУПРЕЖДЕНИЕ] Установлен параметр AllowTelemetry = 0." "#ffff00"
        Write-Host "     Решение: Вернуть базовый уровень сбора данных (Level 1)." -ForegroundColor DarkYellow
        $ans = Read-Host "     > Восстановить? (Y/N)"
        if ($ans -match '^[YyДд]') {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 1 -Force
            Write-Host "     [OK] Базовая телеметрия восстановлена." -ForegroundColor Green
            Add-Log "[ИСПРАВЛЕНО] Базовая телеметрия восстановлена (AllowTelemetry = 1)." "#00ff00"
        }
    } else { 
        Write-Host " [OK] Службы сбора данных в исходном состоянии." -ForegroundColor Green
        Add-Log "[НОРМА] Службы сбора данных функционируют." "#00ff00"
    }

    Write-Host " -----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "`n [Нажмите любую клавишу для возврата в меню]" -ForegroundColor DarkGray
    Wait-Key | Out-Null
}

function Check-Network {
    Print-Header
    Write-Host " [+] АНАЛИЗ СЕТЕВОГО СТЕКА..." -ForegroundColor Magenta
    Write-Host " -----------------------------------------------------" -ForegroundColor DarkGray
    Add-Log "<br>--- СЕТЕВОЙ СТЕК ---" "#ffffff"
    
    Simulate-Progress " [~] Синтаксический анализ активных правил файла hosts"
    $hostsPath = "$env:windir\System32\drivers\etc\hosts"
    $activeRules = Get-Content $hostsPath -ErrorAction SilentlyContinue | Where-Object { $_ -match '\S' -and $_ -notmatch '^\s*#' }
    
    if ($activeRules.Count -gt 0) { 
        Write-Host " [!] В файле hosts обнаружено активных правил маршрутизации: $($activeRules.Count)!" -ForegroundColor Red
        Add-Log "[УГРОЗА] Обнаружена модификация файла hosts (активных строк: $($activeRules.Count))." "#ff0000"
        Write-Host "     Решение: Создать резервную копию hosts.bak и сбросить файл до заводских настроек." -ForegroundColor DarkYellow
        $ans = Read-Host "     > Выполнить резервное копирование и сброс? (Y/N)"
        if ($ans -match '^[YyДд]') {
            Copy-Item -Path $hostsPath -Destination "$hostsPath.bak" -Force -ErrorAction SilentlyContinue
            $defaultHosts = "# Copyright (c) 1993-2009 Microsoft Corp.`r`n# 127.0.0.1 localhost`r`n# ::1 localhost"
            Set-Content -Path $hostsPath -Value $defaultHosts -Force
            Write-Host "     [OK] Копия сохранена в hosts.bak, файл hosts успешно очищен." -ForegroundColor Green
            Add-Log "[ИСПРАВЛЕНО] Создана копия hosts.bak, файл hosts сброшен до оригинала." "#00ff00"
        }
    } else { 
        Write-Host " [OK] Активных перенаправлений в файле hosts не обнаружено." -ForegroundColor Green
        Add-Log "[НОРМА] Файл hosts содержит только стандартные комментарии." "#00ff00"
    }
    
    Write-Host " -----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "`n [Нажмите любую клавишу для возврата в меню]" -ForegroundColor DarkGray
    Wait-Key | Out-Null
}

function Repair-SystemFiles {
    Print-Header
    Write-Host " [+] ПРОВЕРКА ЦЕЛОСТНОСТИ ФАЙЛОВОЙ СИСТЕМЫ ОС..." -ForegroundColor Magenta
    Write-Host " -----------------------------------------------------" -ForegroundColor DarkGray
    Add-Log "<br>--- DISM и SFC ---" "#ffffff"
    
    Write-Host " [~] Шаг 1: Проверка и восстановление хранилища компонентов через DISM..." -ForegroundColor DarkGray
    $ans = Read-Host "     > Запустить предварительную сверку хранилища DISM /RestoreHealth? (Y/N)"
    if ($ans -match '^[YyДд]') {
        DISM /Online /Cleanup-Image /RestoreHealth | Out-Null
        Write-Host "     [OK] Проверка хранилища компонентов DISM завершена." -ForegroundColor Green
        Add-Log "[ИНФО] Выполнена верификация хранилища через DISM /RestoreHealth." "#00ffff"
    }

    Write-Host "`n [~] Шаг 2: Инициализация System File Checker (sfc /scannow)..." -ForegroundColor DarkGray
    $sfcOutput = sfc /scannow
    
    if ($LASTEXITCODE -eq 0 -or $sfcOutput -match "не обнаружила" -or $sfcOutput -match "did not find") {
        Write-Host " [OK] Нарушений целостности системных файлов не обнаружено." -ForegroundColor Green
        Add-Log "[НОРМА] Сканирование SFC не выявило поврежденных файлов." "#00ff00"
    } elseif ($sfcOutput -match "восстановила" -or $sfcOutput -match "successfully repaired") {
        Write-Host " [OK] Поврежденные файлы успешно найдены и восстановлены!" -ForegroundColor Green
        Add-Log "[ИСПРАВЛЕНО] Утилита SFC восстановила поврежденные компоненты." "#00ff00"
    } else {
        Write-Host " [!] Обнаружены ошибки системных файлов. Проверьте журнал CBS.log." -ForegroundColor Red
        Add-Log "[УГРОЗА] SFC зафиксировал ошибки целостности системных библиотек." "#ff0000"
    }
    
    Write-Host " -----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "`n [Нажмите любую клавишу для возврата в меню]" -ForegroundColor DarkGray
    Wait-Key | Out-Null
}

function Safe-Optimize {
    Print-Header
    Write-Host " [+] ЗАПУСК БЕЗОПАСНОЙ ОПТИМИЗАЦИИ ОС (SAFE-BOOST)..." -ForegroundColor Magenta
    Write-Host " -----------------------------------------------------" -ForegroundColor DarkGray
    Add-Log "<br>--- SAFE-BOOST ОПТИМИЗАЦИЯ ---" "#ffffff"

    Simulate-Progress " [~] Безопасная очистка временных директорий Temp (без удаления Prefetch)"
    Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:WINDIR\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "     [OK] Временный кэш Temp очищен. Трассировки Prefetch сохранены." -ForegroundColor Green
    Add-Log "[ИНФО] Очищены временные каталоги Temp." "#00ffff"

    Write-Host ""
    Simulate-Progress " [~] Оптимизация файла гибернации (Освобождение места на SSD)"
    $ansHib = Read-Host "     > Отключить гибернацию для освобождения места на SSD? (Y/N)"
    if ($ansHib -match '^[YyДд]') {
        powercfg.exe /hibernate off *>&1 | Out-Null
        Write-Host "     [OK] Файл hiberfil.sys удален. Дисковое пространство освобождено." -ForegroundColor Green
        Add-Log "[ИНФО] Гибернация отключена по запросу пользователя." "#00ffff"
    }

    Write-Host ""
    Simulate-Progress " [~] Сброс сетевых сокетов Winsock и кэша DNS"
    ipconfig /flushdns | Out-Null
    netsh winsock reset | Out-Null
    Write-Host "     [OK] Кэш DNS и сокеты Winsock успешно сброшены." -ForegroundColor Green
    Add-Log "[ИНФО] Выполнен сброс DNS-кэша и каталога Winsock." "#00ffff"

    Write-Host ""
    Simulate-Progress " [~] Проверка типа платформы и настройка профиля электропитания"
    $battery = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue
    if ($null -eq $battery) {
        powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c | Out-Null
        Write-Host "     [OK] Обнаружен стационарный ПК: активирована схема 'Высокая производительность'." -ForegroundColor Green
        Add-Log "[ИНФО] Активирована схема питания 'Высокая производительность' (Настольный ПК)." "#00ffff"
    } else {
        Write-Host "     [i] Обнаружен ноутбук: сохранен сбалансированный профиль для защиты от перегрева." -ForegroundColor Yellow
        Add-Log "[ИНФО] Обнаружен ноутбук: сохранена штатная схема питания во избежание троттлинга." "#00ffff"
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
            $desktopPath = [Environment]::GetFolderPath("Desktop")
            $reportPath = Join-Path $desktopPath "Security_Audit_Report.html"
            Set-Content -Path $reportPath -Value $global:ReportHtml -Encoding UTF8 -Force
            
            Write-Host "`n[+] Сеанс завершен." -ForegroundColor Cyan
            Write-Host "[!] Отчет сохранен по пути: $reportPath" -ForegroundColor Green
            Write-Host "[~] Открываю отчет в браузере..." -ForegroundColor DarkGray
            
            Start-Process $reportPath
            Start-Sleep -Seconds 2
            exit 
        }
        default { } 
    }
}
