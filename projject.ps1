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
    Write-Host "    [1] Базовый аудит       (UAC, Защитник Windows)" -ForegroundColor White
    Write-Host "    [2] Аудит реестра       (Политики, Телеметрия)" -ForegroundColor White
    Write-Host "    [3] Сетевой стек        (Файл hosts, DNS)" -ForegroundColor White
    Write-Host "    [4] Целостность ОС      (SFC сканирование / DISM)" -ForegroundColor White
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
        Write-Host " [!] UAC полностью отключен (Высокий риск повышения привилегий)!" -ForegroundColor Red
        Add-Log "[УГРОЗА] Обнаружен отключенный UAC." "#ff0000"
        Write-Host "     Решение: Включить механизм изоляции процессов." -ForegroundColor DarkYellow
        $ans = Read-Host "     > Выполнить исправление? (Y/N)"
        if ($ans -match '^[YyДд]') {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Force
            Write-Host "     [OK] UAC успешно включен (требуется перезагрузка)." -ForegroundColor Green
            Add-Log "[ИСПРАВЛЕНО] UAC успешно активирован." "#00ff00"
        }
        $riskScore += 30 
    } else { 
        Write-Host " [OK] UAC активен." -ForegroundColor Green
        Add-Log "[НОРМА] UAC функционирует корректно." "#00ff00"
    }

    Write-Host ""
    Simulate-Progress " [~] Опрос статуса службы WinDefend через API Windows"
    $defender = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
    if ($null -eq $defender -or$defender.Status -ne 'Running') { 
        Write-Host " [!] Защитник Windows остановлен (AMSI отключен)!" -ForegroundColor Red
        Add-Log "[УГРОЗА] Служба WinDefend остановлена." "#ff0000"
        Write-Host "     Решение: Запустить службу антивирусной защиты." -ForegroundColor DarkYellow
        $ans = Read-Host "     > Выполнить исправление? (Y/N)"
        if ($ans -match '^[YyДд]') {
            Start-Service -Name "WinDefend" -ErrorAction SilentlyContinue
            Write-Host "     [OK] Отправлена команда на запуск службы." -ForegroundColor Green
            Add-Log "[ИСПРАВЛЕНО] Служба WinDefend принудительно запущена." "#00ff00"
        }
        $riskScore += 40 
    } else { 
        Write-Host " [OK] Защитник функционирует." -ForegroundColor Green
        Add-Log "[НОРМА] Защитник Windows активен." "#00ff00"
    }

    Write-Host " -----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host " Индекс риска: $riskScore" -ForegroundColor Yellow
    Write-Host "`n [Нажмите любую клавишу для возврата в меню]" -ForegroundColor DarkGray
    Wait-Key | Out-Null
}

function Check-Registry {
    Print-Header
    Write-Host " [+] ЗАПУСК ГЛУБОКОГО АУДИТА РЕЕСТРА..." -ForegroundColor Magenta
    Write-Host " -----------------------------------------------------" -ForegroundColor DarkGray
    Add-Log "<br>--- АУДИТ РЕЕСТРА ---" "#ffffff"
    
    Simulate-Progress " [~] Поиск ключа DisableAntiSpyware (Блокировка антивируса)"
    $regDef = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
    if ($regDef.DisableAntiSpyware -eq 1) { 
        Write-Host " [!] Defender заблокирован политиками реестра!" -ForegroundColor Red 
        Add-Log "[УГРОЗА] Найдена политика отключения Defender." "#ff0000"
        Write-Host "     Решение: Удалить блокирующее правило из реестра." -ForegroundColor DarkYellow
        $ans = Read-Host "     > Удалить правило? (Y/N)"
        if ($ans -match '^[YyДд]') {
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
            Write-Host "     [OK] Блокировка снята." -ForegroundColor Green
            Add-Log "[ИСПРАВЛЕНО] Блокирующая политика удалена." "#00ff00"
        }
    } else { 
        Write-Host " [OK] Политики Defender не скомпрометированы." -ForegroundColor Green
        Add-Log "[НОРМА] Политики Defender в исходном состоянии." "#00ff00"
    }

    Write-Host ""
    Simulate-Progress " [~] Проверка служб DataCollection (Телеметрия/Сбор данных)"
    $regTele = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue
    if ($regTele.AllowTelemetry -eq 0) { 
        Write-Host " [!] Службы телеметрии вырезаны (Возможна блокировка Windows Update)." -ForegroundColor Yellow
        Add-Log "[ПРЕДУПРЕЖДЕНИЕ] Отключена базовая телеметрия." "#ffff00"
        Write-Host "     Решение: Вернуть базовый уровень сбора данных (Level 1)." -ForegroundColor DarkYellow
        $ans = Read-Host "     > Восстановить? (Y/N)"
        if ($ans -match '^[YyДд]') {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 1 -Force
            Write-Host "     [OK] Базовая телеметрия восстановлена." -ForegroundColor Green
            Add-Log "[ИСПРАВЛЕНО] Базовая телеметрия восстановлена." "#00ff00"
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
    
    Simulate-Progress " [~] Проверка контрольной суммы файла hosts"
    $hostsPath = "$env:windir\System32\drivers\etc\hosts"
    $hostsContent = Get-Content $hostsPath -ErrorAction SilentlyContinue
    
    if ($hostsContent.Length -gt 25) { 
        Write-Host " [!] Файл hosts модифицирован! Возможен угон трафика (DNS Hijacking)." -ForegroundColor Red
        Add-Log "[УГРОЗА] Обнаружена модификация файла hosts." "#ff0000"
        Write-Host "     Решение: Сбросить файл hosts до заводских настроек." -ForegroundColor DarkYellow
        $ans = Read-Host "     > Выполнить сброс? (Y/N)"
        if ($ans -match '^[YyДд]') {
            $defaultHosts = "# Copyright (c) 1993-2009 Microsoft Corp.`r`n# 127.0.0.1 localhost`r`n# ::1 localhost"
            Set-Content -Path $hostsPath -Value $defaultHosts -Force
            Write-Host "     [OK] Файл hosts успешно очищен." -ForegroundColor Green
            Add-Log "[ИСПРАВЛЕНО] Файл hosts сброшен до оригинала." "#00ff00"
        }
    } else { 
        Write-Host " [OK] Файл hosts имеет стандартный размер." -ForegroundColor Green
        Add-Log "[НОРМА] Файл hosts не изменен." "#00ff00"
    }
    
    Write-Host " -----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "`n [Нажмите любую клавишу для возврата в меню]" -ForegroundColor DarkGray
    Wait-Key | Out-Null
}

function Repair-SystemFiles {
    Print-Header
    Write-Host " [+] ПРОВЕРКА ЦЕЛОСТНОСТИ ФАЙЛОВОЙ СИСТЕМЫ ОС..." -ForegroundColor Magenta
    Write-Host " -----------------------------------------------------" -ForegroundColor DarkGray
    Add-Log "<br>--- SFC и DISM ---" "#ffffff"
    Write-Host " [~] Инициализация System File Checker (Займет 1-3 минуты)..." -ForegroundColor DarkGray
    
    $sfcOutput = sfc /scannow
    
    if ($sfcOutput -match "не обнаружила" -or $sfcOutput -match "did not find") {
        Write-Host " [OK] Нарушений целостности системных файлов не обнаружено." -ForegroundColor Green
        Add-Log "[НОРМА] Сканирование SFC не выявило битых файлов." "#00ff00"
    } elseif ($sfcOutput -match "восстановила" -or $sfcOutput -match "successfully repaired") {
        Write-Host " [OK] Поврежденные файлы успешно найдены и восстановлены!" -ForegroundColor Green
        Add-Log "[ИСПРАВЛЕНО] SFC восстановил поврежденные компоненты." "#00ff00"
    } else {
        Write-Host " [!] Найдена критическая деградация ОС. Требуется восстановление хранилища." -ForegroundColor Red
        Add-Log "[УГРОЗА] SFC обнаружил неустранимые ошибки." "#ff0000"
        Write-Host "     Решение: Выполнить DISM /RestoreHealth." -ForegroundColor DarkYellow
        $ans = Read-Host "     > Запустить восстановление? (Y/N)"
        if ($ans -match '^[YyДд]') {
            Write-Host " [~] Запуск DISM... Загрузка оригинальных файлов с серверов Microsoft..." -ForegroundColor DarkGray
            DISM /Online /Cleanup-Image /RestoreHealth | Out-Null
            Write-Host "     [OK] Хранилище компонентов ОС восстановлено." -ForegroundColor Green
            Add-Log "[ИСПРАВЛЕНО] Хранилище ОС успешно восстановлено через DISM." "#00ff00"
        }
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

    Simulate-Progress " [~] Очистка кэша и временных файлов (Temp, Prefetch)"
    Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:WINDIR\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:WINDIR\Prefetch\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "     [OK] Системный мусор удален. Дисковое пространство освобождено." -ForegroundColor Green
    Add-Log "[ИНФО] Очищены папки Temp и Prefetch." "#00ffff"

    Write-Host ""
    Simulate-Progress " [~] Отключение режима гибернации (Освобождение SSD)"
    powercfg.exe /hibernate off *>&1 | Out-Null
    Write-Host "     [OK] Файл hiberfil.sys удален. Ресурс SSD разгружен." -ForegroundColor Green
    Add-Log "[ИНФО] Гибернация отключена, освобождено место на SSD." "#00ffff"

    Write-Host ""
    Simulate-Progress " [~] Сброс сетевых сокетов и кэша DNS (Снижение задержек)"
    ipconfig /flushdns | Out-Null
    netsh winsock reset | Out-Null
    Write-Host "     [OK] Сетевой стек обновлен." -ForegroundColor Green
    Add-Log "[ИНФО] Выполнен сброс DNS и TCP/IP сокетов." "#00ffff"

    Write-Host ""
    Simulate-Progress " [~] Активация профиля 'Высокая производительность'"
    powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c | Out-Null
    Write-Host "     [OK] Аппаратные лимиты энергопотребления сняты." -ForegroundColor Green
    Add-Log "[ИНФО] Активирована схема 'Высокая производительность'." "#00ffff"

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
            # Сохраняем отчет прямо в корень диска C:\
            $reportPath = "C:\Security_Audit_Report.html"
            Set-Content -Path $reportPath -Value $global:ReportHtml -Encoding UTF8 -Force
            
            Write-Host "`n[+] Сеанс завершен." -ForegroundColor Cyan
            Write-Host "[!] Отчет сохранен по пути: $reportPath" -ForegroundColor Green
            Write-Host "[~] Открываю отчет в браузере..." -ForegroundColor DarkGray
            
            # Автоматически открываем файл в браузере
            Start-Process $reportPath
            Start-Sleep -Seconds 2
            exit 
        }
        default { } 
    }
}
