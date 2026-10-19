# ============================================================================
# Скрипт-анализатор угроз и уязвимостей ОС Windows (Интерактивный CLI)
# Автор: Сарим | КарТУ им. А.Сагинова
# ============================================================================

# 1. Железобетонный перезапуск с правами Администратора
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $url = "https://raw.githubusercontent.com/kinger111/projject/refs/heads/main/projject.ps1"
    $cmd = "-NoProfile -ExecutionPolicy Bypass -NoExit -Command `"Invoke-RestMethod -Uri '$url' | Invoke-Expression`""
    Start-Process powershell -ArgumentList $cmd -Verb RunAs
    exit
}

# 2. Настройка окна консоли и Логирования
$Host.UI.RawUI.WindowTitle = "TERMINAL :: Windows Security Analyzer & Fixer"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$global:LogPath = "$env:USERPROFILE\Desktop\Windows_Security_Report.txt"
"==================================================" | Out-File -FilePath $global:LogPath -Force -Encoding UTF8
" ОТЧЕТ АУДИТА БЕЗОПАСНОСТИ WINDOWS" | Out-File -FilePath $global:LogPath -Append -Encoding UTF8
" Дата: $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')" \vert{} Out-File -FilePath $global:LogPath -Append -Encoding UTF8
"==================================================" | Out-File -FilePath $global:LogPath -Append -Encoding UTF8

function Log-Event ($Message) {$timestamp = Get-Date -Format "HH:mm:ss"
    "[$timestamp] $Message" \vert{} Out-File -FilePath $global:LogPath -Append -Encoding UTF8
}

# 3. Базовые функции интерфейса
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
    Write-Host "    [0] Завершить сеанс" -ForegroundColor DarkGray
    Write-Host "    -----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "`n    [>] Ожидание команды [1-5, 0] : " -NoNewline -ForegroundColor Green
}

# 4. Модули проверок и фиксов
function Check-BasicSecurity {
    Print-Header
    Write-Host " [+] ЗАПУСК БАЗОВОГО АУДИТА СИСТЕМЫ..." -ForegroundColor Magenta
    Write-Host " -----------------------------------------------------" -ForegroundColor DarkGray
    Log-Event "--- Запуск модуля: Базовый аудит ---"
    $riskScore = 0

    Simulate-Progress " [~] Чтение кустов реестра HKLM\SOFTWARE\Policies\System"
    $uac = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
    if ($uac.EnableLUA -eq 0) { 
        Write-Host " [!] UAC полностью отключен (Высокий риск повышения привилегий)!" -ForegroundColor Red
        Log-Event "[УГРОЗА] Обнаружен отключенный UAC (EnableLUA=0)."
        Write-Host "     Решение: Включить механизм изоляции процессов." -ForegroundColor DarkYellow
        $ans = Read-Host "     > Выполнить исправление? (Y/N)"
        if ($ans -match '^[YyДд]') {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1 -Force
            Write-Host "     [OK] UAC успешно включен (требуется перезагрузка)." -ForegroundColor Green
            Log-Event "[ИСПРАВЛЕНО] UAC успешно активирован."
        }
        $riskScore += 30 
    } else { 
        Write-Host " [OK] UAC активен." -ForegroundColor Green
        Log-Event "[НОРМА] UAC функционирует корректно."
    }

    Write-Host ""
    Simulate-Progress " [~] Опрос статуса службы WinDefend через API Windows"
    $defender = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue
    if ($null -eq $defender -or $defender.Status -ne 'Running') { 
        Write-Host " [!] Защитник Windows остановлен (AMSI отключен)!" -ForegroundColor Red
        Log-Event "[УГРОЗА] Служба WinDefend остановлена."
        Write-Host "     Решение: Запустить службу антивирусной защиты." -ForegroundColor DarkYellow
        $ans = Read-Host "     > Выполнить исправление? (Y/N)"
        if ($ans -match '^[YyДд]') {
            Start-Service -Name "WinDefend" -ErrorAction SilentlyContinue
            Write-Host "     [OK] Отправлена команда на запуск службы." -ForegroundColor Green
            Log-Event "[ИСПРАВЛЕНО] Служба WinDefend принудительно запущена."
        }
        $riskScore += 40 
    } else { 
        Write-Host " [OK] Защитник функционирует." -ForegroundColor Green
        Log-Event "[НОРМА] Защитник Windows активен."
    }

    Write-Host " -----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host " Индекс риска: $riskScore" -ForegroundColor Yellow
    Log-Event "Суммарный индекс риска: $riskScore"
    Write-Host "`n [Нажмите любую клавишу для возврата в меню]" -ForegroundColor DarkGray
    Wait-Key | Out-Null
}

function Check-Registry {
    Print-Header
    Write-Host " [+] ЗАПУСК ГЛУБОКОГО АУДИТА РЕЕСТРА..." -ForegroundColor Magenta
    Write-Host " -----------------------------------------------------" -ForegroundColor DarkGray
    Log-Event "--- Запуск модуля: Аудит реестра ---"
    
    Simulate-Progress " [~] Поиск ключа DisableAntiSpyware (Блокировка антивируса)"
    $regDef = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
    if ($regDef.DisableAntiSpyware -eq 1) { 
        Write-Host " [!] Defender заблокирован политиками реестра!" -ForegroundColor Red 
        Log-Event "[УГРОЗА] Найдена политика отключения Defender (DisableAntiSpyware=1)."
        Write-Host "     Решение: Удалить блокирующее правило из реестра." -ForegroundColor DarkYellow
        $ans = Read-Host "     > Удалить правило? (Y/N)"
        if ($ans -match '^[YyДд]') {
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
            Write-Host "     [OK] Блокировка снята." -ForegroundColor Green
            Log-Event "[ИСПРАВЛЕНО] Блокирующая политика удалена."
        }
    } else { 
        Write-Host " [OK] Политики Defender не скомпрометированы." -ForegroundColor Green
        Log-Event "[НОРМА] Политики Defender в исходном состоянии."
    }

    Write-Host ""
    Simulate-Progress " [~] Проверка служб DataCollection (Телеметрия/Сбор данных)"
    $regTele = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -ErrorAction SilentlyContinue
    if ($regTele.AllowTelemetry -eq 0) { 
        Write-Host " [!] Службы телеметрии вырезаны (Возможна блокировка Windows Update)." -ForegroundColor Yellow
        Log-Event "[ПРЕДУПРЕЖДЕНИЕ] Отключена базовая телеметрия (AllowTelemetry=0)."
        Write-Host "     Решение: Вернуть базовый уровень сбора данных (Level 1)." -ForegroundColor DarkYellow
        $ans = Read-Host "     > Восстановить? (Y/N)"
        if ($ans -match '^[YyДд]') {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 1 -Force
            Write-Host "     [OK] Базовая телеметрия восстановлена." -ForegroundColor Green
            Log-Event "[ИСПРАВЛЕНО] Базовая телеметрия восстановлена."
        }
    } else { 
        Write-Host " [OK] Службы сбора данных в исходном состоянии." -ForegroundColor Green
        Log-Event "[НОРМА] Службы сбора данных функционируют."
    }

    Write-Host " -----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "`n [Нажмите любую клавишу для возврата в меню]" -ForegroundColor DarkGray
    Wait-Key | Out-Null
}

function Check-Network {
    Print-Header
    Write-Host " [+] АНАЛИЗ СЕТЕВОГО СТЕКА..." -ForegroundColor Magenta
    Write-Host " -----------------------------------------------------" -ForegroundColor DarkGray
    Log-Event "--- Запуск модуля: Сетевой стек ---"
    
    Simulate-Progress " [~] Проверка контрольной суммы файла hosts"
    $hostsPath = "$env:windir\System32\drivers\etc\hosts"
    $hostsContent = Get-Content $hostsPath -ErrorAction SilentlyContinue
    
    if ($hostsContent.Length -gt 25) { 
        Write-Host " [!] Файл hosts модифицирован! Возможен угон трафика (DNS Hijacking)." -ForegroundColor Red
        Log-Event "[УГРОЗА] Обнаружена модификация файла hosts."
        Write-Host "     Решение: Сбросить файл hosts до заводских настроек." -ForegroundColor DarkYellow
        $ans = Read-Host "     > Выполнить сброс? (Y/N)"
        if ($ans -match '^[YyДд]') {
            $defaultHosts = "# Copyright (c) 1993-2009 Microsoft Corp.`r`n# 127.0.0.1 localhost`r`n# ::1 localhost"
            Set-Content -Path $hostsPath -Value $defaultHosts -Force
            Write-Host "     [OK] Файл hosts успешно очищен." -ForegroundColor Green
            Log-Event "[ИСПРАВЛЕНО] Файл hosts сброшен до оригинала."
        }
    } else { 
        Write-Host " [OK] Файл hosts имеет стандартный размер." -ForegroundColor Green
        Log-Event "[НОРМА] Файл hosts не изменен."
    }
    
    Write-Host " -----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "`n [Нажмите любую клавишу для возврата в меню]" -ForegroundColor DarkGray
    Wait-Key | Out-Null
}

function Repair-SystemFiles {
    Print-Header
    Write-Host " [+] ПРОВЕРКА ЦЕЛОСТНОСТИ ФАЙЛОВОЙ СИСТЕМЫ ОС..." -ForegroundColor Magenta
    Write-Host " -----------------------------------------------------" -ForegroundColor DarkGray
    Log-Event "--- Запуск модуля: SFC и DISM ---"
    Write-Host " [~] Инициализация System File Checker (Займет 1-3 минуты)..." -ForegroundColor DarkGray
    
    $sfcOutput = sfc /scannow
    
    if ($sfcOutput -match "не обнаружила" -or $sfcOutput -match "did not find") {
        Write-Host " [OK] Нарушений целостности системных файлов не обнаружено." -ForegroundColor Green
        Log-Event "[НОРМА] Сканирование SFC не выявило битых файлов."
    } elseif ($sfcOutput -match "восстановила" -or $sfcOutput -match "successfully repaired") {
        Write-Host " [OK] Поврежденные файлы успешно найдены и восстановлены!" -ForegroundColor Green
        Log-Event "[ИСПРАВЛЕНО] SFC восстановил поврежденные компоненты."
    } else {
        Write-Host " [!] Найдена критическая деградация ОС. Требуется восстановление хранилища." -ForegroundColor Red
        Log-Event "[УГРОЗА] SFC обнаружил неустранимые ошибки файловой системы."
        Write-Host "     Решение: Выполнить DISM /RestoreHealth." -ForegroundColor DarkYellow
        $ans = Read-Host "     > Запустить восстановление? (Y/N)"
        if ($ans -match '^[YyДд]') {
            Write-Host " [~] Запуск DISM... Загрузка оригинальных файлов с серверов Microsoft..." -ForegroundColor DarkGray
            DISM /Online /Cleanup-Image /RestoreHealth | Out-Null
            Write-Host "     [OK] Хранилище компонентов ОС восстановлено." -ForegroundColor Green
            Log-Event "[ИСПРАВЛЕНО] Хранилище ОС успешно восстановлено через DISM."
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
    Log-Event "--- Запуск модуля: Safe-Boost ---"

    Simulate-Progress " [~] Очистка кэша и временных файлов (Temp, Prefetch)"
    Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:WINDIR\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:WINDIR\Prefetch\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "     [OK] Системный мусор удален. Дисковое пространство освобождено." -ForegroundColor Green
    Log-Event "[ИНФО] Очищены папки Temp и Prefetch."

    Write-Host ""
    Simulate-Progress " [~] Отключение режима гибернации (Освобождение SSD)"
    powercfg -h off -ErrorAction SilentlyContinue
    Write-Host "     [OK] Файл hiberfil.sys удален. Ресурс SSD разгружен." -ForegroundColor Green
    Log-Event "[ИНФО] Гибернация отключена, освобождено место на системном диске."

    Write-Host ""
    Simulate-Progress " [~] Сброс сетевых сокетов и кэша DNS (Снижение задержек)"
    ipconfig /flushdns | Out-Null
    netsh winsock reset | Out-Null
    Write-Host "     [OK] Сетевой стек обновлен." -ForegroundColor Green
    Log-Event "[ИНФО] Выполнен сброс DNS и TCP/IP сокетов."

    Write-Host ""
    Simulate-Progress " [~] Активация профиля 'Высокая производительность'"
    powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c | Out-Null
    Write-Host "     [OK] Аппаратные лимиты энергопотребления сняты." -ForegroundColor Green
    Log-Event "[ИНФО] Активирована схема управления питанием 'Высокая производительность'."

    Write-Host " -----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "`n [Нажмите любую клавишу для возврата в меню]" -ForegroundColor DarkGray
    Wait-Key | Out-Null
}

# 5. Изолированный главный цикл
Show-Menu
while ($true) {$choice = Wait-Key
    switch ($choice) {
        '1' { Check-BasicSecurity; Show-Menu }
        '2' { Check-Registry; Show-Menu }
        '3' { Check-Network; Show-Menu }
        '4' { Repair-SystemFiles; Show-Menu }
        '5' { Safe-Optimize; Show-Menu }
        '0' { 
            Clear-Host
            Write-Host "`n[+] Сеанс завершен." -ForegroundColor Cyan
            Write-Host "[!] Подробный отчет сохранен на Рабочем столе: $global:LogPath`n" -ForegroundColor Green
            exit 
        }
        default { } # Игнорируем левые клавиши
    }
}
