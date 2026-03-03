# Windows DFIR: Артефакты для реагирования на инциденты

> **Применимость:** Windows 7 / Server 2008 R2 — Windows 11 / Server 2022  
> **Назначение:** Справочник для сбора и анализа артефактов с живой системы или образа диска  
> **Версия:** 1.1 | Обновлено: 2026-02

---

## Условные обозначения

| Символ | Значение |
|--------|----------|
| 🔴 | Критически важно — собирать в первую очередь |
| 🟡 | Важно — стандартный IR |
| 🟢 | Дополнительно — углублённое расследование |
| ⚠️ | Требует прав администратора |
| ⏱️ | Волатильный — исчезает при перезагрузке |
| 🔐 | Может быть зашифрован (BitLocker) |
| 🔧 | Требует дополнительной настройки аудита |

---

## Содержание

| # | Категория | Ключевые артефакты |
|---|-----------|-------------------|
| [1](#1-persistence) | **Persistence** | Run-ключи, Scheduled Tasks, Services, WMI, COM |
| [2](#2-process) | **Process** | Список процессов, дескрипторы, DLL, хэши |
| [3](#3-network) | **Network** | Соединения, ARP, DNS, маршруты, конфиги |
| [4](#4-file-system) | **File System** | MFT, USN Journal, Prefetch, LNK, VSS |
| [5](#5-user-activity) | **User Activity** | ShellBags, JumpLists, UserAssist, TypedURLs |
| [6](#6-execution-artifacts) | **Execution Artifacts** | AmCache, ShimCache, BAM/DAM |
| [7](#7-srum) | **SRUM** | Сетевое использование, ресурсы, приложения |
| [8](#8-system-logs) | **System Logs** | Security.evtx, System.evtx, PowerShell, RDP, Kerberos |
| [9](#9-authentication) | **Authentication** | SAM, LSA Secrets, DPAPI, сессии, пользователи |
| [10](#10-applications) | **Applications** | Installed apps, браузеры, WMI репозиторий |
| [11](#11-security-state) | **Security State** | Windows Defender, Firewall, AMSI, ETW, Sysmon |
| [12](#12-memory--volatile) | **Memory & Volatile** | RAM-дамп, lsass, handles, env vars |
| [13](#13-external-devices) | **External Devices** | USB, Bluetooth, монтирование |
| [14](#14-registry) | **Registry** | Ключевые кусты, анализ, нюансы |
| [П1](#приложение-1-порядок-сбора) | **Приложение 1** | Order of Volatility |
| [П2](#приложение-3-инструменты-комбайны) | **Приложение 2** | Инструменты сбора и анализа |
| [П3](#приложение-4-ссылки) | **Приложение 3** | Ссылки |
| [П4](#приложение-5-покрытие-артефактов-по-инструментам) | **Приложение 4** | Покрытие артефактов по инструментам |

---

## 1. Persistence

*Чаще всего злоумышленники пытаются обеспечить себе устойчивое закрепление на системе. Наиболее распространенные методы представены ниже. Более полный граф техник persistence для Windows доступен в репозитории [flostyen/windows-persistence](https://github.com/flostyen/windows-persistence).*

---

### 1.1 Run / RunOnce ключи реестра 🔴

**Что это:** Классический и наиболее распространённый механизм автозапуска через реестр. При входе пользователя или старте системы Windows выполняет все программы, перечисленные в этих ключах. Встречается в подавляющем большинстве инцидентов с малварью — от массовых стилеров до APT-групп.

**Пути реестра:**
```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run
```

**На какие вопросы отвечает:**
- Какие программы запускаются автоматически при входе пользователя?
- Есть ли нестандартные или подозрительные записи с путями в `%TEMP%`, `%APPDATA%` или с нестандартными именами?
- Когда была добавлена запись (Last Write Time ключа реестра)?
- Совпадает ли путь к бинарю с легитимным расположением приложения?

**Парсинг:**
```powershell
# Все записи Run для системы и текущего пользователя
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Через AutoRuns (Sysinternals) — рекомендуется для живой системы (ловит не все, но очень многое)
autorunsc.exe -a * -s -c -accepteula -nobanner -h * | Set-Content -Encoding UTF8 -Path %destinationDirectory%\Autoruns.csv

# KAPE: Target = !SANS_Triage или KapeTriage
# Module = SysInternals_Autoruns.mkape — запускает Autorunsc и сохраняет CSV
```

**Инструменты:** KAPE (`SysInternals_Autoruns.mkape`, `RECmd_AllRegExecutablesFoundOrRun.mkape`) · Velociraptor (`Windows.Sys.StartupItems`) · Autoruns (Sysinternals)

---

### 1.2 Scheduled Tasks (Запланированные задачи) 🔴

**Что это:** Один из наиболее активно используемых механизмов persistence по данным публичных отчётов. Задачи могут создаваться как через GUI (`taskschd.msc`), так и через `schtasks.exe`, WMI, или напрямую через XML в `C:\Windows\System32\Tasks`. Начиная с Windows 8 реальное хранилище задач переехало в реестр — XML-файлы на диске синхронизируются из него. Гораздо надежнее проверять реестр, чем xml файлы.

**Пути:**
```
C:\Windows\System32\Tasks\               ← XML-файлы задач (Task Scheduler 2.0, Vista+)
C:\Windows\SysWOW64\Tasks\
C:\Windows\Tasks\                        ← бинарные .job файлы (Task Scheduler 1.0, XP-era)
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree
```

**На какие вопросы отвечает:**
- Какой исполняемый файл или команда запускается задачей?
- Какой триггер у задачи — при входе, по расписанию, при событии?
- Когда задача была создана и когда запускалась последний раз?
- Есть ли задачи, запускающие скрипты из `%TEMP%`, PowerShell c `-EncodedCommand` или `bypass`, `ProgramData` и т.п.?

**Парсинг:**
```powershell
# Список всех задач
schtasks /query /fo LIST /v > scheduled_tasks.txt

# KAPE: Target = ScheduledTasks
# Module = EvtxECmd.mkape (задачи в Microsoft-Windows-TaskScheduler%4Operational.evtx)
# EID 4698 — задача создана; EID 4702 — изменена; EID 106 — зарегистрирована
```

**Журнал:** `Microsoft-Windows-TaskScheduler/Operational` — включён по умолчанию на Windows 7+.

**Инструменты:** KAPE (`ScheduledTasks.tkape` + `EvtxECmd.mkape`, `RECmd_DFIRBatch.mkape`) · Velociraptor (`Windows.System.TaskScheduler`) · Autoruns

---

### 1.3 Windows Services (Службы) 🔴

**Что это:** Вредоносные службы — также очень популярный вектор persistence. Службы запускаются с правами SYSTEM по умолчанию. Для создания службы нужны права администратора, но после создания она существует до удаления. Конфигурация хранится в реестре.

**Пути:**
```
HKLM\SYSTEM\CurrentControlSet\Services\       ← все службы (исполняемые бинари, тип, статус)
C:\Windows\System32\drivers\                   ← драйверы (тип = Kernel)
```

**На какие вопросы отвечает:**
- Есть ли нестандартные службы или драйверы, не связанные с установленным ПО?
- Каков путь к исполняемому файлу службы и подписан ли он?
- Когда ключ реестра службы был создан или изменён?
- Есть ли службы, запускающиеся из `%TEMP%`, `%APPDATA%` или нестандартных путей?

**Парсинг:**
```powershell
# Все службы с путями
sc query type= all state= all
Get-WmiObject Win32_Service | Select-Object Name, StartMode, State, PathName |
  Export-Csv services.csv

# Неподписанные или подозрительные бинари служб
Get-WmiObject Win32_Service | ForEach-Object {
  $path = ($_.PathName -replace '"','') -split ' ' | Select-Object -First 1
  if ($path -and (Test-Path $path)) {
    $sig = Get-AuthenticodeSignature $path
    [PSCustomObject]@{Name=$_.Name; Path=$path; Signature=$sig.Status}
  }
} | Where-Object {$_.Signature -ne 'Valid'}

# KAPE: Target = WindowsServices (копирует реестровые кусты)
# Module = RECmd_Kroll.mkape — парсит ключи Services через RECmd
```

**Инструменты:** KAPE (`RECmd_DFIRBatch.mkape`) · Autoruns · Velociraptor (`Windows.System.Services`)

---

### 1.4 WMI Event Subscriptions 🔴

**Что это:** Один из наиболее скрытных механизмов persistence. WMI-подписки позволяют выполнять произвольный код при системных событиях (запуск процесса, изменение файла, периодический таймер). Не отображается в стандартных средствах просмотра автозапуска, хранится в бинарном репозитории WMI.

**Хранилище:**
```
C:\Windows\System32\wbem\Repository\       ← бинарный репозиторий WMI (OBJECTS.DATA, INDEX.BTR)
```

**Три компонента подписки:**
1. **EventFilter** — условие (например, запуск определённого процесса)
2. **EventConsumer** — действие (CommandLineEventConsumer = запуск команды)
3. **FilterToConsumerBinding** — привязка фильтра к консьюмеру

**На какие вопросы отвечает:**
- Есть ли активные WMI-подписки, которые могут выполнять команды?
- Какой командный потребитель (`CommandLineEventConsumer` или `ActiveScriptEventConsumer`) зарегистрирован?
- Когда были созданы подписки?
- Связаны ли подписки с подозрительными исполняемыми файлами или скриптами?

**Парсинг:**
```powershell
# Перечисление всех подписок (живая система)
Get-WMIObject -Namespace root\subscription -Class __EventFilter
Get-WMIObject -Namespace root\subscription -Class __EventConsumer
Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding

# Компактный вывод
Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding |
  Select-Object Filter, Consumer, @{n="Created";e={$_.__DERIVATION}}

# Анализ репозитория с образа диска
python3 PyWMIPersistenceFinder.py -i Repository/OBJECTS.DATA

# KAPE: PowerShell_WMIRepositoryAuditing (Модуль, который парсит wmi репозиторий и выводит все в txt формат)
# Анализ: PyWMIPersistenceFinder (https://github.com/davidpany/WMI_Forensics)
```

**Журнал:** `Microsoft-Windows-WMI-Activity/Operational` — EID 5861 (создание подписки). По умолчанию включён на Windows 10+.

**Инструменты:** KAPE (`PowerShell_WMIRepositoryAuditing.mkape`) · Velociraptor (`Windows.Persistence.PermanentWMIEvents`) · Autoruns

---

### 1.5 DLL Hijacking — Следы 🟡

**Что это:** Техника, при которой вредоносная DLL размещается в директории, которая проверяется перед системной при загрузке (злоупотребление [порядком поиска](https://www.akshayjain.blog/post/understanding-the-windows-dll-search-order-a-deep-dive-into-internals-and-security-implications) dll библиотек в Windows). Прямых артефактов «флаг hijacking» нет — нужно искать косвенные признаки: нестандартные DLL рядом с легитимными исполняемыми файлами или DLL в директориях приложений, подписанные не тем вендором. амое надежное - корреляция по меткам времени.

**На какие вопросы отвечает:**
- Есть ли DLL в нестандартных путях рядом с легитимными бинарями?
- Существуют ли DLL без подписи или с отозванным сертификатом рядом с подписанными EXE?
- Есть ли DLL с именами системных библиотек в директориях приложений?
- Есть ли dll с несовпадающими метками времени, рядом с бинарем?

**Парсинг:**
```powershell
# Поиск неподписанных DLL в директориях приложений (не в System32)
Get-ChildItem "C:\Program Files","C:\Program Files (x86)" -Recurse -Filter "*.dll" -EA SilentlyContinue |
  ForEach-Object {
    $sig = Get-AuthenticodeSignature $_.FullName
    if ($sig.Status -ne 'Valid') { 
      [PSCustomObject]@{Path=$_.FullName; Status=$sig.Status}
    }
  }
```

**Инструменты:** Autoruns (вкладка DLLs) · Process Monitor (Sysinternals) · KAPE + `MFTECmd`

---

### 1.6 COM Object Hijacking 🟡

**Что это:** COM (Component Object Model) — стандарт Microsoft для взаимодействия программных компонентов на уровне двоичного интерфейса, независимо от языка, в котором они написаны ([подробнее](https://habr.com/ru/companies/rvision/articles/734274/)). Каждый COM-объект регистрируется в реестре под HKLM (системный) или HKCU (пользовательский). Если злоумышленник регистрирует COM-объект в HKCU с тем же CLSID, что и системный объект в HKLM, Windows использует пользовательскую запись первой — и загружает вредоносную DLL без прав администратора. Распространённая техника в целевых атаках.

**Пути реестра:**
```
HKCU\Software\Classes\CLSID\             ← пользовательские COM-объекты (без прав admin!)
HKLM\SOFTWARE\Classes\CLSID\             ← системные COM-объекты
```

**На какие вопросы отвечает:**
- Когда был создан/изменён ключ HKCU\CLSID?
- Есть ли COM-объекты в HKCU, переопределяющие системные CLSID?
- На какие DLL или EXE ссылаются нестандартные CLSID?

**Парсинг:**
```powershell
# Перечисление пользовательских COM-объектов
reg query HKCU\Software\Classes\CLSID /s /f InprocServer32 2>$null

# Сравнение с системными
$hkcu = Get-ChildItem "HKCU:\Software\Classes\CLSID" -EA SilentlyContinue
$hkcu | ForEach-Object {
  $clsid = Split-Path $_.PSPath -Leaf
  $hklm_path = "HKLM:\SOFTWARE\Classes\CLSID\$clsid"
  if (Test-Path $hklm_path) { Write-Output "HIJACK CANDIDATE: $clsid → $($_.PSPath)" }
}

# KAPE: Target = RegistryHives (копирует NTUSER.DAT)
# Module = RECmd_Kroll.mkape — парсит куст пользователя
```

**Инструменты:** KAPE (`RECmd + *ASEPs.reb`) · Autoruns (вкладка COM)

---

## 2. Process

*Живые данные о процессах — самый короткоживущий источник информации, собирать в первую очередь.*

### 2.1 Список живых процессов ⏱️ 🔴

**Что это:** Снапшот всех запущенных процессов: PID, PPID, командная строка, путь к исполняемому файлу, пользователь, время запуска. Первое действие на живой системе, поскольку эти данные исчезают при завершении процесса или перезагрузке. Рекомендуется всегда резирвировать команды получения live информации. То есть получать одну информацию через два независисых источника.

**На какие вопросы отвечает:**
- Есть ли аномальные процессы или процессы из `%TEMP%`, `%APPDATA%`?
- Каковы parent-child отношения (нестандартные родители: `winword.exe` → `cmd.exe` = подозрительно)?
- Есть ли процессы с именами системных утилит, но запущенные не из `System32`?
- Запущены ли интерпретаторы (`powershell.exe`, `wscript.exe`, `cscript.exe`) с подозрительными аргументами?

**Парсинг:**
```powershell
# Полный список с деталями
Get-WmiObject Win32_Process | Select-Object ProcessId, ParentProcessId,
  Name, CommandLine, ExecutablePath,
  @{n="StartTime"; e={$_.ConvertToDateTime($_.CreationDate)}} |
  Sort-Object StartTime | Export-Csv processes.csv

# Подозрительные расположения
Get-WmiObject Win32_Process | Where-Object {
  $_.ExecutablePath -match "Temp|AppData|Public|Downloads" -or
  $_.ExecutablePath -notmatch "^C:\\Windows|^C:\\Program"
} | Select-Object ProcessId, Name, CommandLine, ExecutablePath

# Дерево процессов
Get-WmiObject Win32_Process | ForEach-Object {
  "$($_.ParentProcessId) → $($_.ProcessId) [$($_.Name)] $($_.CommandLine)"
} | Sort-Object
```

**Инструменты:** Velociraptor (`Windows.System.Pslist`) · KAPE (live response модули)

---

### 2.2 Загруженные DLL и дескрипторы ⏱️ 🟡

**Что это:** Список всех открытых файловых дескрипторов, мьютексов, именованных каналов и загруженных библиотек для каждого процесса. Позволяет обнаружить инъекцию DLL (Process Injection), hollow process и fileless-малварь, а также факт обращения к сетевым соединениям или другим файлам.

**На какие вопросы отвечает:**
- Есть ли процессы с открытыми файлами из подозрительных директорий?
- Держит ли процесс дескрипторы на уже удалённые файлы (fileless persistence)?
- Есть ли нестандартные именованные каналы (Named Pipes), характерные для C2-фреймворков?
- Загружены ли нестандартные DLL в легитимные системные процессы (`explorer.exe`, `svchost.exe`)?


**Парсинг:**
```powershell
# Загруженные модули каждого процесса
Get-Process | ForEach-Object {
  $proc = $_
  try {
    $proc.Modules | Select-Object @{n="PID";e={$proc.Id}},
      @{n="Process";e={$proc.Name}}, FileName
  } catch {}
} | Where-Object {$_.FileName -notmatch "System32|SysWOW64|Program Files"} |
  Export-Csv suspicious_dlls.csv

# Дескрипторы через Handle.exe (Sysinternals)
handle.exe -accepteula -a > handles.txt

# Named Pipes — поиск нестандартных
[System.IO.Directory]::GetFiles("\\.\pipe\") | Where-Object {
  $_ -notmatch "^\\\\\.\\pipe\\(svcctl|samr|lsass|wkssvc|netlogon|srvsvc)"
}
```

**Инструменты:** Velociraptor (`Windows.System.DLLs`) · Process Hacker / System Informer · Handle.exe (Sysinternals)

---

### 2.3 Хэши исполняемых файлов запущенных процессов 🔴

**Что это:** SHA256-хэши всех исполняемых файлов запущенных процессов. Позволяет быстро сверить хеши на системе с базами вредносных.


**На какие вопросы отвечает:**
- Есть ли известные вредоносные хэши среди запущенных процессов?
- Совпадают ли хэши системных бинарей с эталонными (Microsoft)?
- Есть ли исполняемые файлы без цифровой подписи среди запущенных процессов?
- Какая 

**Парсинг:**
```powershell
# Хэши всех исполняемых файлов запущенных процессов
Get-Process | Where-Object {$_.Path} | ForEach-Object {
  $hash = Get-FileHash $_.Path -Algorithm SHA256 -EA SilentlyContinue
  [PSCustomObject]@{
    PID=$_.Id; Name=$_.Name; Path=$_.Path
    SHA256=$hash.Hash
    Signed=(Get-AuthenticodeSignature $_.Path -EA SilentlyContinue).Status
  }
} | Export-Csv process_hashes.csv

# Поиск неподписанных исполняемых в подозрительных локациях
find C:\Users -name "*.exe" -newer C:\Windows\System32\calc.exe ^
  | while read f; do echo $f; done
```

**Инструменты:** KAPE (`PowerShell_Processes.mkape`, `PowerShell_ProcessList_WMI.mkape`, `PowerShell_ProcessList_CimInstance.mkape`)

---

## 3. Network

*Сетевые артефакты — собирать сразу после живых процессов.*

### 3.1 Активные соединения ⏱️ 🔴

**Что это:** Таблица всех текущих TCP/UDP-соединений с привязкой к процессам. Ключевой артефакт для обнаружения C2-коммуникации, reverse shell, эксфильтрации.

**На какие вопросы отвечает:**
- Какие процессы имеют активные соединения с внешними IP-адресами?
- Есть ли соединения на нестандартные порты или к известным C2-инфраструктурам?
- Есть ли новые listening-порты, которых не было раньше (потенциальный backdoor)?
- Какой процесс инициировал исходящее соединение к подозрительному IP?

**Парсинг:**
```powershell
# Все соединения с именами процессов
netstat -anob > netstat_full.txt

# Через PowerShell с деталями
Get-NetTCPConnection | ForEach-Object {
  $proc = Get-Process -Id $_.OwningProcess -EA SilentlyContinue
  [PSCustomObject]@{
    State=$_.State; LocalAddress=$_.LocalAddress; LocalPort=$_.LocalPort
    RemoteAddress=$_.RemoteAddress; RemotePort=$_.RemotePort
    PID=$_.OwningProcess; Process=$proc.Name
  }
} | Where-Object {$_.State -eq "Established"} | Export-Csv connections.csv

# Только ESTABLISHED
netstat -ano | findstr ESTABLISHED
```

**Инструменты:** Velociraptor (`Windows.Network.Netstat`) · KAPE (live response)

---

### 3.2 DNS-кэш ⏱️ 🔴

**Что это:** Кэш DNS-клиента Windows — история недавно разрешённых доменных имён. Исчезает при перезагрузке. Позволяет увидеть обращения к C2-доменам, DGA-доменам и фишинговым ресурсам даже без PCAP.

**На какие вопросы отвечает:**
- Есть ли DNS-запросы к известным C2-доменам или DGA-паттернам (случайные длинные домены)?
- К каким доменам обращалась система за последнее время?
- Есть ли необычные поддомены легитимных сервисов (DNS tunneling)?

**Парсинг:**
```powershell
# Дамп DNS-кэша
ipconfig /displaydns > dns_cache.txt
Get-DnsClientCache | Select-Object Entry, Data, TimeToLive | Export-Csv dns_cache.csv

# Поиск DGA-паттернов (длинные случайные домены)
Get-DnsClientCache | Where-Object {
  $_.Entry -match "^[a-z0-9]{10,}\." -and $_.Entry -notmatch "(google|microsoft|windows|cloudflare|etc)"
}
```

**Инструменты:** KAPE (live response) · Velociraptor (`Windows.System.DNSCache`)

---

### 3.3 ARP-кэш и таблица маршрутизации ⏱️ 🟡

**Что это:** ARP-кэш содержит таблицу IP→MAC для локальной сети, что позволяет установить соседей по сети в момент инцидента. Таблица маршрутизации может содержать вредоносные статические маршруты для перехвата трафика.

**На какие вопросы отвечает:**
- Есть ли аномальные ARP-записи, указывающие на ARP-спуфинг?
- Добавлены ли нестандартные статические маршруты для перенаправления трафика?

```powershell
arp -a > arp_cache.txt
route print > routing_table.txt
Get-NetRoute | Export-Csv routes.csv
```

**Инструменты:** KAPE (`Windows_ARPCache.mkape`) · Velociraptor (`Windows.Network.ArpCache`)

---

### 3.4 Конфигурация сети и файл hosts 🟡

**Что это:** Файл `hosts` имеет приоритет над DNS. Малварь модифицирует его для блокировки обновлений AV/EDR или перенаправления трафика. Изменение DNS-серверов = перехват DNS.

**Пути:**
```
C:\Windows\System32\drivers\etc\hosts
C:\Windows\System32\drivers\etc\lmhosts
HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters    ← DNS-серверы
```

**На какие вопросы отвечает:**
- Добавлены ли нестандартные записи в hosts (блокировка AV-сайтов, перенаправление)?
- Изменены ли DNS-серверы на нестандартные?

```powershell
type C:\Windows\System32\drivers\etc\hosts
Get-DnsClientServerAddress | Select-Object InterfaceAlias, ServerAddresses
ipconfig /all
```

**Инструменты:** KAPE (`PowerShell_NetworkIPConfiguration.mkape` + `HostsFile.tkape`)

---

### 3.5 История Wi-Fi соединений 🟡

**Путь:**
```
C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\   ← XML-профили Wi-Fi сетей
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures
```

**На какие вопросы отвечает:**
- К каким Wi-Fi сетям подключалось устройство (история местонахождения)?
- Когда впервые и последний раз подключалось к каждой сети?
- Подключалось ли устройство к корпоративной сети в нерабочее время?

```powershell
netsh wlan show profiles
netsh wlan show profile name="<SSID>" key=clear    # пароль в открытом виде!
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"
```

**Инструменты:** KAPE (`RegistryHives.tkape`)

---

## 4. File System

*Файловые артефакты — хронология всего, что происходило с файлами.*

### 4.1 $MFT (Master File Table) 🔴

**Что это:** Сердце файловой системы NTFS. Каждый файл и директория имеют запись в MFT с четырьмя временными метками в двух местах (вообще их может быть и [больше](https://t.me/s3Ch1n7/363)): `$STANDARD_INFORMATION` (видимые через Explorer, доступны для модификации пользователем) и `$FILE_NAME` (обновляются ядром NTFS, сложнее подделать). Различия между этими двумя наборами меток — классический признак **timestomping** (подделки временных меток).

> ⚠️ **Важная оговорка по timestomping:** ситуация, когда `$STANDARD_INFORMATION` старее `$FILE_NAME` или метки расходятся, может возникать и **легитимно** — например, при перемещении файла между томами, деплойменте через пакетные установщики, восстановлении из резервной копии или при работе некоторых инсталляторов. Детектировать timestomping следует **только в корреляции с другими аномалиями**: нестандартным расположением файла, аномалиями в AmCache/Prefetch, подозрительными записями в журналах событий. Само по себе расхождение меток не является однозначным IoC.

**На какие вопросы отвечает:**
- Какие файлы были созданы в период инцидента?
- Когда был создан, изменён, открыт и скопирован файл?
- Есть ли признаки timestomping (расхождение `$SI` и `$FN` меток)?
- Есть ли записи в MFT для удалённых файлов (MFT-запись сохраняется до перезаписи)?

**Парсинг:**
```powershell
# Сбор $MFT (требует raw NTFS-доступа, инструменты сами извлекают)
# KAPE: Target = $MFT
# Module = MFTECmd.mkape — парсит MFT в CSV/JSON

# MFTECmd (Eric Zimmerman) — ручной запуск
MFTECmd.exe -f "C:\$MFT" --csv C:\output --csvf mft.csv

# Анализ в Timeline Explorer:
# 1. Открыть Timeline Explorer
# 2. File → Open → выбрать mft.csv
# 3. Фильтр по дате инцидента
# 4. Сортировка по Created или Modified
# 5. Признаки timestomping: в колонке $SI vs $FN смотреть расхождения > нескольких секунд
```

**Инструменты:** KAPE (`$MFT.tkape` → `MFTECmd.mkape`) · Velociraptor (`Windows.NTFS.MFT`) · Timeline Explorer

---

### 4.2 $UsnJrnl (USN Change Journal) 🔴

**Что это:** Журнал изменений файловой системы NTFS. Фиксирует все операции с файлами: создание, переименование, удаление, изменение атрибутов. Хранится как ADS (Alternate Data Stream) `$J` в системном файле `$Extend\$UsnJrnl`. **Критически важен:** даже если файл удалён, запись в USN Journal о его создании и удалении остаётся, пока журнал не ротируется. Ротация происходит по достижении максимального размера (по умолчанию ~32 MB). Важно собирать этот журал в начале сбора информации, чтобы зафиксировать записи в нем.

**Путь:** `C:\$Extend\$UsnJrnl:$J`

**На какие вопросы отвечает:**
- Когда вредоносный файл появился в системе и когда был удалён?
- Как файл был переименован перед удалением (для сокрытия следов)?
- Какие файлы создавались и удалялись в заданном временном окне?
- Есть ли массовое удаление файлов (антикриминалистика)?

**Парсинг:**
```powershell
# KAPE: Target = $UsnJrnl
# Module = MFTECmd.mkape запускается для $J тоже:
# MFTECmd.exe -f "C:\$Extend\$UsnJrnl:$J" --csv output --csvf usnjrnl.csv

# Фильтр по дате и операции
# В Timeline Explorer: фильтр по колонке UpdateReasons → Delete
```

**Инструменты:** KAPE (`$UsnJrnl.tkape` → `MFTECmd.mkape`) · Velociraptor · Timeline Explorer

---

### 4.3 $LogFile (Ярлыки) 🟡

**Что это**: Журнал транзакций файловой системы NTFS. `$LogFile` — это системный файл (атрибут $LOG_FILE в MFT), который реализует механизм восстановления NTFS после сбоев. Принцип работы — write-ahead logging: перед тем как применить любое изменение к файловой системе (создание, переименование, удаление файла, обновление MFT-записи), NTFS сначала записывает транзакцию в $LogFile, и только потом применяет её к диску. Это позволяет откатить незавершённые транзакции при следующем монтировании тома.
С точки зрения форензики $LogFile даёт ретроспективу файловых операций — но в отличие от USN Journal ($UsnJrnl:$J), который хранит только факт изменения, $LogFile хранит полные данные транзакций, включая предыдущее и новое состояние MFT-записей. Размер фиксирован (обычно 64–512 MB), данные перезаписываются по кольцу — глубина истории зависит от активности файловой системы и обычно составляет от нескольких часов до нескольких дней на активной системе.

**Путm:**
```
C:\$LogFile
```

**На какие вопросы отвечает:**
- Какие файловые операции выполнялись незадолго до анализа (создание, удаление, переименование)?
- Был ли файл переименован или перемещён (актуально для малвари, которая маскируется под системные имена)?
- Когда и в какой последовательности создавались компоненты атаки (staging artifacts)?
- Как соотносятся транзакции с другими временными метками (кросс-корреляция с USN Journal и MFT)?
- Есть ли следы операций, которые были «зачищены» через прямую запись на диск (bypass filesystem API) — в таких случаях транзакции в $LogFile не будет, что само по себе аномалия?

**Парсинг:**
```powershell
# Сбор файла через KAPE (Обычное копирование требует Volume Shadow Copy или оффлайн-образ, 
# т.к. файл заблокирован ОС)
# KAPE Target: !BasicCollection или $LogFile.tkape, SANS_Triage
# Для корректного парсинга нужна также mft запись

python3 ntfs_parser --log MFT LogFile output.txt

```

**Инструменты:** [dfir_ntfs](https://github.com/msuhanov/dfir_ntfs) · [LogFileParser](https://github.com/jschicht/LogFileParser)

---

### 4.4 $I30 (Directory Index) 🟡

**Что это**: $I30 — это атрибут индекса директории в NTFS. Каждая папка в файловой системе содержит атрибут $INDEX_ROOT и, при большом количестве записей, $INDEX_ALLOCATION — вместе они образуют B-дерево (B-tree), которое хранит список файлов и поддиректорий с их метаданными. Совокупно эти атрибуты называют $I30 (по имени потока индекса).
Главная ценность для форензики — артефакт резидуальных записей (index slack). Когда файл удаляется из директории, его запись в B-дереве не затирается немедленно: дерево переструктурируется, а старая запись остаётся в «slack-пространстве» индексного буфера до тех пор, пока не будет перезаписана новыми данными. Это позволяет восстановить факт существования удалённых файлов вместе с их временными метками — даже если сам файл и его MFT-запись уже перезаписаны.

**Пути:**

`$I30` — это не отдельный файл, а атрибут каждой директории на томе NTFS. Для извлечения необходим образ диска.


**На какие вопросы отвечает:**
- Какие файлы существовали в директории, но были удалены?
- Когда удалённый файл был создан, изменён, последний раз открыт (временны́е метки из slack-пространства)?
- Использовались ли staging-директории (временные папки для сборки инструментов атаки)?
- Существовал ли конкретный файл в директории в определённый момент времени (подтверждение/опровержение версии)?
- Были ли аномальные файлы в системных директориях (например, исполняемые в C:\Windows\ с нестандартными именами)?

**Парсинг:**
```powershell
#Можно забирать только с образа
python3 ntfs_parser --indx image.raw bytes_offset_of_ntfs_partition out.csv

python3 INDXRipper.py image.raw out.csv
```

**Инструменты:** [dfir_ntfs](https://github.com/msuhanov/dfir_ntfs) · [INDXRipper](https://github.com/harelsegev/INDXRipper)

---

### 4.5 LNK-файлы (Ярлыки) 🟡

**Что это:** Файлы ярлыков, автоматически создаваемые Windows при открытии файлов. Содержат метаданные оригинального файла: путь, временные метки, размер, MAC-адрес и серийный номер тома источника. Позволяют доказать факт открытия файла, даже если он уже удалён.

**Пути:**
```
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\
C:\Users\<user>\AppData\Roaming\Microsoft\Office\Recent\
```

**На какие вопросы отвечает:**
- Какие файлы открывал пользователь (даже с удалённых носителей)?
- С каких томов (серийный номер, сетевой путь) открывались файлы?
- Когда файлы открывались в последний раз?
- Использовались ли портативные носители (серийный номер тома USB)?

**Парсинг:**
```powershell
# KAPE: Target = LNKFilesAndJumpLists
# Module = LECmd.mkape (LNK) + JLECmd.mkape (JumpLists)
# LECmd.exe -d "C:\Users\user\AppData\Roaming\Microsoft\Windows\Recent" --csv output

# В Timeline Explorer:
# Открыть lnk.csv → смотреть SourceCreated, SourceModified, TargetPath
```

**Инструменты:** KAPE (`LNKFilesAndJumpLists.tkape` → `LECmd.mkape`) · Velociraptor (`Windows.Forensics.Lnk`)

---

### 4.6 Volume Shadow Copies (VSS) 🟡 🔐

**Что это:** Теневые копии тома — снапшоты состояния файловой системы в определённый момент времени. Создаются автоматически при Windows Update, System Restore, бэкапах. Для IR: позволяют получить состояние системы **до** компрометации и восстановить легитимные или вредоносные файлы, удалённые злоумышленником. **Удаление теневых копий** — типичное действие ransomware и APT для уничтожения доказательств.

**Путь:** `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy<N>\`

**На какие вопросы отвечает:**
- Какое состояние системы было до компрометации (точка восстановления)?
- Какие файлы злоумышленник удалил, но они сохранились в теневых копиях?
- Были ли теневые копии удалены (признак ransomware: `vssadmin delete shadows`)?
- Когда создавались и удалялись теневые копии?

**Парсинг:**
```powershell
# Список всех теневых копий
vssadmin list shadows /for=C:

# Монтирование теневой копии для анализа
$vss = (Get-WmiObject Win32_ShadowCopy)[0]
$link = "C:\VSS_Mount"
$vss.GetObjectPath() | Out-Null
cmd /c mklink /d $link "$($vss.DeviceObject)\"

# KAPE: параметр --vss включает сбор артефактов из всех VSS
# kape.exe --tsource C: --tdest output --target !SANS_Triage --vss

# Детектирование удаления теневых копий через журналы:
# Security.evtx EID 4688: командная строка содержит "vssadmin delete" или "wmic shadowcopy delete"
# System.evtx EID 7036 (остановка VSS) + корреляция по времени
```

**Инструменты:** KAPE (`--vss` флаг) · Velociraptor (`Windows.Search.VSS`)

---

### 4.7 Temporary директории 🔴

**Что это:** Классическое место первоначального дропа вредоносного ПО. Малварь часто записывает payload в `%TEMP%`, выполняет и удаляет файл. Артефакты в MFT и USN Journal сохраняются, но сам файл уже отсутствует.

**Пути:**
```
C:\Windows\Temp\
C:\Users\<user>\AppData\Local\Temp\
C:\Users\<user>\AppData\Roaming\
C:\ProgramData\
```

**На какие вопросы отвечает:**
- Есть ли исполняемые файлы в временных директориях сейчас?
- Есть ли следы в MFT/USN Journal об исполняемых файлах, уже удалённых из %TEMP%?
- Каковы хэши файлов, которые сейчас находятся в этих директориях?

```powershell
# Исполняемые в TEMP прямо сейчас
Get-ChildItem $env:TEMP,$env:WINDIR\Temp -Include *.exe,*.dll,*.bat,*.ps1,*.vbs -Recurse -EA SilentlyContinue |
  ForEach-Object { [PSCustomObject]@{Path=$_.FullName; Hash=(Get-FileHash $_.FullName).Hash} }
```

---

## 5. User Activity

*Цифровой след пользователя в интерфейсе Windows.*

### 5.1 ShellBags 🔴

**Что это:** Записи реестра, фиксирующие директории, которые пользователь **открывал через Explorer** — включая директории на USB-носителях, сетевых ресурсах и уже несуществующих путях. Крайне устойчивый артефакт: запись в ShellBags сохраняется даже после удаления директории или отключения носителя.

**Пути реестра:**
```
HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU
HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags
HKCU\SOFTWARE\Microsoft\Windows\Shell\BagMRU        ← в NTUSER.DAT
HKCU\SOFTWARE\Microsoft\Windows\Shell\Bags
```

**Файлы реестра:**
```
C:\Users\<user>\NTUSER.DAT
C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat    ← основной для ShellBags
```

**На какие вопросы отвечает:**
- Какие директории пользователь просматривал через Explorer?
- Подключались ли съёмные носители и какие папки на них открывались?
- Были ли открыты сетевые ресурсы или пути UNC?
- Когда конкретная директория была открыта в последний раз?

**Парсинг:**
```powershell
# KAPE: Target = RegistryHives (собирает NTUSER.DAT и UsrClass.dat)
# Module = SBECmd.mkape
# SBECmd.exe -d "C:\Users\user" --csv output --csvf shellbags.csv

# В Timeline Explorer:
# 1. Открыть shellbags.csv
# 2. Смотреть LastInteracted column
# 3. Фильтр по AbsolutePath — искать USB-пути (буквы дисков), сетевые ресурсы
```

**Инструменты:** KAPE (`RegistryHives.tkape` → `SBECmd.mkape`) · Velociraptor

---

### 5.2 JumpLists 🟡

**Что это:** Списки недавно открытых файлов для каждого приложения (правая кнопка на иконке в таскбаре). Хранятся как OLE-файлы, содержат LNK-записи с метаданными файлов. Существуют два типа: AutomaticDestinations (создаются автоматически) и CustomDestinations (создаются приложением).

**Пути:**
```
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\*.customDestinations-ms
```

**На какие вопросы отвечает:**
- Какие файлы открывало конкретное приложение?
- Когда файлы открывались (независимый источник, дополняет LNK)?
- Открывались ли файлы с внешних носителей или сетевых ресурсов?

```powershell
# KAPE: Target = LNKFilesAndJumpLists
# Module = JLECmd.mkape
# JLECmd.exe -d "C:\Users\user\AppData\Roaming\Microsoft\Windows\Recent" --csv output
```

**Инструменты:** KAPE → `JLECmd.mkape` · Timeline Explorer

---

### 5.3 UserAssist 🟡

**Что это:** Реестровый ключ, хранящий ROT13-закодированные имена приложений с GUI, запускавшихся пользователем, количество запусков и последнее время запуска. Ключевое отличие от Prefetch: UserAssist отслеживает только **GUI-приложения**, запущенные **через Explorer** (двойной клик, меню Пуск), но не через командную строку.

**Путь реестра:**
```
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count
```

**На какие вопросы отвечает:**
- Какие GUI-приложения запускал пользователь через Explorer?
- Сколько раз запускалось каждое приложение?
- Когда последний раз запускалось приложение?

```powershell
# KAPE: Target = RegistryHives
# Module = RECmd_Kroll.mkape (парсит UserAssist через плагин)
# Или отдельно: decode ROT13 имён ключей

# Декодирование ROT13 в PowerShell
$key = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
Get-ChildItem $key -Recurse | ForEach-Object {
  Get-ItemProperty $_.PSPath | ForEach-Object {
    $_.PSObject.Properties | Where-Object {$_.Name -match "UEME"} | ForEach-Object {
      $decoded = -join ($_.Name.ToCharArray() | ForEach-Object {
        if ($_ -match "[A-Za-z]") { [char](([int][char]$_ - [int][char]$(if ($_ -cmatch "[A-Z]"){"A"}else{"a"}) + 13) % 26 + [int][char]$(if ($_ -cmatch "[A-Z]"){"A"}else{"a"})) } else { $_ }
      })
      Write-Output "$decoded → $($_.Value)"
    }
  }
}
```

**Инструменты:** KAPE → `RECmd_Kroll.mkape` · Registry Explorer (Eric Zimmerman)

---

### 5.4 TypedURLs и история браузеров 🟡

**TypedURLs — URL, введённые вручную в адресную строку Internet Explorer/Edge legacy:**

```
HKCU\SOFTWARE\Microsoft\Internet Explorer\TypedURLs
```

**Браузерные артефакты (Chromium-based):**
```
C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\History      ← SQLite
C:\Users\<user>\AppData\Local\Microsoft\Edge\User Data\Default\History
C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\*.default\places.sqlite
```

**На какие вопросы отвечает:**
- Какие URL посещал пользователь?
- Есть ли загрузки вредоносных файлов (таблица `downloads` в History)?
- Когда именно посещались конкретные сайты?

```powershell
# KAPE: Target = WebBrowsers
# Module = SQLECmd.mkape — парсит SQLite-базы браузеров через EZ Maps
# ChromeHistoryParser.mkape, FirefoxHistoryParser.mkape
```

**Инструменты:** KAPE (`WebBrowsers.tkape` → `SQLECmd.mkape`) · Velociraptor (`Windows.Applications.Chrome.History`)

---

## 6. Execution Artifacts

*Артефакты, доказывающие факт присутствия и запуска файлов на системе.*


### 6.1 Prefetch 🔴

**Что это:** Windows Prefetch — механизм предзагрузки, ускоряющий запуск приложений. Файлы `.pf` содержат: имя исполняемого файла, хэш пути запуска, до 8 последних временных меток запуска (Windows 8+), количество запусков, список загруженных файлов и DLL. **Работает только на десктопных Windows** — на серверных ОС отключён по умолчанию.

**Путь:** `C:\Windows\Prefetch\*.pf`

**На какие вопросы отвечает:**
- Запускался ли конкретный исполняемый файл на системе?
- Когда именно он запускался (до 8 последних временных меток)?
- Сколько раз запускался файл?
- Какие файлы и DLL загружал процесс (полезно для анализа малвари)?

**Парсинг:**
```powershell
# KAPE: Target = Prefetch
# Module = PECmd.mkape — парсит все .pf файлы
# PECmd.exe -d "C:\Windows\Prefetch" --csv output --csvf prefetch.csv

# Ручной просмотр через PECmd
PECmd.exe -f "C:\Windows\Prefetch\MALWARE.EXE-XXXXXXXX.pf"

# В Timeline Explorer:
# 1. Открыть prefetch.csv
# 2. Фильтр по Run Date
# 3. Колонка ExecutableName — поиск подозрительных имён
# 4. Колонка SourceFilesReferenced — что загружал процесс
```

**Инструменты:** KAPE (`Prefetch.tkape` → `PECmd.mkape`) · Velociraptor (`Windows.Forensics.Prefetch`)

---

### 6.2 AmCache 🔴

**Что это:** Реестровый куст `Amcache.hve`, часть Application Compatibility Framework. Фиксирует метаданные исполняемых файлов, с которыми взаимодействовала система: полный путь, SHA-1 хэш, размер файла, информацию о компании и продукте. Хранит информацию о **драйверах**, **исполняемых файлах** и **установленных программах**.

> ⚠️ **Важно:** Записи AmCache создаются задачей планировщика `Microsoft Compatibility Appraiser` — она сканирует файлы в `Program Files`, `Desktop` и других директориях. Таким образом, файл мог **существовать** на диске без запуска, но попасть в AmCache. AmCache — это **доказательство присутствия**, а не обязательно запуска.

**Путь:** `C:\Windows\AppCompat\Programs\Amcache.hve`

**На какие вопросы отвечает:**
- Существовал ли конкретный исполняемый файл на системе (даже если он удалён)?
- Каков SHA-1 хэш файла (для проверки в VirusTotal/TI-платформах)?
- Откуда запускался файл (полный путь, включая съёмные носители)?
- Какие драйверы устанавливались в систему?
- Присутствовало ли антифорензик-ПО (CCleaner, DBAN и т.д.)?

**Парсинг:**
```powershell
# KAPE: Target = Amcache
# Module = AmcacheParser.mkape
AmcacheParser.exe -f "C:\Windows\AppCompat\Programs\Amcache.hve" --csv output

# Поиск по SHA-1 хэшам в TI-системах:
# 1. Распарсить AmcacheParser → amcache_InventoryApplicationFile.csv
# 2. Извлечь колонку SHA1
# 3. Проверить по VirusTotal или NSRL (легитимные хэши)

# В Timeline Explorer:
# Открыть amcache_InventoryApplicationFile.csv
# Смотреть FileKeyLastWriteTimestamp + SHA1
```

**Инструменты:** KAPE (`Amcache.tkape` → `AmcacheParser.mkape`) · Velociraptor · Registry Explorer

---

### 6.3 ShimCache (AppCompatCache) 🔴

**Что это:** Кэш совместимости приложений, хранимый в реестре. Фиксирует метаданные исполняемых файлов: путь и дату последней модификации. **Критическое отличие:** записи в ShimCache создаются при **выключении системы**, а не в момент запуска. Порядок записей: самые новые взаимодействия — в начале списка, самые старые — вытесняются. Windows 10+ не говорит, был ли исполнен файл.

**Путь реестра:**
```
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
```

**На какие вопросы отвечает:**
- Был ли файл доступен или запущен на системе (доказательство присутствия)?
- Когда файл был модифицирован в последний раз (дата модификации файла)?
- Есть ли исполняемые файлы в ShimCache, которые отсутствуют на диске (признак удалённой малвари)?

```powershell
# KAPE: Target = RegistryHives (SYSTEM)
# Module = AppCompatCacheParser.mkape
# AppCompatCacheParser.exe -f "C:\Windows\System32\config\SYSTEM" --csv output --csvf shimcache.csv

# В Timeline Explorer:
# Открыть shimcache.csv
# Фильтр по LastModified
# Искать пути в %TEMP%, %APPDATA%, нестандартные пути
```

**Инструменты:** KAPE (`RegistryHives.tkape` → `AppCompatCacheParser.mkape`) · Velociraptor

---

### 6.4 BAM / DAM (Background Activity Moderator) 🔴

**Что это:** Background Activity Moderator — компонент Windows 10+, управляющий фоновой активностью приложений. Ведёт учёт исполняемых файлов с временными метками **последнего запуска**. В отличие от ShimCache, BAM даёт прямые временные метки выполнения.

**Путь реестра:**
```
HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>\    ← Windows 10 1809+
HKLM\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\<SID>\
```

**На какие вопросы отвечает:**
- Когда конкретный исполняемый файл запускался последний раз (прямая временная метка)?
- Какие исполняемые файлы запускались с полными путями (включая съёмные носители)?
- Запускались ли антифорензик или хакерские инструменты конкретным пользователем?

```powershell
# KAPE: Target = RegistryHives (SYSTEM)
# Module = RECmd_Kroll.mkape — парсит BAM-ключи
reg query "HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" /s
```

**Инструменты:** KAPE → `RECmd_Kroll.mkape` · Registry Explorer

---

## 7. SRUM (System Resource Usage Monitor)

*Монитор использования системных ресурсов — детальная статистика по приложениям и сетевой активности.*

### 7.1 SRUM Database 🔴

**Что это:** База данных ESE (Extensible Storage Engine), в которой Windows ведёт детальную статистику использования ресурсов каждым приложением: объём переданных/полученных данных по сети, использование CPU, количество операций ввода-вывода. Хранит данные за **30–60 дней**. Для IR: позволяет количественно оценить эксфильтрацию данных — сколько байт конкретное приложение отправило/получило.

**Путь:** `C:\Windows\System32\sru\SRUDB.dat`

**На какие вопросы отвечает:**
- Сколько данных приложение передало по сети (объём эксфильтрации)?
- Какие приложения использовали сеть в конкретный временной промежуток?
- Как долго работало конкретное приложение (время CPU)?
- Было ли вредоносное ПО активно в заданный период даже после удаления с диска?

**Таблицы SRUDB.dat:**

| Таблица | Описание |
|---------|----------|
| `{973F5D5C-...}` (Network Usage) | Байты отправлено/получено по приложениям |
| `{DD6636C4-...}` (Network Connectivity) | Время подключения к сети |
| `{D10CA2FE-...}` (Energy Usage) | Потребление энергии (ноутбуки) |
| `{FEE4E14F-...}` (Application Resource Usage) | CPU, I/O по приложениям |

**Парсинг:**
```powershell
# KAPE: Target = SRUM
# Module = SrumECmd.mkape (требует SRUM-Repair.ps1 для исправления ESE-журнала)
# Последовательность:
# 1. Скопировать SRUDB.dat + SOFTWARE (реестровый куст для имён приложений)
# 2. Запустить SRUM-Repair.ps1 (https://github.com/AndrewRathbun/DFIRPowerShellScripts/blob/main/KAPE/SRUM-Repair.ps1) для исправления транзакционного журнала
SrumECmd.exe -f "SRUDB.dat" -r "SOFTWARE" --csv output

# В Timeline Explorer:
# Открыть srumdb_NetworkUsage.csv
# Смотреть BytesSent, BytesRecvd по ExeName
# Сортировать по BytesSent DESC — топ по эксфильтрации
```

**Инструменты:** KAPE (`SRUM.tkape` → `SrumECmd.mkape`) · Velociraptor (`Windows.Forensics.SRUM`)

---

## 8. System Logs

*Журналы событий Windows — хронология всего происходящего в системе.*

> **Важное разделение:** события делятся на **включённые по умолчанию** (доступны без дополнительной настройки) и **расширенные** (требуют явного включения групповой политики). Отсутствие расширенных журналов в собранных данных — не ошибка, а особенность конфигурации системы. При выборе инфраструктуры для мониторинга рекомендуется включать расширенный аудит целенаправленно.

---

### 8.1 Security.evtx — Аутентификация и привилегии 🔴

**Что это:** Журнал безопасности Windows. Содержит события аутентификации, управления учётными записями, доступа к объектам (если включён), привилегированных действий. **По умолчанию** ведёт базовый набор событий.

**Путь:** `C:\Windows\System32\winevt\Logs\Security.evtx`

**На какие вопросы отвечает:**
- Кто и когда входил в систему (интерактивно, по сети, через RDP)?
- Были ли попытки подбора пароля (серия EID 4625)?
- Создавались ли новые пользователи или изменялись группы?
- Какие привилегированные операции выполнялись?

**Ключевые события (по умолчанию):**

| EID | Описание | Важность |
|-----|----------|----------|
| 4624 | Успешный вход | Тип входа 2=Интерактивный, 3=Сетевой, 10=RemoteInteractive (RDP), 7=Unlock |
| 4625 | Неуспешный вход | Серия → брутфорс |
| 4634/4647 | Выход из системы | |
| 4648 | Явный вход с альтернативными кредами (`runas`) | Pass-the-Hash / Pass-the-Ticket |
| 4720 | Создание нового пользователя | Высокий приоритет |
| 4722 | Учётная запись активирована | |
| 4726 | Учётная запись удалена | |
| 4728/4732/4756 | Добавление в группу безопасности | Особенно в Administrators |
| 4768 | Запрос TGT (Kerberos) | Начало Kerberos-аутентификации |
| 4769 | Запрос Service Ticket (Kerberos) | Kerberoasting (множество запросов к разным SPN) |
| 4771 | Отказ Kerberos pre-auth | |
| 4776 | NTLM-аутентификация | |
| 4672 | Специальные привилегии при входе | |

**Расширенные события** 🔧 (требуют настройки политики аудита):

| EID | Описание | Как включить |
|-----|----------|-------------|
| 4688 | Создание процесса с командной строкой | `Audit Process Creation` + ключ реестра для записи командной строки: `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1` |
| 4663 | Доступ к объекту (файл, реестр) | `Audit Object Access` (очень шумный, включать точечно) |
| 4698 | Создание задачи планировщика | `Audit Other Object Access Events` |
| 5140/5145 | Доступ к сетевому ресурсу | `Audit File Share` |

**Парсинг:**
```powershell
# KAPE: Target = EventLogs (или SecurityEventLog)
# Module = EvtxECmd.mkape — парсит evtx в CSV с использованием EZ Maps
# EvtxECmd.exe -d "C:\Windows\System32\winevt\Logs" --csv output --csvf evtx.csv

# Фильтр по EID через PowerShell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4720,4728} |
  Select-Object TimeCreated, Id, Message | Export-Csv auth_events.csv

# Hayabusa — детект аномалий по сигнатурам:
# hayabusa.exe csv-timeline -d "C:\Windows\System32\winevt\Logs" -o timeline.csv

# В Timeline Explorer:
# Открыть evtx.csv → фильтр по EID
# Chainsaw: chainsaw hunt "C:\Windows\System32\winevt\Logs" -s sigma/ --csv > chainsaw.csv
```

**Инструменты:** KAPE (`EventLogs.tkape` → `EvtxECmd.mkape`) · Hayabusa · Chainsaw · Velociraptor (`Windows.EventLogs.EvtxHunter`)

---

### 8.2 System.evtx — Службы и система 🔴

**Что это:** Системный журнал. Фиксирует запуск/остановку служб, ошибки драйверов, события Plug and Play (подключение USB), изменения системного времени.

**Путь:** `C:\Windows\System32\winevt\Logs\System.evtx`

**На какие вопросы отвечает:**
- Когда устанавливались и запускались новые службы?
- Когда подключались USB-устройства (Plug and Play события)?
- Изменялось ли системное время (признак антикриминалистики)?
- Когда система была перезагружена?

| EID | Источник | Описание |
|-----|----------|----------|
| 7045 | Service Control Manager | Установка новой службы — **высокий приоритет** |
| 7036 | Service Control Manager | Запуск/остановка службы |
| 7040 | Service Control Manager | Изменение типа запуска службы |
| 6005 | EventLog | Запуск Event Log (= загрузка Windows) |
| 6006 | EventLog | Остановка Event Log (= выключение Windows) |
| 20001/20003 | Plug and Play | Установка/удаление USB-устройства |
| 104 | EventLog | Очистка журнала (признак сокрытия следов!) |

**Парсинг:**
```powershell
# KAPE → EvtxECmd.mkape (парсит все evtx включая System.evtx)

# Только новые службы
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} |
  ForEach-Object { $_.Message } | Select-String "Service Name|Service File"
```

---

### 8.3 PowerShell — Журналы скриптов 🔴

**Что это:** PowerShell ведёт несколько журналов. Наиболее ценны для IR: **Script Block Logging** (фиксирует все исполняемые блоки кода, включая декодированный obfuscated PowerShell) и **Transcription** (полный ввод/вывод сессии в текстовый файл).

> ⚠️ **Большинство полезных PowerShell-журналов ОТКЛЮЧЕНЫ по умолчанию** и требуют явного включения через GPO или реестр.

**Пути журналов:**
```
C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx
C:\Windows\System32\winevt\Logs\Windows PowerShell.evtx
```

**На какие вопросы отвечает:**
- Какие PowerShell-скрипты выполнялись (включая obfuscated)?
- Есть ли признаки загрузки payload через Invoke-Expression, WebClient, DownloadString?
- Каков полный текст выполненных команд?

| EID | Описание | Включён по умолчанию |
|-----|----------|---------------------|
| 400 | Запуск движка PowerShell | ✅ Да |
| 403 | Остановка движка | ✅ Да |
| 4103 | Pipeline execution (Module Logging) | ❌ Нет |
| 4104 | **Script Block Logging** — исполняемый код | ❌ Нет |

**Как включить расширенный аудит PowerShell** 🔧:
```powershell
# Script Block Logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

# Module Logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f

# Transcription (сохранение в файл)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d "C:\PSTranscripts" /f
```

**Парсинг:**
```powershell
# KAPE: Target = PowerShellConsole (собирает evtx + транскрипты)
# Module = EvtxECmd.mkape

Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} |
  Select-Object TimeCreated, @{n="Script";e={$_.Message}} |
  Where-Object {$_.Script -match "IEX|Invoke-Expression|DownloadString|FromBase64|WebClient"} |
  Export-Csv suspicious_ps.csv
```

**Инструменты:** KAPE (`PowerShellConsole.tkape` → `EvtxECmd.mkape`) · Velociraptor (`Windows.EventLogs.PowershellScriptblock`)

---

### 8.4 RDP — Журналы подключений 🔴

**Что это:** Несколько журналов, фиксирующих входящие и исходящие RDP-подключения. Позволяют восстановить боковое перемещение (lateral movement) и несанкционированный удалённый доступ.

**Пути журналов:**
```
C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx
C:\Windows\System32\winevt\Logs\Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx
```

**На какие вопросы отвечает:**
- Кто и с какого IP подключался по RDP и когда?
- Были ли входящие RDP-подключения в нерабочее время?
- Какой пользователь инициировал RDP-сессию?
- Когда RDP-сессия была завершена?

| EID | Журнал | Описание |
|-----|--------|----------|
| 21 | LocalSessionManager | Успешный вход по RDP |
| 23 | LocalSessionManager | Выход из RDP-сессии |
| 24 | LocalSessionManager | Отключение RDP-сессии (без выхода) |
| 25 | LocalSessionManager | Переподключение к существующей сессии |
| 1149 | RemoteConnectionManager | Аутентификация RDP (IP-адрес клиента!) |
| 4624 | Security.evtx | Тип входа 10 = RemoteInteractive (RDP) |

**Исходящие RDP (mstsc.exe):**
```
HKCU\SOFTWARE\Microsoft\Terminal Server Client\Servers\   ← история подключений
C:\Users\<user>\AppData\Local\Microsoft\Terminal Server Client\Cache\  ← кэш экрана
```

**Парсинг:**
```powershell
# KAPE: Target = RDPLogs (или EventLogs)
# Module = EvtxECmd.mkape

Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Id=1149
} | Select-Object TimeCreated, @{n="User";e={$_.Properties[0].Value}},
  @{n="Domain";e={$_.Properties[1].Value}},
  @{n="SourceIP";e={$_.Properties[2].Value}}
```

**Инструменты:** KAPE → `EvtxECmd.mkape` · Velociraptor

---

### 8.5 Kerberos — Журналы аутентификации 🔴

**Что это:** События Kerberos в `Security.evtx` — аутентификация в Active Directory. Ключевы для обнаружения **Kerberoasting** (атака на SPN-учётные записи через запросы Service Ticket), **Pass-the-Ticket**, **Golden/Silver Ticket**, **AS-REP Roasting**.

**На какие вопросы отвечает:**
- Есть ли аномальный паттерн запросов Service Ticket к множеству SPN (Kerberoasting)?
- Есть ли запросы TGT без pre-authentication (AS-REP Roasting)?
- Есть ли аутентификация с нестандартного IP для привилегированной учётной записи?
- Есть ли ошибки аутентификации с последующим успехом (брутфорс)?

| EID | Описание |
|-----|----------|
| 4768 | Запрос TGT — начало Kerberos-сессии |
| 4769 | Запрос Service Ticket (много запросов к разным SPN = Kerberoasting) |
| 4770 | Обновление Service Ticket |
| 4771 | Отказ Kerberos pre-authentication (AS-REP Roasting) |
| 4672 | Специальные привилегии при входе (Domain Admin?) |

> ℹ️ События Kerberos полноценно записываются на **контроллерах домена (DC)**. На рядовых серверах и рабочих станциях Kerberos-события менее детальны.

**Парсинг:**
```powershell
# KAPE → EvtxECmd.mkape (собирать Security.evtx с DC)

# Kerberoasting — много Service Ticket запросов от одного источника
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} |
  Group-Object {$_.Properties[0].Value} |
  Where-Object {$_.Count -gt 10} |
  Sort-Object Count -Descending
```

---

### 8.6 Windows Defender / Antivirus журналы 🟡

**Путь:**
```
C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx
C:\ProgramData\Microsoft\Windows Defender\Support\   ← MPLog файлы
```

**На какие вопросы отвечает:**
- Обнаруживал ли Defender угрозы в период инцидента?
- Были ли угрозы помещены в карантин или удалены?
- Отключался ли Defender (признак действий злоумышленника)?

| EID | Описание |
|-----|----------|
| 1116 | Обнаружение угрозы |
| 1117 | Принятие мер по угрозе (карантин/удаление) |
| 1118/1119 | Удаление угрозы |
| 5001 | Защита в реальном времени отключена |
| 5007 | Изменение конфигурации Defender |

**Инструменты:** KAPE (`WindowsDefender.tkape` → `EvtxECmd.mkape`)

---

## 9. Authentication

*Аутентификация и управление учётными записями.*

### 9.1 SAM — База локальных учётных записей 🔴

**Что это:** Security Account Manager — реестровый куст, хранящий хэши паролей локальных пользователей Windows. Файл заблокирован системой на живой системе. При IR важен для инвентаризации локальных учётных записей и обнаружения скрытых или созданных злоумышленником аккаунтов. Анализ хэшей выполняется **только в рамках DFIR-расследования** для проверки факта компрометации учётных данных или их слабости.

> ⚠️ Хэши в SAM могут быть использованы злоумышленником для Pass-the-Hash атак. При обнаружении компрометации SAM необходимо сменить все локальные пароли на хостах, включая хост куда злоумышленник мог получить доступ.

**Путь:** `C:\Windows\System32\config\SAM` (+ SYSTEM для расшифровки)

**На какие вопросы отвечает:**
- Какие локальные учётные записи существуют на системе (включая скрытые)?
- Когда созданы учётные записи?
- Есть ли нелегитимные административные аккаунты?
- Когда последний раз менялся пароль каждой учётной записи?

**Парсинг:**
```powershell
# Инвентаризация пользователей (без хэшей, встроенными инструментами)
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet,
  @{n="IsAdmin";e={$_ | Get-LocalGroupMember Administrators -EA SilentlyContinue}}

# Члены группы Administrators
Get-LocalGroupMember -Group "Administrators"

# KAPE: Target = RegistryHives (копирует SAM + SYSTEM)
# Анализ метаданных через Registry Explorer (без извлечения хэшей)
# RECmd_Kroll.mkape парсит ключи SAM для метаданных пользователей
```

**Инструменты:** KAPE (`RegistryHives.tkape` → `RECmd_Kroll.mkape`) · Registry Explorer

---

### 9.2 DPAPI (Data Protection API) артефакты 🟡

**Что это:** DPAPI — Windows-механизм шифрования пользовательских секретов. Браузеры, почтовые клиенты, RDP-клиент, менеджеры паролей хранят данные, защищённые DPAPI. Мастер-ключ привязан к паролю пользователя. Для IR: позволяет понять, к каким секретам мог получить доступ злоумышленник.

**Пути:**
```
C:\Users\<user>\AppData\Roaming\Microsoft\Protect\<SID>\   ← мастер-ключи DPAPI
C:\Users\<user>\AppData\Local\Microsoft\Credentials\       ← зашифрованные кредсы
C:\Users\<user>\AppData\Roaming\Microsoft\Credentials\
```

**На какие вопросы отвечает:**
- Какие зашифрованные секреты хранятся в системе (тип и количество)?
- Какие приложения используют DPAPI (Chrome пароли, RDP, WiFi-ключи)?
- Есть ли признаки попытки экспорта DPAPI-секретов?

```powershell
# Инвентаризация DPAPI-блобов (только метаданные, без расшифровки)
Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Credentials" -EA SilentlyContinue
Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Protect" -Recurse -EA SilentlyContinue

# KAPE: Target = DPAPI (собирает мастер-ключи и блобы для офлайн-анализа)
```

---

### 9.3 Сессии и активные пользователи ⏱️ 🟡

**Что это:** Текущие активные и закрытые сессии пользователей на живой системе. Ключевые данные для понимания, кто работал с системой в момент обнаружения инцидента.

**На какие вопросы отвечает:**
- Кто в данный момент авторизован в системе?
- Есть ли активные RDP или сетевые сессии?
- Когда последний раз каждый пользователь входил в систему?

```powershell
# Текущие сессии
query session
query user

# История входов
Get-EventLog -LogName Security -InstanceId 4624 -Newest 50 |
  Select-Object TimeGenerated, @{n="User";e={$_.ReplacementStrings[5]}},
  @{n="LogonType";e={$_.ReplacementStrings[8]}},
  @{n="Source";e={$_.ReplacementStrings[18]}}

# Последние входы пользователей через реестр
# HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI
```

---

## 10. Applications

### 10.1 История установки ПО 🟡

**Пути:**
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\
HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\
C:\Windows\System32\winevt\Logs\Setup.evtx
```

**На какие вопросы отвечает:**
- Какое ПО установлено на системе (включая нестандартные инструменты)?
- Когда устанавливалось конкретное приложение?
- Есть ли ПО для удалённого доступа (AnyDesk, TeamViewer, RMM-инструменты)?

```powershell
# Всё установленное ПО
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
  "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" |
  Select-Object DisplayName, DisplayVersion, InstallDate, Publisher |
  Sort-Object InstallDate | Export-Csv installed_software.csv

# RMM и инструменты удалённого доступа (разбираться в контексте инцидента)
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" |
  Where-Object {$_.DisplayName -match "AnyDesk|TeamViewer|Radmin|VNC|RDP|Remote|Splashtop|ConnectWise"}
```

**Инструменты:** KAPE → `RECmd_Kroll.mkape` · Velociraptor

---

### 10.2 WMI Repository 🟡

**Что это:** Бинарный репозиторий WMI в `C:\Windows\System32\wbem\Repository`. Содержит все зарегистрированные классы WMI, провайдеры и — самое важное для DFIR — WMI Event Subscriptions (persistence, см. 1.4). Заслуживает отдельного артефакта, так как репозиторий нужно собирать для офлайн-анализа.

**На какие вопросы отвечает:**
- Есть ли WMI-persistence (EventFilter/Consumer, уже описан в 1.4)?
- Какие нестандартные WMI-классы зарегистрированы?
- Есть ли следы MOF-компиляции (malicious .mof файлы)?

```powershell
# KAPE: Target = WMIRepository
# Анализ: strings OBJECTS.DATA | grep -i CommandLine
# PyWMIPersistenceFinder.py -i OBJECTS.DATA
```

---

## 11. Security State

*Состояние защитных механизмов и источники телеметрии.*

### 11.1 Windows Defender статус 🔴

**Что это:** Встроенный антивирус. Его отключение или изменение политик исключений — типичное действие злоумышленника после получения доступа.

```powershell
Get-MpComputerStatus | Select-Object AMServiceEnabled, AntispywareEnabled,
  AntivirusEnabled, RealTimeProtectionEnabled, OnAccessProtectionEnabled,
  IoavProtectionEnabled, BehaviorMonitorEnabled, NisEnabled

# Исключения (malware часто добавляет себя в исключения)
Get-MpPreference | Select-Object ExclusionPath, ExclusionExtension, ExclusionProcess

# KAPE: Target = WindowsDefender
# Module = EvtxECmd.mkape (EID 5001, 5007)
```

**На какие вопросы отвечает:**
- Включена ли защита в реальном времени?
- Добавлены ли подозрительные пути в исключения?
- Когда и кем были изменены настройки Defender?

---

### 11.2 Windows Firewall 🟡

**Пути:**
```
C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx
HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy
C:\Windows\System32\LogFiles\Firewall\pfirewall.log    ← лог соединений (если включён)
```

**На какие вопросы отвечает:**
- Отключался ли Firewall?
- Добавлялись ли нестандартные правила (открытие портов для backdoor)?
- Есть ли правила, разрешающие входящие соединения для нестандартных приложений?

```powershell
# Текущие правила
Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound'} |
  Select-Object DisplayName, Action, @{n="Program";e={(Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $_).Program}}

# KAPE: Target = WindowsFirewall
# Module = EvtxECmd.mkape (EID 2004 = добавлено правило, 2006 = удалено)
```

---

### 11.3 AMSI (Antimalware Scan Interface) и ETW 🟡

**Что это:** AMSI — интерфейс, позволяющий антивирусным продуктам сканировать скрипты перед выполнением (PowerShell, VBScript, JScript, WMI). ETW (Event Tracing for Windows) — инфраструктура трассировки событий ядра, из которой Defender и другие продукты получают телеметрию.

**На какие вопросы отвечает:**
- Есть ли попытки обхода AMSI (AMSI bypass в журналах PowerShell)?
- Какие провайдеры ETW активны (EDR-агенты обычно подписываются на ключевые провайдеры)?

```powershell
# Активные ETW-провайдеры
logman query providers
Get-EtwTraceSession

# Попытки отключить AMSI (искать в Script Block Log 4104)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} |
  Where-Object {$_.Message -match "amsiInitFailed|AmsiScanBuffer|amsi.dll"}
```

---

### 11.4 Sysmon (если установлен) 🔴

**Что это:** System Monitor (Sysinternals) — бесплатный драйвер и служба для глубокого мониторинга системы. Если установлен в организации — **главный источник телеметрии** для DFIR. Записывает создание процессов с хэшами, сетевые соединения, изменения реестра, загрузку драйверов, WMI-события.

**Путь журнала:**
```
C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx
```

**На какие вопросы отвечает (по ключевым EID):**

| EID | Описание |
|-----|----------|
| 1 | Создание процесса (с хэшем и командной строкой) |
| 2 | Изменение временных меток файла (timestomping!) |
| 3 | Сетевое соединение процесса |
| 6 | Загрузка драйвера |
| 7 | Загрузка образа DLL |
| 10 | Доступ к процессу (Process Access — инъекция) |
| 11 | Создание файла |
| 13 | Изменение значения реестра |
| 22 | DNS-запрос процессом |
| 25 | Подмена образа процесса (Process Tampering) |

```powershell
# KAPE: Target = Sysmon (собирает evtx)
# Module = EvtxECmd.mkape

# Hayabusa отлично работает с Sysmon-логами для detections
# hayabusa.exe csv-timeline -d "C:\Windows\System32\winevt\Logs" -o sysmon_timeline.csv
```

**Инструменты:** KAPE → `EvtxECmd.mkape` · Hayabusa · Velociraptor

---

### 11.5 Audit Policy — Текущие настройки аудита 🟡

**Что это:** Конфигурация политики аудита определяет, какие события записываются в Security.evtx. Понимание текущей политики аудита помогает оценить полноту журналов.

```powershell
# Текущие настройки аудита
auditpol /get /category:*

# KAPE: Target = RegistryHives + EventLogs
```

---

## 12. Memory & Volatile

### 12.1 RAM-дамп ⏱️ 🟡 ⚠️

**Что это:** Полный снапшот оперативной памяти. Содержит запущенные процессы, ключи шифрования (BitLocker!), fileless malware, injected shellcode, учётные данные в памяти (lsass), расшифрованные строки вредоносного ПО. Бесценен для анализа fileless-атак.

**На какие вопросы отвечает:**
- Есть ли fileless malware или инжектированный шеллкод в памяти?
- Есть ли ключи шифрования BitLocker в памяти?
- Какие учётные данные находятся в памяти lsass?
- Есть ли процессы, скрытые от стандартных инструментов через DKOM?

```powershell
# WinPmem (рекомендуется, open-source)
winpmem_mini_x64.exe memory.aff4
# Или вывод в raw:
winpmem_mini_x64.exe -o memory.raw

# Magnet RAM Capture (GUI, бесплатный)
# RAMMap (Sysinternals) — менее полный, для быстрого анализа

# Volatility 3 — анализ дампа
python3 vol.py -f memory.raw windows.pslist          # список процессов
python3 vol.py -f memory.raw windows.netscan         # сетевые соединения
python3 vol.py -f memory.raw windows.malfind         # подозрительные регионы памяти
python3 vol.py -f memory.raw windows.cmdline         # командные строки
python3 vol.py -f memory.raw windows.dlllist         # загруженные DLL
python3 vol.py -f memory.raw windows.ldrmodules      # DLL без записей в PEB (инъекция)
```

---

### 12.2 Переменные окружения ⏱️ 🟡

**Что это:** Переменные окружения процессов. Нестандартные переменные могут содержать C2-адреса, пути к компонентам малвари, ключи для расшифровки.

```powershell
# Текущие переменные системы
[System.Environment]::GetEnvironmentVariables() | Out-File env.txt

# Переменные конкретного процесса (через WMI)
(Get-WmiObject Win32_Process -Filter "ProcessId=<PID>").GetOwner()
```

---

## 13. External Devices

### 13.1 USB-устройства 🟡

**Что это:** История подключения USB-устройств. В отличие от macOS, Windows ведёт детальный реестровый учёт всех когда-либо подключавшихся USB-устройств с метаданными, временными метками первого и последнего подключения.

**Пути реестра:**
```
HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR\         ← устройства хранения (флешки, диски)
HKLM\SYSTEM\CurrentControlSet\Enum\USB\              ← все USB-устройства
HKLM\SOFTWARE\Microsoft\Windows Portable Devices\   ← дружелюбные имена устройств
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\  ← точки монтирования
```

**На какие вопросы отвечает:**
- Какие USB-накопители подключались к системе и когда?
- Каковы серийный номер и идентификатор VID/PID устройства?
- Когда устройство подключалось первый раз и последний раз?
- Какую букву диска получало устройство (для корреляции с LNK-файлами)?

```powershell
# KAPE: Target = USBDetective (собирает все реестровые ключи USB)
# Module = RECmd_Kroll.mkape

# Быстрый просмотр через PowerShell
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" |
  Select-Object FriendlyName, DeviceType,
  @{n="FirstInstall";e={$_.Properties[10].Data}},
  @{n="LastArrival";e={$_.Properties[11].Data}}

# System.evtx EID 20001/20003 — события Plug and Play
```

**Инструменты:** KAPE (`USBDetective.tkape` → `RECmd_Kroll.mkape`) · USB Detective · Velociraptor

---

### 13.2 Bluetooth 🟢

**Путь реестра:**
```
HKLM\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices\
```

```powershell
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices\*" |
  Select-Object Name, Address, LastConnected
```

---

## 14. Registry

*Реестр Windows — централизованное хранилище конфигурации системы, пользователей и приложений.*

### 14.1 Структура и кусты реестра (Hives)

**Что это:** Реестр Windows физически хранится в нескольких файлах-кустах (hives). Для DFIR важно понимать, какой куст где хранится на диске — это определяет, что и откуда собирать.

| Куст реестра | Файл на диске | Описание |
|-------------|---------------|----------|
| `HKLM\SYSTEM` | `C:\Windows\System32\config\SYSTEM` | Конфигурация системы, службы, драйверы, USB |
| `HKLM\SOFTWARE` | `C:\Windows\System32\config\SOFTWARE` | Установленное ПО, настройки системы |
| `HKLM\SAM` | `C:\Windows\System32\config\SAM` | Локальные учётные записи (доступен только SYSTEM) |
| `HKLM\SECURITY` | `C:\Windows\System32\config\SECURITY` | LSA secrets, политики безопасности |
| `HKCU` / `HKU\<SID>` | `C:\Users\<user>\NTUSER.DAT` | Пользовательские настройки (один файл на пользователя) |
| `HKCU\...\Classes` | `C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat` | COM-регистрации и ShellBags пользователя |
| AmCache | `C:\Windows\AppCompat\Programs\Amcache.hve` | Отдельный реестровый куст (см. раздел 6.1) |

---

### 14.2 Важные ключи реестра для DFIR 🔴

**Системная информация:**
```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion                           ← версия ОС, сборка, дата установки (InstallDate — Unix timestamp)
HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName             ← имя компьютера
HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation                   ← часовой пояс (критично для корреляции временны́х меток)
HKLM\SYSTEM\Select                                                           ← активный ControlSet (Current, LastKnownGood)
```

**Время последнего выключения:**
```
HKLM\SYSTEM\CurrentControlSet\Control\Windows → ShutdownTime (FILETIME в little-endian)
```

**Сетевые интерфейсы:**
```
HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\<GUID>   ← IP, DNS, DHCP, шлюз
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles       ← история сетей: имя, DateFirstConnected, DateLastConnected
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings             ← ProxyEnable, ProxyServer (малварь меняет для перехвата трафика)
```

**Persistence — автозапуск:**
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run                          ← автозапуск для всех пользователей (требует прав admin)
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce                      ← однократный запуск для всех пользователей
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run                          ← автозапуск текущего пользователя (без прав admin — любимый вектор малвари)
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce                      ← однократный запуск текущего пользователя
```

**Persistence — системные механизмы:**
```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon                  ← Shell (explorer.exe) и Userinit: дополнения = красный флаг
HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>                        ← сервисы: ImagePath, Start (2=Auto), Type
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks  ← задачи планировщика (поле Actions — команда запуска)
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree   ← дерево задач планировщика
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs      ← в норме пусто; любое значение = DLL грузится в каждый GUI-процесс
HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute           ← выполняется до загрузки ОС; по умолчанию только autocheck autochk *
```

**Persistence — скрытые техники:**
```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<process.exe>
                                                                             ← значение Debugger: подмена процесса; используется для отключения AV/EDR
HKCU\SOFTWARE\Classes\CLSID\                                                ← COM Hijacking: HKCU имеет приоритет над HKLM, не требует прав admin
HKCU\Environment\UserInitMprLogonScript                                      ← в норме отсутствует; если есть — скрипт выполняется при каждом входе
```

**Пользователи и аутентификация:**
```
SAM\SAM\Domains\Account\Users\Names\                                         ← все локальные аккаунты: RID, дата создания, последний вход
SAM\SAM\Domains\Account\Groups\                                              ← локальные группы и члены (кто локальный admin)
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList                ← SID → путь к профилю (для декодирования SID из логов)
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon                  ← DefaultUserName, DefaultPassword, AutoAdminLogon (пароль в открытом виде!)
```

**USB и внешние устройства:**
```
HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR                                  ← история USB-носителей: VID, PID, серийный номер, время подключения
HKLM\SYSTEM\CurrentControlSet\Enum\USB                                      ← все USB-устройства включая HID (rubber ducky, keystroke injectors)
HKLM\SYSTEM\CurrentControlSet\MountedDevices                                ← маппинг букв дисков на устройства
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2        ← все тома (USB + сетевые шары), к которым пользователь обращался через Explorer
```

**Последние запущенные программы (MRU — Most Recently Used):**
```
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU              ← командная строка Win+R
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU ← открытые/сохранённые файлы через диалог
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs          ← недавние документы по расширениям
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count  ← GUI-запуски приложений (ROT13-кодирование, кол-во запусков + время)
```

**Поисковые запросы и навигация:**
```
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery      ← поиск в Explorer
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths          ← пути, введённые вручную в адресную строку Explorer
HKCU\SOFTWARE\Microsoft\Windows\Shell\Bags                                  ← ShellBags: история навигации по папкам
HKCU\SOFTWARE\Microsoft\Windows\Shell\BagMRU                                ← ShellBags MRU (записи сохраняются даже после удаления папки)
HKU\<SID>_Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags
HKU\<SID>_Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU
```

**Конфигурация безопасности:**
```
HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths                   ← исключения Defender по путям (путь малвари здесь = прямой IoC)
HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions              ← исключения по расширениям
HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes               ← исключения по процессам
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System              ← EnableLUA (0 = UAC отключён), ConsentPromptBehaviorAdmin
HKCU\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell\ExecutionPolicy ← Bypass/Unrestricted без прав admin
HKLM\SECURITY\Policy\PolAdtEv                                                ← текущие настройки аудита (что реально логируется)
```

**RDP и lateral movement:**
```
HKCU\SOFTWARE\Microsoft\Terminal Server Client\Servers                      ← хосты, к которым подключались по RDP исходящие соединения
HKCU\SOFTWARE\Microsoft\Terminal Server Client\Default                      ← последние RDP-подключения
HKCU\Network\                                                                ← подключённые сетевые диски с UNC-путями
```

**Office и документы:**
```
HKCU\SOFTWARE\Microsoft\Office\<version>\Word\Security\TrustedLocations     ← доверенные пути (Office не проверяет безопасность файлов отсюда)
HKCU\SOFTWARE\Microsoft\Office\<version>\Excel\Security\VBAWarnings         ← 1 = макросы включены без предупреждений
```

---

### 14.3 Нюансы анализа реестра 🟡

**1. Last Write Time — единственная временна́я метка ключа**

Каждый ключ реестра имеет только одну временну́ю метку — `Last Write Time` (время последней записи в ключ или любой из его subkeys). Временны́х меток создания, чтения или удаления у ключей реестра нет. Это ограничение нужно учитывать при построении timeline: `Last Write Time` может означать любое изменение в поддереве ключа, а не обязательно изменение конкретного значения.

**2. Значения реестра не имеют временны́х меток**

Отдельные значения (REG_SZ, REG_DWORD и т.д.) не имеют собственных временны́х меток. Для определения времени изменения значения нужно смотреть `Last Write Time` родительского ключа.

**3. Транзакционные журналы реестра**

Каждый куст реестра имеет файлы-журналы транзакций: `SYSTEM.LOG1`, `SYSTEM.LOG2`, `NTUSER.DAT.LOG1` и т.д. Для корректного анализа куста с образа диска необходимо применить эти журналы. Большинство инструментов (Registry Explorer, RECmd) делают это автоматически, но требуют наличия LOG-файлов рядом с кустом.

**4. Удалённые ключи могут быть восстановлены**

Пространство реестра не перераспределяется немедленно после удаления ключей. Registry Explorer и специализированные инструменты могут обнаруживать «мусорное пространство» (slack space) со следами удалённых ключей и значений.

**5. Виртуализация реестра (Registry Virtualization)**

В Windows Vista+ 32-битные приложения, пишущие в `HKLM\SOFTWARE`, могут быть перенаправлены в `HKLM\SOFTWARE\WOW6432Node`. При анализе нужно проверять оба пути.

---

### 14.4 Парсинг реестра 🔴

```powershell
# KAPE: Target = RegistryHives
# Собирает: SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT всех пользователей, UsrClass.dat
# kape.exe --tsource C: --tdest output --target RegistryHives

# Module = RECmd_Kroll.mkape
# RECmd.exe -d "output\C\Windows\System32\config" --csv regs_system --bn BatchExamples\Kroll_Batch.reb
# RECmd.exe -d "output\C\Users" --csv regs_users --bn BatchExamples\Kroll_Batch.reb

# Ручной анализ через Registry Explorer (GUI):
# 1. File → Load Hive → выбрать SYSTEM (он подтянет SYSTEM.LOG1/LOG2 сам)
# 2. Для NTUSER.DAT то же самое
# 3. View → Bookmarks — набор готовых закладок на криминалистически значимые ключи
# 4. Search (Ctrl+F) — поиск по имени, значению, типу данных

# Regripper — быстрый парсинг по плагинам
rip.exe -r NTUSER.DAT -f ntuser > ntuser_rip.txt
rip.exe -r SYSTEM -f system > system_rip.txt
```

**Инструменты:** KAPE (`RegistryHives.tkape` → `RECmd_Kroll.mkape`) · Registry Explorer · RegRipper · Velociraptor (`Windows.Registry.*`)

---

## Приложение 1: Порядок сбора

*Собирай от наиболее волатильных к наименее.*

| Приоритет | Артефакт | Причина волатильности |
|:---------:|----------|-----------------------|
| 1 | Живые процессы, сетевые соединения, открытые файловые дескрипторы, handles | Исчезают при завершении процесса |
| 2 | DNS-кэш, ARP-таблица | Сбрасываются при перезагрузке |
| 3 | RAM-дамп | Полностью теряется при выключении |
| 4 | USN, LogFile | Только live |
| 5 | Переменные окружения процессов | Только live |
| 6 | Security.evtx, System.evtx | Ротируются при заполнении |
| 7 | VSS (теневые копии) | Злоумышленник может удалить |
| 8 | Prefetch | Перезаписываются при новых запусках |
| 9 | USN Journal | Ротируется по достижению максимального размера |
| 10 | AmCache, ShimCache | Обновляются при работе системы |
| 11 | Реестр (Run-ключи, службы) | Персистентны, но могут изменяться |
| 12 | LNK-файлы, JumpLists | Обновляются при открытии файлов |
| 13 | MFT | Стабилен, но записи перезаписываются |
| 14 | SRUM | 30-60 дней истории |
| 15 | Журналы установки, SAM | Практически не меняются |

---

## Приложение 2: Инструменты-комбайны

*Инструменты, способные как собирать артефакты, так и проводить первичный анализ на одной платформе. Именно такой подход — «собрал и сразу получил структурированный вывод» — оптимален при массовой работе с большим числом хостов.*

---

### KAPE + EZ Tools (Kroll Artifact Parser and Extractor) 🔴

**Тип:** Сборщик (Targets) + Парсер (Modules через Eric Zimmerman Tools)  
**Лицензия:** Бесплатно для внутреннего использования, госструктур, правоохранителей; коммерческая лицензия для консультантов  
**Ссылка:** https://www.kroll.com/kape · https://github.com/EricZimmerman/KapeFiles

**Что умеет:** KAPE — двухфазный инструмент. Фаза 1 (Targets): копирует файлы артефактов с живой системы или образа, используя raw-доступ к NTFS для обхода блокировок. Фаза 2 (Modules): запускает EZ Tools (MFTECmd, PECmd, AmcacheParser, EvtxECmd и т.д.) на собранных данных и выдаёт CSV/JSON.

**Ключевые Targets:**
- `!SANS_Triage` — максимальный сбор (рекомендуется для IR)
- `KapeTriage` — стандартный набор
- `$MFT`, `$UsnJrnl` — файловая система
- `EventLogs` — все evtx
- `RegistryHives` — все кусты реестра
- `Prefetch`, `Amcache`, `SRUM`, `LNKFilesAndJumpLists`

**Ключевые Modules:**
- `!EZParser.mkape` — запускает все EZ Tools сразу
- `MFTECmd.mkape` — парсинг MFT и USN Journal
- `PECmd.mkape` — парсинг Prefetch
- `AmcacheParser.mkape` — парсинг AmCache
- `AppCompatCacheParser.mkape` — парсинг ShimCache
- `EvtxECmd.mkape` — парсинг evtx с EZ Maps
- `RECmd_Kroll.mkape` — парсинг реестра по батч-конфигу Kroll
- `SBECmd.mkape` — ShellBags
- `JLECmd.mkape` / `LECmd.mkape` — JumpLists и LNK
- `SrumECmd.mkape` — SRUM
- `AutoRunsToCSV.mkape` — Autoruns

**Базовый флоу:**
```powershell
# 1. Сбор (с живой системы на USB)
kape.exe --tsource C: --tdest E:\KapeOutput --target !SANS_Triage --vss --tflush

# 2. Парсинг собранных данных
kape.exe --msource E:\KapeOutput --mdest E:\KapeParsed --module !EZParser

# 3. Открытие результатов в Timeline Explorer
# Все CSV из E:\KapeParsed → Timeline Explorer → Filter by date
```

**Вывод:** Структурированные CSV файлы, читаемые в Timeline Explorer. Не требует установки, запускается с USB.

---

### Velociraptor 🔴

**Тип:** Агентный DFIR-фреймворк (сбор + анализ + масштабирование на флот)  
**Лицензия:** Open Source (Apache 2.0)  
**Ссылка:** https://velociraptor.app

**Что умеет:** Агент-серверная архитектура. VQL (Velociraptor Query Language) позволяет писать произвольные запросы к артефактам в реальном времени. Имеет встроенные готовые артефакты для большинства Windows-артефактов.

**Режимы работы:**
- **Агентный:** постоянный агент на хосте, централизованное управление
- **Offline Collector:** standalone exe, собирает данные без сервера, упаковывает в ZIP

**Ключевые артефакты VQL:**
```
Windows.Sys.StartupItems          ← Persistence (Run keys, Tasks, Services)
Windows.Analysis.EvidenceOfExecution  ← Prefetch + AmCache + ShimCache
Windows.EventLogs.EvtxHunter      ← поиск по evtx с фильтрами
Windows.NTFS.MFT                  ← MFT в JSON
Windows.Forensics.SRUM             ← SRUM
Windows.Registry.*                ← произвольные запросы к реестру
Windows.Network.Netstat           ← live сетевые соединения
Windows.System.Pslist              ← live процессы
```

**Флоу Offline Collector:**
```powershell
# 1. В GUI Velociraptor Server: Create Offline Collector → выбрать артефакты → Download exe
# 2. Запустить на целевой системе:
Velociraptor_offline_collector.exe

# 3. Загрузить полученный ZIP в Velociraptor Server или распаковать для анализа
```

**Вывод:** JSON/CSV, интеграция с Elasticsearch, встроенный веб-интерфейс для timeline-анализа.

---

### Cyber Triage (Lite / Standard) 🟡

**Тип:** Сборщик + автоматический анализ с скорингом  
**Лицензия:** Lite — бесплатно (без аналитики); Standard/Pro — коммерческая  
**Ссылка:** https://www.cybertriage.com

**Что умеет:** Адаптивный сборщик: начинает со статических правил, затем расширяет сбор на основе найденного (например, находит путь в Run-ключе → собирает соответствующий бинарь). Автоматически скорит артефакты как «плохие» или «подозрительные» на основе эвристик, YARA и VirusTotal (платная версия). Встроенный UI для навигации по артефактам.

**Что собирает:**
- Registry, Event Logs, Prefetch, ShimCache, AmCache, SRUM
- Все исполняемые файлы, запускаемые автозапуском
- Недавно изменённые исполняемые файлы
- Полные метаданные из MFT

**Флоу:**
```
1. Скачать CyberTriageCollector.exe
2. Запустить на целевой системе (от имени администратора)
3. Коллекция сохраняется в ZIP или напрямую отправляется на Cyber Triage сервер
4. В Cyber Triage UI: Add Host → Import Collection
5. Автоматически парсится и скорируется
6. Начать анализ с Bad Items / Suspicious Items
```

**Ограничения Lite:** Без автоматического скоринга, без интеграции с TI.

---

### Magnet AXIOM / AXIOM Cyber 🟡

**Тип:** Коммерческая платформа сбора и анализа  
**Лицензия:** Коммерческая  
**Ссылка:** https://www.magnetforensics.com/axiom

**Что умеет:** Полный цикл от образа диска/KAPE-коллекции до анализа артефактов с timeline. Имеет встроенные парсеры для большинства Windows-артефактов, браузеров, мессенджеров. Ключевая особенность — Connections: автоматически связывает артефакты между собой (процесс → файл → сетевое соединение).

**Флоу:**
```
1. Acquire: подключить источник (диск, образ, KAPE-коллекция, live endpoint)
2. Process: выбрать категории артефактов для анализа → запустить обработку
3. Examine: анализ в AXIOM Examine
   - Timeline: хронологический вид всех событий
   - Connections: граф связей между артефактами
   - Filters: фильтрация по типу, дате, ключевым словам
4. Экспорт: CSV, PDF-отчёт, Timeline
```

---

### Autopsy 🟢

**Тип:** Бесплатная forensic-платформа с модулями  
**Лицензия:** Open Source  
**Ссылка:** https://www.autopsy.com

**Что умеет:** GUI-оболочка над The Sleuth Kit. Подходит для анализа образов дисков. Имеет Ingest Modules для автоматического извлечения артефактов. Медленнее коммерческих решений на больших образах, но бесплатен.

**Флоу:**
```
1. New Case → Add Data Source (выбрать образ диска или папку KAPE)
2. Configure Ingest Modules: Recent Activity, Registry Analysis, Keyword Search
3. Дождаться завершения Ingest
4. Анализ в дереве артефактов слева
5. Timeline → выбрать диапазон дат
6. Report → HTML/Excel
```

---

## Приложение 3: Ссылки

- [flostyen/windows-persistence](https://github.com/flostyen/windows-persistence) — карта техник persistence Windows
- [ForensicArtifacts/artifacts](https://github.com/ForensicArtifacts/artifacts) — реестр артефактов для автоматизации сбора
- [EricZimmerman/KapeFiles](https://github.com/EricZimmerman/KapeFiles) — Targets и Modules для KAPE
- [Eric Zimmerman's Tools](https://ericzimmerman.github.io) — MFTECmd, PECmd, EvtxECmd и другие парсеры
- [Velociraptor](https://velociraptor.app) — DFIR фреймворк
- [SANS FOR508: Advanced Incident Response](https://www.sans.org/cyber-security-courses/advanced-incident-response-threat-hunting-training/)
- [AboutDFIR Windows](https://aboutdfir.com/toolsandartifacts/windows/) — актуальный каталог артефактов
- [13Cubed YouTube](https://www.youtube.com/@13Cubed) — видео-разборы Windows-артефактов
- [Velociraptor Artifact Exchange](https://docs.velociraptor.app/exchange/) — каталог VQL-артефактов
- [Hayabusa](https://github.com/Yamato-Security/hayabusa) — быстрый детект по sigma-правилам из evtx
- [Chainsaw](https://github.com/WithSecureLabs/chainsaw) — поиск по evtx и sigma-правилам
- [Securelist AmCache](https://securelist.com/amcache-forensic-artifact/117622/) — глубокий разбор AmCache (Kaspersky)
- [DFIR.ru](https://dfir.ru) — русскоязычное сообщество, переводы и кейсы

---

## Приложение 4: Покрытие артефактов по инструментам

Сравнительная таблица: **KAPE+EZTools**, **Velociraptor**, **Cyber Triage**, **Magnet AXIOM**.

**Обозначения:**
- ✅ — собирает и парсит / поддерживает
- ⚠️ — частично
- ❌ — не поддерживает

---

### 1. Persistence

| Артефакт | KAPE+EZ | Velociraptor | Cyber Triage | AXIOM |
|---|:---:|:---:|:---:|:---:|
| Run / RunOnce keys | ✅ | ✅ | ✅ | ✅ |
| Scheduled Tasks | ✅ | ✅ | ✅ | ✅ |
| Services | ✅ | ✅ | ✅ | ✅ |
| WMI Subscriptions | ✅ | ✅ | ✅ | ⚠️ |
| DLL Hijacking следы | ⚠️ | ⚠️ | ⚠️ | ❌ |
| COM Hijacking | ✅ | ✅ | ❌ | ❌ |

---

### 2. Process

| Артефакт | KAPE+EZ | Velociraptor | Cyber Triage | AXIOM |
|---|:---:|:---:|:---:|:---:|
| Список живых процессов | ⚠️ (only live) | ✅ | ✅ | ❌ |
| Загруженные DLL / handles | ❌ | ✅ | ⚠️ | ❌ |
| Хэши бинарей | ✅ | ✅ | ✅ | ✅ |

---

### 3. Network

| Артефакт | KAPE+EZ | Velociraptor | Cyber Triage | AXIOM |
|---|:---:|:---:|:---:|:---:|
| Активные соединения | ⚠️ (live only) | ✅ | ✅ | ❌ |
| DNS-кэш | ⚠️ | ✅ | ✅ | ❌ |
| ARP / Routing | ⚠️ | ✅ | ⚠️ | ❌ |
| Конфиг сети / hosts | ✅ | ✅ | ✅ | ✅ |
| Wi-Fi история | ✅ | ✅ | ⚠️ | ✅ |
| Firewall конфиг | ✅ | ✅ | ✅ | ✅ |

---

### 4. File System

| Артефакт | KAPE+EZ | Velociraptor | Cyber Triage | AXIOM |
|---|:---:|:---:|:---:|:---:|
| $MFT (парсинг) | ✅ | ✅ | ✅ | ✅ |
| $UsnJrnl | ✅ | ✅ | ⚠️ | ✅ |
| Prefetch | ✅ | ✅ | ✅ | ✅ |
| LNK-файлы | ✅ | ✅ | ✅ | ✅ |
| VSS (сбор артефактов) | ✅ (`--vss`) | ⚠️ | ❌ | ✅ |

---

### 5. User Activity

| Артефакт | KAPE+EZ | Velociraptor | Cyber Triage | AXIOM |
|---|:---:|:---:|:---:|:---:|
| ShellBags | ✅ | ✅ | ✅ | ✅ |
| JumpLists | ✅ | ✅ | ✅ | ✅ |
| UserAssist | ✅ | ✅ | ✅ | ✅ |
| TypedURLs / Browser History | ✅ | ✅ | ✅ | ✅ |

---

### 6. Execution Artifacts

| Артефакт | KAPE+EZ | Velociraptor | Cyber Triage | AXIOM |
|---|:---:|:---:|:---:|:---:|
| AmCache | ✅ | ✅ | ✅ | ✅ |
| ShimCache | ✅ | ✅ | ✅ | ✅ |
| BAM/DAM | ✅ | ✅ | ⚠️ | ✅ |

---

### 7. SRUM

| Артефакт | KAPE+EZ | Velociraptor | Cyber Triage | AXIOM |
|---|:---:|:---:|:---:|:---:|
| SRUM (Network + App Usage) | ✅ | ✅ | ⚠️ | ✅ |

---

### 8. System Logs

| Артефакт | KAPE+EZ | Velociraptor | Cyber Triage | AXIOM |
|---|:---:|:---:|:---:|:---:|
| Security.evtx | ✅ | ✅ | ✅ | ✅ |
| System.evtx | ✅ | ✅ | ✅ | ✅ |
| PowerShell Operational | ✅ | ✅ | ✅ | ✅ |
| RDP журналы | ✅ | ✅ | ✅ | ✅ |
| Sysmon | ✅ | ✅ | ✅ | ✅ |
| Windows Defender | ✅ | ✅ | ✅ | ✅ |
| Детект по Sigma/Hayabusa | ⚠️ | ✅ | ✅ (встроенный) | ⚠️ |

---

### 9. Authentication

| Артефакт | KAPE+EZ | Velociraptor | Cyber Triage | AXIOM |
|---|:---:|:---:|:---:|:---:|
| SAM (метаданные) | ✅ | ✅ | ✅ | ✅ |
| DPAPI (метаданные) | ✅ | ⚠️ | ❌ | ⚠️ |
| Сессии (live) | ❌ | ✅ | ✅ | ❌ |

---

### 10. Applications

| Артефакт | KAPE+EZ | Velociraptor | Cyber Triage | AXIOM |
|---|:---:|:---:|:---:|:---:|
| Installed software | ✅ | ✅ | ✅ | ✅ |
| Browser history | ✅ | ✅ | ✅ | ✅ |
| WMI Repository | ✅ | ✅ | ✅ | ⚠️ |

---

### 11. Security State

| Артефакт | KAPE+EZ | Velociraptor | Cyber Triage | AXIOM |
|---|:---:|:---:|:---:|:---:|
| Defender статус | ✅ | ✅ | ✅ | ✅ |
| Firewall конфиг | ✅ | ✅ | ✅ | ✅ |
| Sysmon конфиг | ✅ | ✅ | ❌ | ❌ |
| Audit Policy | ✅ | ✅ | ❌ | ❌ |

---

### 12. Memory & Volatile

| Артефакт | KAPE+EZ | Velociraptor | Cyber Triage | AXIOM |
|---|:---:|:---:|:---:|:---:|
| RAM-дамп | ❌ | ❌ | ❌ | ❌ (отдельный Magnet RAM Capture) |
| Анализ дампа памяти | ❌ | ❌ | ❌ | ✅ |

---

### 13. External Devices

| Артефакт | KAPE+EZ | Velociraptor | Cyber Triage | AXIOM |
|---|:---:|:---:|:---:|:---:|
| USB (реестр USBSTOR) | ✅ | ✅ | ✅ | ✅ |
| Bluetooth | ✅ | ✅ | ❌ | ✅ |

---

### 14. Registry

| Артефакт | KAPE+EZ | Velociraptor | Cyber Triage | AXIOM |
|---|:---:|:---:|:---:|:---:|
| Полный сбор кустов | ✅ | ✅ | ✅ | ✅ |
| Парсинг по батч-конфигу | ✅ (RECmd_Kroll) | ⚠️ | ✅ | ✅ |
| Поиск удалённых ключей | ❌ | ❌ | ❌ | ⚠️ |

---

### Сводка по инструментам

| | KAPE + EZ Tools | Velociraptor | Cyber Triage | Magnet AXIOM |
|---|---|---|---|---|
| **Тип** | Сборщик + парсер | Агент + аналитика | Сборщик + автоанализ | Коммерческая платформа |
| **Лицензия** | Бесплатно* | Open Source | Lite бесплатно / Платно | Коммерческая |
| **Режим работы** | Live + offline | Agent / Offline Collector | Live / USB | Live / Image / KAPE-коллекция |
| **Деплой** | USB / сеть | Agent / standalone | Standalone exe | Установка |
| **Первичный анализ** | ✅ (EZ Tools) | ✅ (VQL) | ✅ (Scoring) | ✅ (Инсайты + граф) |
| **Сильные стороны** | Лучший набор парсеров (EZ Tools), VSS, детальный timeline | Масштабирование, VQL-гибкость, live-телеметрия | Адаптивный сбор, автоскоринг, UI | Connections, коммерческая поддержка, анализ памяти |
| **Слепые пятна** | Live-данные ограничены; нет автоскоринга | Нет RAM-дампа; нет Magnet-подобного UI | Без скоринга в Lite; нет VSS | Дорогой; нет live агента (через F-Response) |
| **Уникально** | `!EZParser.mkape` — всё сразу; `--vss` флаг | VQL on-demand; Offline Collector | Adaptive collection; Scoring engine | Connections graph; Memory analysis |

> *KAPE: бесплатно для госструктур, правоохранителей, внутреннего IR. Коммерческая лицензия для консультантов.
