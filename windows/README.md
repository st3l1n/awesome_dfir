# Windows DFIR — Индекс артефактов

Windows 7 / Server 2008 R2 — Windows 11 / Server 2022

> Монолитный справочник: [windows.md](windows.md) | Версия 1.1, 2026-02

---

## Persistence

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 1.1 | Run / RunOnce ключи реестра | [persistence/registry_run_keys.md](persistence/registry_run_keys.md) | WIP |
| 1.2 | Scheduled Tasks | [persistence/scheduled_tasks.md](persistence/scheduled_tasks.md) | WIP |
| 1.3 | Windows Services | [persistence/services.md](persistence/services.md) | WIP |
| 1.4 | WMI Event Subscriptions | [persistence/wmi_subscriptions.md](persistence/wmi_subscriptions.md) | WIP |
| 1.5 | DLL Hijacking — Следы | [persistence/dll_hijacking.md](persistence/dll_hijacking.md) | WIP |
| 1.6 | COM Object Hijacking | [persistence/com_hijacking.md](persistence/com_hijacking.md) | WIP |

## Process

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 2.1 | Список живых процессов | [process/process_list.md](process/process_list.md) | WIP |
| 2.2 | Загруженные DLL и дескрипторы | [process/loaded_dlls.md](process/loaded_dlls.md) | WIP |
| 2.3 | Хэши исполняемых файлов | [process/binary_hashes.md](process/binary_hashes.md) | WIP |

## Network

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 3.1 | Активные соединения | [network/active_connections.md](network/active_connections.md) | WIP |
| 3.2 | DNS-кэш | [network/dns_cache.md](network/dns_cache.md) | WIP |
| 3.3 | ARP-кэш и таблица маршрутизации | [network/arp_routing.md](network/arp_routing.md) | WIP |
| 3.4 | Конфигурация сети и hosts | [network/network_config.md](network/network_config.md) | WIP |
| 3.5 | История Wi-Fi соединений | [network/wifi_history.md](network/wifi_history.md) | WIP |

## File System

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 4.1 | $MFT (Master File Table) | [filesystem/mft.md](filesystem/mft.md) | WIP |
| 4.2 | $UsnJrnl (USN Change Journal) | [filesystem/usn_journal.md](filesystem/usn_journal.md) | WIP |
| 4.3 | $LogFile | [filesystem/logfile.md](filesystem/logfile.md) | WIP |
| 4.4 | $I30 (Directory Index) | [filesystem/i30.md](filesystem/i30.md) | WIP |
| 4.5 | LNK-файлы (Ярлыки) | [filesystem/lnk.md](filesystem/lnk.md) | WIP |
| 4.6 | Volume Shadow Copies (VSS) | [filesystem/vss.md](filesystem/vss.md) | WIP |
| 4.7 | Временные директории | [filesystem/temp_dirs.md](filesystem/temp_dirs.md) | WIP |

## User Activity

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 5.1 | ShellBags | [user_activity/shellbags.md](user_activity/shellbags.md) | WIP |
| 5.2 | JumpLists | [user_activity/jumplists.md](user_activity/jumplists.md) | WIP |
| 5.3 | UserAssist | [user_activity/userassist.md](user_activity/userassist.md) | WIP |
| 5.4 | TypedURLs и история браузеров | [user_activity/browser_history.md](user_activity/browser_history.md) | WIP |

## Execution Artifacts

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 6.1 | Prefetch | [execution/prefetch.md](execution/prefetch.md) | WIP |
| 6.2 | AmCache | [execution/amcache.md](execution/amcache.md) | WIP |
| 6.3 | ShimCache (AppCompatCache) | [execution/shimcache.md](execution/shimcache.md) | WIP |
| 6.4 | BAM / DAM | [execution/bam_dam.md](execution/bam_dam.md) | WIP |

## SRUM

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 7.1 | SRUM Database | [srum/srum.md](srum/srum.md) | WIP |

## System Logs

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 8.1 | Security.evtx | [logs/security_evtx.md](logs/security_evtx.md) | WIP |
| 8.2 | System.evtx | [logs/system_evtx.md](logs/system_evtx.md) | WIP |
| 8.3 | PowerShell журналы | [logs/powershell.md](logs/powershell.md) | WIP |
| 8.4 | RDP журналы | [logs/rdp.md](logs/rdp.md) | WIP |
| 8.5 | Kerberos журналы | [logs/kerberos.md](logs/kerberos.md) | WIP |
| 8.6 | Windows Defender журналы | [logs/defender.md](logs/defender.md) | WIP |

## Authentication

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 9.1 | SAM — База локальных учётных записей | [authentication/sam.md](authentication/sam.md) | WIP |
| 9.2 | DPAPI артефакты | [authentication/dpapi.md](authentication/dpapi.md) | WIP |
| 9.3 | Сессии и активные пользователи | [authentication/sessions.md](authentication/sessions.md) | WIP |

## Applications

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 10.1 | История установки ПО | [applications/software_install.md](applications/software_install.md) | WIP |
| 10.2 | WMI Repository | [applications/wmi_repository.md](applications/wmi_repository.md) | WIP |

## Security State

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 11.1 | Windows Defender статус | [security_state/defender.md](security_state/defender.md) | WIP |
| 11.2 | Windows Firewall | [security_state/firewall.md](security_state/firewall.md) | WIP |
| 11.3 | AMSI и ETW | [security_state/amsi_etw.md](security_state/amsi_etw.md) | WIP |
| 11.4 | Sysmon | [security_state/sysmon.md](security_state/sysmon.md) | WIP |
| 11.5 | Audit Policy | [security_state/audit_policy.md](security_state/audit_policy.md) | WIP |

## Memory & Volatile

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 12.1 | RAM-дамп | [memory/ram_dump.md](memory/ram_dump.md) | WIP |
| 12.2 | Переменные окружения | [memory/env_vars.md](memory/env_vars.md) | WIP |

## External Devices

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 13.1 | USB-устройства | [external_devices/usb.md](external_devices/usb.md) | WIP |
| 13.2 | Bluetooth | [external_devices/bluetooth.md](external_devices/bluetooth.md) | WIP |

## Registry

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 14.1 | Структура и кусты реестра | [registry/structure.md](registry/structure.md) | WIP |
| 14.2 | Важные ключи реестра для DFIR | [registry/important_keys.md](registry/important_keys.md) | WIP |
| 14.3 | Парсинг реестра | [registry/parsing.md](registry/parsing.md) | WIP |
