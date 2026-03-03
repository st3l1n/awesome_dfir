# macOS DFIR — Индекс артефактов

macOS 10.15 Catalina — macOS 15 Sequoia

> Монолитный справочник: [mac.md](mac.md) | Версия 2.1, 2026-02

---

## Persistence

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 1.1 | LaunchDaemons (системные) | [persistence/launch_daemons.md](persistence/launch_daemons.md) | WIP |
| 1.2 | LaunchAgents (пользовательские) | [persistence/launch_agents.md](persistence/launch_agents.md) | WIP |
| 1.3 | Login Items | [persistence/login_items.md](persistence/login_items.md) | WIP |
| 1.4 | Cron Jobs | [persistence/cron.md](persistence/cron.md) | WIP |
| 1.5 | System / Kernel Extensions | [persistence/kernel_extensions.md](persistence/kernel_extensions.md) | WIP |
| 1.6 | Login/Logout Hooks | [persistence/login_logout_hooks.md](persistence/login_logout_hooks.md) | WIP |
| 1.7 | Emond | [persistence/emond.md](persistence/emond.md) | WIP |
| 1.8 | At Jobs | [persistence/at_jobs.md](persistence/at_jobs.md) | WIP |

## Process

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 2.1 | Список живых процессов | [process/process_list.md](process/process_list.md) | WIP |
| 2.2 | Хэши исполняемых файлов | [process/binary_hashes.md](process/binary_hashes.md) | WIP |
| 2.3 | Endpoint Security Events | [process/endpoint_security.md](process/endpoint_security.md) | WIP |

## Network

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 3.1 | Активные соединения | [network/active_connections.md](network/active_connections.md) | WIP |
| 3.2 | ARP-кэш | [network/arp_cache.md](network/arp_cache.md) | WIP |
| 3.3 | Таблица маршрутизации | [network/routing_table.md](network/routing_table.md) | WIP |
| 3.4 | DNS-кэш | [network/dns_cache.md](network/dns_cache.md) | WIP |
| 3.5 | Конфигурация сети и hosts | [network/network_config.md](network/network_config.md) | WIP |
| 3.6 | Wi-Fi история | [network/wifi_history.md](network/wifi_history.md) | WIP |
| 3.7 | Firewall конфигурация | [network/firewall.md](network/firewall.md) | WIP |
| 3.8 | Захват трафика (PCAP) | [network/pcap.md](network/pcap.md) | WIP |

## File System

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 4.1 | FSEvents Store Database | [filesystem/fsevents.md](filesystem/fsevents.md) | WIP |
| 4.2 | Bodyfile (MACB Timestamps) | [filesystem/bodyfile.md](filesystem/bodyfile.md) | WIP |
| 4.3 | Quarantine Events Database | [filesystem/quarantine.md](filesystem/quarantine.md) | WIP |
| 4.4 | Spotlight Metadata | [filesystem/spotlight.md](filesystem/spotlight.md) | WIP |
| 4.5 | .DS_Store файлы | [filesystem/ds_store.md](filesystem/ds_store.md) | WIP |
| 4.6 | Temp-директории | [filesystem/temp_dirs.md](filesystem/temp_dirs.md) | WIP |
| 4.7 | Extended Attributes (xattr) | [filesystem/extended_attrs.md](filesystem/extended_attrs.md) | WIP |

## User Activity

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 5.1 | Shell History | [user_activity/shell_history.md](user_activity/shell_history.md) | WIP |
| 5.2 | KnowledgeC Database | [user_activity/knowledgec.md](user_activity/knowledgec.md) | WIP |
| 5.3 | Biome Data (macOS 13+) | [user_activity/biome.md](user_activity/biome.md) | WIP |
| 5.4 | Apple Intelligence Artifacts (macOS 15+) | [user_activity/apple_intelligence.md](user_activity/apple_intelligence.md) | WIP |
| 5.5 | Recent Items и MRU | [user_activity/recent_items.md](user_activity/recent_items.md) | WIP |
| 5.6 | Trash (Корзина) | [user_activity/trash.md](user_activity/trash.md) | WIP |
| 5.7 | Браузерные артефакты — Safari | [user_activity/browser_safari.md](user_activity/browser_safari.md) | WIP |
| 5.8 | Браузерные артефакты — Chrome/Edge/Firefox | [user_activity/browser_chromium.md](user_activity/browser_chromium.md) | WIP |
| 5.9 | Настроенные облачные аккаунты | [user_activity/cloud_accounts.md](user_activity/cloud_accounts.md) | WIP |

## System Logs

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 6.1 | Unified Logging System | [logs/unified_logging.md](logs/unified_logging.md) | WIP |
| 6.2 | Install Log | [logs/install_log.md](logs/install_log.md) | WIP |
| 6.3 | Crash Reports | [logs/crash_reports.md](logs/crash_reports.md) | WIP |
| 6.4 | ASL (Apple System Log) | [logs/asl.md](logs/asl.md) | WIP |

## Authentication

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 7.1 | TCC Database | [authentication/tcc.md](authentication/tcc.md) | WIP |
| 7.2 | Keychain | [authentication/keychain.md](authentication/keychain.md) | WIP |
| 7.3 | Sudo Logs | [authentication/sudo_logs.md](authentication/sudo_logs.md) | WIP |
| 7.4 | SSH конфигурация и ключи | [authentication/ssh_config.md](authentication/ssh_config.md) | WIP |
| 7.5 | Пользователи системы | [authentication/users.md](authentication/users.md) | WIP |
| 7.6 | История входов | [authentication/login_history.md](authentication/login_history.md) | WIP |

## Applications

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 8.1 | История установки ПО | [applications/software_install.md](applications/software_install.md) | WIP |
| 8.2 | Code Signing и Gatekeeper | [applications/code_signing.md](applications/code_signing.md) | WIP |
| 8.3 | CUPS (Журнал печати) | [applications/cups.md](applications/cups.md) | WIP |

## Cloud & Sync

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 9.1 | Time Machine | [cloud_sync/time_machine.md](cloud_sync/time_machine.md) | WIP |
| 9.2 | iCloud Drive | [cloud_sync/icloud.md](cloud_sync/icloud.md) | WIP |
| 9.3 | Dropbox / Google Drive / OneDrive | [cloud_sync/third_party_clouds.md](cloud_sync/third_party_clouds.md) | WIP |

## Security State

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 10.1 | System Integrity Protection (SIP) | [security_state/sip.md](security_state/sip.md) | WIP |
| 10.2 | Gatekeeper и XProtect | [security_state/gatekeeper_xprotect.md](security_state/gatekeeper_xprotect.md) | WIP |
| 10.3 | FileVault статус | [security_state/filevault.md](security_state/filevault.md) | WIP |
| 10.4 | Secure Boot / T2 / Apple Silicon | [security_state/secure_boot.md](security_state/secure_boot.md) | WIP |

## Memory & Volatile

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 11.1 | RAM-дамп | [memory/ram_dump.md](memory/ram_dump.md) | WIP |
| 11.2 | Открытые файловые дескрипторы | [memory/file_descriptors.md](memory/file_descriptors.md) | WIP |
| 11.3 | Переменные окружения | [memory/env_vars.md](memory/env_vars.md) | WIP |

## External Devices

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 12.1 | USB и внешние тома | [external_devices/usb.md](external_devices/usb.md) | WIP |
| 12.2 | Bluetooth | [external_devices/bluetooth.md](external_devices/bluetooth.md) | WIP |

## Email & Communication

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 13.1 | Apple Mail | [communication/apple_mail.md](communication/apple_mail.md) | WIP |
| 13.2 | Messages (iMessage / SMS) | [communication/messages.md](communication/messages.md) | WIP |
