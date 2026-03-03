# Linux DFIR — Индекс артефактов

Ubuntu / Debian / RHEL / CentOS / AlmaLinux

> Монолитный справочник: [linux.md](linux.md) | Версия 1.1, 2026-02

---

## Persistence

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 1.1 | Systemd Units | [persistence/systemd_units.md](persistence/systemd_units.md) | WIP |
| 1.2 | SysVInit / rc.d Scripts | [persistence/sysvinit.md](persistence/sysvinit.md) | WIP |
| 1.3 | Cron и Anacron | [persistence/cron.md](persistence/cron.md) | WIP |
| 1.4 | At Jobs | [persistence/at_jobs.md](persistence/at_jobs.md) | WIP |
| 1.5 | Shell Profile и Bashrc Hooks | [persistence/shell_hooks.md](persistence/shell_hooks.md) | WIP |
| 1.6 | LD_PRELOAD и /etc/ld.so.preload | [persistence/ld_preload.md](persistence/ld_preload.md) | WIP |
| 1.7 | PAM Modules | [persistence/pam_modules.md](persistence/pam_modules.md) | WIP |
| 1.8 | SSH Authorized Keys | [persistence/ssh_authorized_keys.md](persistence/ssh_authorized_keys.md) | WIP |
| 1.9 | MOTD и Update-MOTD | [persistence/motd.md](persistence/motd.md) | WIP |
| 1.10 | Глобальные переменные окружения | [persistence/env_global.md](persistence/env_global.md) | WIP |

## Process

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 2.1 | /proc — Псевдофайловая система | [process/proc_fs.md](process/proc_fs.md) | WIP |
| 2.2 | Список живых процессов | [process/process_list.md](process/process_list.md) | WIP |
| 2.3 | Хэши исполняемых файлов | [process/binary_hashes.md](process/binary_hashes.md) | WIP |
| 2.4 | Открытые файловые дескрипторы | [process/file_descriptors.md](process/file_descriptors.md) | WIP |

## Network

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 3.1 | Активные соединения | [network/active_connections.md](network/active_connections.md) | WIP |
| 3.2 | ARP-кэш и соседи | [network/arp_cache.md](network/arp_cache.md) | WIP |
| 3.3 | Таблица маршрутизации | [network/routing_table.md](network/routing_table.md) | WIP |
| 3.4 | Unix Domain Sockets | [network/unix_sockets.md](network/unix_sockets.md) | WIP |
| 3.5 | DNS-кэш | [network/dns_cache.md](network/dns_cache.md) | WIP |
| 3.6 | Конфигурация сети и /etc/hosts | [network/network_config.md](network/network_config.md) | WIP |
| 3.7 | Netfilter / iptables / nftables | [network/netfilter.md](network/netfilter.md) | WIP |

## File System

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 4.1 | Метки времени (MACB) | [filesystem/macb_timestamps.md](filesystem/macb_timestamps.md) | WIP |
| 4.2 | Bodyfile | [filesystem/bodyfile.md](filesystem/bodyfile.md) | WIP |
| 4.3 | Временные и Volatile директории | [filesystem/temp_dirs.md](filesystem/temp_dirs.md) | WIP |
| 4.4 | SUID/SGID Файлы | [filesystem/suid_sgid.md](filesystem/suid_sgid.md) | WIP |
| 4.5 | Linux Capabilities | [filesystem/capabilities.md](filesystem/capabilities.md) | WIP |
| 4.6 | Скрытые файлы и директории | [filesystem/hidden_files.md](filesystem/hidden_files.md) | WIP |
| 4.7 | World-Writable Files | [filesystem/world_writable.md](filesystem/world_writable.md) | WIP |

## User Activity

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 5.1 | Shell History | [user_activity/shell_history.md](user_activity/shell_history.md) | WIP |
| 5.2 | Недавно изменённые файлы | [user_activity/recent_files.md](user_activity/recent_files.md) | WIP |

## System Logs

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 6.1 | Логи аутентификации | [logs/auth_logs.md](logs/auth_logs.md) | WIP |
| 6.2 | Systemd Journal (journald) | [logs/journald.md](logs/journald.md) | WIP |
| 6.3 | Syslog | [logs/syslog.md](logs/syslog.md) | WIP |
| 6.4 | Лог ядра (dmesg) | [logs/kernel_logs.md](logs/kernel_logs.md) | WIP |
| 6.5 | Логи аудита (auditd) | [logs/auditd.md](logs/auditd.md) | WIP |
| 6.6 | Логи пакетных менеджеров | [logs/package_manager_logs.md](logs/package_manager_logs.md) | WIP |
| 6.7 | Лог Cron | [logs/cron_logs.md](logs/cron_logs.md) | WIP |
| 6.8 | Лог загрузчика | [logs/boot_logs.md](logs/boot_logs.md) | WIP |
| 6.9 | Process Accounting (pacct) | [logs/process_accounting.md](logs/process_accounting.md) | WIP |

## Authentication

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 7.1 | /etc/passwd и /etc/shadow | [authentication/passwd_shadow.md](authentication/passwd_shadow.md) | WIP |
| 7.2 | /etc/sudoers и sudo-конфигурация | [authentication/sudoers.md](authentication/sudoers.md) | WIP |
| 7.3 | SSH конфигурация и история | [authentication/ssh_config.md](authentication/ssh_config.md) | WIP |
| 7.4 | Sudo Log | [authentication/sudo_logs.md](authentication/sudo_logs.md) | WIP |
| 7.5 | Пользователи и группы | [authentication/users_groups.md](authentication/users_groups.md) | WIP |

## Applications

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 8.1 | Пакетные менеджеры | [applications/package_managers.md](applications/package_managers.md) | WIP |
| 8.2 | Веб-серверы | [applications/web_servers.md](applications/web_servers.md) | WIP |
| 8.3 | Docker и контейнеры | [applications/docker.md](applications/docker.md) | WIP |

## Security State

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 9.1 | Модули ядра (Kernel Modules) | [security_state/kernel_modules.md](security_state/kernel_modules.md) | WIP |
| 9.2 | Rootkit Detection | [security_state/rootkit_detection.md](security_state/rootkit_detection.md) | WIP |
| 9.3 | AppArmor / SELinux | [security_state/apparmor_selinux.md](security_state/apparmor_selinux.md) | WIP |
| 9.4 | Сертификаты и CA | [security_state/certificates.md](security_state/certificates.md) | WIP |

## Memory & Volatile

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 10.1 | RAM-дамп | [memory/ram_dump.md](memory/ram_dump.md) | WIP |
| 10.2 | Crash Dumps | [memory/crash_dumps.md](memory/crash_dumps.md) | WIP |

## External Devices

| # | Артефакт | Файл | Статус |
|---|----------|------|--------|
| 11.1 | USB и внешние устройства | [external_devices/usb.md](external_devices/usb.md) | WIP |
| 11.2 | Примонтированные устройства | [external_devices/mounted_devices.md](external_devices/mounted_devices.md) | WIP |
