# SSH конфигурация и история

<!-- Приоритет: 🔴🟡🟢 | ⚠️⏱️🔄🔐 -->

> **Статус:** WIP

## Что это
SSH-сервер — основной вектор для удалённого доступа на Linux-сервере. Конфигурация sshd определяет политику входа. `known_hosts` — история SSH-соединений хоста (lateral movement).

## Пути
```
/etc/ssh/sshd_config            ← конфигурация SSH-сервера
/etc/ssh/sshd_config.d/         ← дополнительные конфиги
/etc/ssh/ssh_config             ← клиентская конфигурация

# Ключи хоста
/etc/ssh/ssh_host_*_key         ← приватные ключи хоста

# Пользовательские
~/.ssh/authorized_keys          ← авторизованные ключи (см. 1.8)
~/.ssh/known_hosts              ← куда подключались (lateral movement)
~/.ssh/config                   ← SSH-клиент конфигурация
~/.ssh/id_*                     ← приватные ключи пользователя
```

## На какие вопросы отвечает
- К каким хостам подключалась система по SSH (lateral movement)?
- Нестандартные настройки sshd: PermitRootLogin, PasswordAuthentication, нестандартный порт?
- Есть ли BackdoorKeysFile или другие аномальные директивы в sshd_config?

## Парсинг
```bash
grep -Ev "^#|^$" /etc/ssh/sshd_config

# known_hosts для всех пользователей (lateral movement)
find /root /home -name "known_hosts" -exec cat {} \; 2>/dev/null

# Ключевые настройки
grep -Ei "PermitRootLogin|PasswordAuthentication|AuthorizedKeysFile|Port|ListenAddress" \
  /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null
```

SSH поддерживает шифрование систем в `known_hosts` посредством параметра `HashKnownHosts` в `ssh_config`.
Формат зашифрованных подключений:
```
|<magic>|<salt>|<hash> <key algorithm> <public key sig>
|1|b08QaZXugZ42Kx2lmu7krSkrbSA=|DK9KjVOSW3/9J+yfHk+cb6z6FMs= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJJk3a190w/1TZkzVKORvz/kwyKmFY144lVeDFm80p17
```
Можно попробовать восстановить исходящие подключения брутфорсом, перед этим рекомендуется изменить маску на таргетированную под кейс. Системы хэшируются в том виде, в каком были указаны при подключении к ним, помимо IPv4 адреса может быть IPv4 с нестандартным портом, IPv6 или доменное имя.

## Инструменты
- UAC
- [known_hosts-hashcat](https://github.com/chris408/known_hosts-hashcat) - брутфорс `known_hosts`