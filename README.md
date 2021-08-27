# ceph-buckets Amazon S3-compatible storage manager

#### Здесь и далее:

- `ceph-buckets`
    : бинарный файл для создания и обновления бакетов в Amazon S3-compatible хранилище Ceph;
- `ceph_config.yml`
    : конфигурационный файл, содержащий данные о бакетах и их конфигурации (см.пример [ceph_config_example.yml](./ceph_config_example.yml));
- `ceph_credentials.yml`
    : файл, содержащий данные, необходимые для подключения к хранилищу Ceph. (см.пример [ceph_credentials_example.yml](./ceph_credentials_example.yml))
- `app_buckets_config.txt`
    : файл, содержащий список бакетов, необходимых для работы приложения (см.пример [app_buckets_config_example.txt](./app_buckets_config_example.txt))

## Поддерживаемые операции:

- Создание/изменение бакета Amazon S3 <sup id="a1">[1](#f1)</sup>:
    - Создание/изменение прав доступа (**ACL** [(ссылка на документацию)](https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html#permissions)). Поддерживаемые типы <sup id="a2">[2](#f2)</sup>:
        - "FULL_CONTROL"
        - "READ"
        - "WRITE"
    - Создание/изменение параметров жизненного цикла файлов (**Lifecycle Configuration** [(ссылка на документацию)](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lifecycle-mgmt.html)). Поддеживаемый тип <sup id="a3">[3](#f3)</sup>:
        - "Expiration actions"

- Создание/изменение конфигурационного файла для последующего применения на Amazon s3 хранилище.



## Сборка:

1. Установите пакет golang и его зависимости:

    ```
    # RHEL / CentOS / Fedora
    yum install -y golang

    # Debian / Ubuntu
    apt install -y golang
    ```

2. Войдите в папку GIT-проекта и запустите команду 

    ```
    make
    ```

## Использование:

#### Поддерживаемые параметры:

| тип | параметр | описание |
| - | - | - |
| флаг | `--help` | Вывести помощь по использованию утилиты |
| флаг | `--help-long` | Вывести расширенную помощь по использованию утилиты, команд, их параметров и значения по умолчанию |
| флаг | `--debug` | Включить режим отладки |
| флаг | `--version` | Вывести информацию о версии и сборке |
| команда | `help [<command>]` | Вывести контекстную помощь по указанной команде |
| команда | `app [<flags>]` | Создать/обновить `ceph_config.yml` на основе списка бакетов приложения (`app_buckets_config.txt`) |
| команда |  `create [<flags>]` | Создать/обновить `ceph_config.yml` на основе данных с сервера |
| команда |  `create [<flags>]` | Создать/обновить бакеты на сервере, на основе данных из `ceph_config.yml` |

##### На примере флага `--help-long` и команды `help app`:

```
# ceph-buckets --help-long
usage: ceph-buckets [<flags>] <command> [<args> ...]

A command-line application for manage Cephconfiguration of Amazon S3-compatible storage based on Ceph.

Flags:
  --help     Show context-sensitive help (also try --help-long and --help-man).
  --debug    Enable debug mode.
  --version  Show application version.

Commands:
  help [<command>...]
    Show help.

  app [<flags>]
    Create/Update Ceph configuration YAML-file from application's TXT-file.

    --app-config="./app_buckets_config.txt"  
      Application's TXT-file, contains buckets list.
    --ceph-config="./ceph_config.yml"  
      Ceph configuration YAML-file.

  create [<flags>]
    Create/Update Ceph configuration YAML-file from server.

    --ceph-config="./ceph_config.yml"  
      Ceph configuration YAML-file.
    --credentials="./ceph_credentials.yml"  
      Ceph credentials YAML-file.

  config [<flags>]
    Create/Update Ceph configuration on server from YAML-file.

    --ceph-config="./ceph-config.yml"  
      Ceph configuration YAML-file.
    --credentials="./ceph_credentials.yml"  
      Ceph credentials YAML-file.


# ceph-buckets help app
usage: ceph-buckets app [<flags>]

Create/Update Ceph configuration YAML-file from application's TXT-file.

Flags:
  --help     Show context-sensitive help (also try --help-long and --help-man).
  --debug    Enable debug mode.
  --version  Show application version.
  --app-config="./app_buckets_config.txt"  
             Application's TXT-file, contains buckets list.
  --ceph-config="./ceph_config.yml"  
             Ceph configuration YAML-file.
```

#### Перед использованием:
Заполните файл `ceph_credentials.yaml`, указав следующее:
* `endpoint_url:` IP/FQDN и порт хоста Ceph, например `endpoint_url: "127.0.0.1:8080"`
* `access_key:` Ключ пользователя, под которым будет выполняться подключение, например `access_key: "445S7Y2GPP3R2PVPXH62"`
* `secret_key:` Секретная часть ключа пользователя, под которым будет выполняться подключение, например `secret_key: "CCqdBtWKVT6zX6PvMX3UPOGnhEHwU3Gt7jJA1Z89"`
* `disable_ssl:` Требуется ли отключить SSL (т.е. использовать HTTP протокол, вместо HTTPS), например `disable_ssl: True`

Полный пример конфигурации можно посмотреть в файле [ceph_credentials_example.yml](./ceph_credentials_example.yml)

#### Создание/обновление конфигурационного файла из данных с сервера Ceph:

```
ceph-buckets create --ceph-config ./ceph_config.yml --credentials ./ceph_credentials.yml
```

#### Создание/обновление конфигурационного файла из списка бакетов приложения:

```
ceph-buckets app --app-config ./app_buckets_config.txt --ceph-config ./ceph_config.yml
```

#### Создание/обновление бакетов на сервере Ceph из данных из конфигурационного файла:

```
ceph-buckets config --ceph-config ./ceph_config.yml --credentials ./ceph_credentials.yml
```




----
### Примечания:
<a id="f1">1</a>: Поддерживаются только операции создания и изменения бакетов. Удаление бакетов не поддерживается из соображений безопасности. [↩](#a1)

<a id="f2">2</a>: Типы "READ_ACP" и "WRITE_ACP" не поддерживаются из соображений упрощения конечного конфигурационного файла. [↩](#a2)

<a id="f3">3</a>: Тип "Transition actions" не поддерживается по причине отсутствия дополнительных Storage Class'ов в Ceph. [↩](#a3)