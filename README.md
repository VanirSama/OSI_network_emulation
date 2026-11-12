# Симулятор сетевых взаимодействий L2+

| Уровень OSI | Реализованно                    |
|-------------|---------------------------------|
| L2          | Ethernet II, коммутация L2      |
| L2.5        | ARP                             |
| L3          | IPv4, статическая маршрутизация |
| L4          | UDP                             |

### Установка и настройка:
```bash
git clone https://github.com/VanirSama/OSI_network_emulation.git
cd OSI_network_emulation
python -m venv .venv
.venv/Scripts/Activate
pip install -r requirements.txt
```

### Запуск:
```bash
python main.py arp_spoofing
```
YAML-конфигурации тестов должны находиться в `fixtures/`. Формат названия конфигураций: `<имя_теста>_topology.yaml`, `<имя_теста>_scenario.yaml`
