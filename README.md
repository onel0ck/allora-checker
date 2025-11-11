# Allora Prime Airdrop Checker

## Установка

```bash
pip install -r requirements.txt
```

## Использование

1. Создай `seed.txt` - по одной seed фразе на строку
2. Создай `proxies.txt` - формат `protocol://user:pass@host:port`
3. Запусти:

```bash
python3 allora_checker.py
```

## Результаты

- `results.csv`: CSV файл со всеми данными

## Статусы

- `AIRDROP ELIGIBLE` - есть airdrop
- `BOOST ELIGIBLE` - есть boost (LOW/MED/HIGH: 24%/38%/50%)
- `NOT ELIGIBLE` - ничего нет
