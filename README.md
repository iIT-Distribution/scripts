 # iIT Distribution Scripts

Колекція корисних скриптів для системного адміністрування та DevOps завдань.

## 🛡️ CrowdStrike Falcon

### 🚀 Швидке розгортання Falcon Sensor в Kubernetes

```bash
curl -sSL https://raw.githubusercontent.com/iIT-Distribution/scripts/refs/heads/master/crowdstrike/cloud/deploy-sensors.sh | bash
```

**Що це робить:**
- Автоматично підготовлює розгортання CrowdStrike Falcon sensor через Helm
- Завантажує образи з CrowdStrike registry в ваш локальний registry
- Генерує правильні конфігураційні файли та команди
- Повністю відповідає офіційній документації CrowdStrike

📚 **Детальна документація:** [crowdstrike/cloud/README.md](crowdstrike/cloud/README.md)

### 🔍 Інші CrowdStrike утиліти

- **`crowdstrike/check-usermode.sh`** - Перевірка usermode sensor статусу

## 📋 Вимоги

- **Linux/macOS** з bash
- **Python 3.8+** з pip
- **curl** для завантаження скриптів
- **Docker** (для CrowdStrike утиліт)
- **kubectl** і **helm** (для Kubernetes розгортання)

## 🔧 Використання

### Одноразове виконання
```bash
curl -sSL https://raw.githubusercontent.com/iIT-Distribution/scripts/refs/heads/master/path/to/script.sh | bash
```

### Локальне клонування
```bash
git clone https://github.com/iIT-Distribution/scripts.git
cd scripts
# Виконати потрібний скрипт
```

## 📁 Структура репозиторію

```
scripts/
├── crowdstrike/           # CrowdStrike Falcon утиліти
│   ├── cloud/            # Kubernetes/Cloud розгортання
│   │   ├── deploy-sensors.sh
│   │   ├── sensor-helm-install.py
│   │   └── README.md
│   └── check-usermode.sh # Перевірка usermode sensor
├── docs_orig/            # Оригінальна документація  
├── requirements.txt      # Python залежності
├── LICENSE              # MIT ліцензія
└── README.md            # Цей файл
```

## 🤝 Внесок

Якщо ви хочете внести зміни:

1. Форкніть репозиторій
2. Створіть feature branch
3. Зробіть ваші зміни
4. Відправте pull request

## 📄 Ліцензія

MIT License - дивіться [LICENSE](LICENSE) файл для деталей.

## ⚠️ Важливо

- Всі скрипти призначені для використання досвідченими системними адміністраторами
- Завжди перевіряйте скрипти перед виконанням у продакшн середовищі
- Використовуйте на власний ризик

---

**iIT Distribution Team** | 2024