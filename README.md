 # iIT Distribution Scripts

Колекція корисних скриптів для системного адміністрування та DevOps завдань.

## 🛡️ CrowdStrike Falcon

### 🚀 Швидке розгортання Falcon Sensor в Kubernetes

```bash
bash <(curl -sSL https://raw.githubusercontent.com/iIT-Distribution/scripts/refs/heads/master/crowdstrike/cloud/deploy-sensors.sh)
```

**Що це робить:**
- Автоматично підготовлює розгортання CrowdStrike Falcon sensor через Helm
- Завантажує образи з CrowdStrike registry в ваш локальний registry
- Генерує правильні конфігураційні файли та команди
- Повністю відповідає офіційній документації CrowdStrike

📚 **Детальна документація:** [crowdstrike/cloud/README.md](crowdstrike/cloud/README.md)

### 🔍 Інші CrowdStrike утиліти

- **`crowdstrike/check-usermode.sh`** - Перевірка usermode sensor статусу

## 📁 Структура репозиторію

```
scripts/
├── crowdstrike/           # CrowdStrike Falcon утиліти
│   ├── cloud/            # Kubernetes/Cloud розгортання
│   │   ├── deploy-sensors.sh
│   │   ├── sensor-helm-install.py
│   │   └── README.md
│   └── check-usermode.sh # Перевірка usermode
├── LICENSE              # Apache 2.0 ліцензія
└── README.md            # Цей файл
```

## 🤝 Внесок

Якщо ви хочете внести зміни:

1. Форкніть репозиторій
2. Створіть feature branch
3. Зробіть ваші зміни
4. Відправте pull request

## 📄 Ліцензія

Apache License 2.0 - дивіться [LICENSE](LICENSE) файл для деталей.

## ⚠️ Важливо

- Всі скрипти призначені для використання досвідченими системними адміністраторами
- Завжди перевіряйте скрипти перед виконанням у продакшн середовищі
- Використовуйте на власний ризик

---

**iIT Distribution** | 2025