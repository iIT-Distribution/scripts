# CrowdStrike Falcon Sensor Helm Installation Script

Інтерактивний помічник для підготовки розгортання CrowdStrike Falcon sensor через Helm в Kubernetes кластері.

## Швидкий старт (одна команда)

```bash
bash <(curl -sSL https://raw.githubusercontent.com/iIT-Distribution/scripts/refs/heads/master/crowdstrike/cloud/deploy-sensors.sh)
```

Ця команда:
- Автоматично завантажує найновішу версію скрипта в `/tmp/iitd-csf/`
- Встановлює всі необхідні Python залежності
- Запускає інтерактивний майстер налаштування
- Всі тимчасові файли зберігаються в `/tmp/iitd-csf/`

## Особливості

✅ **Відповідає офіційній документації CrowdStrike**
- Автоматично додає CrowdStrike Helm репозиторій
- Автоматично завантажує образ з CrowdStrike registry в локальний реєстр
- Генерує правильну структуру values.yaml
- Створює команди для налаштування namespace з pod security labels

✅ **Автоматизація образів**
- Автоматично отримує OAuth токен від CrowdStrike API
- Завантажує останню версію Falcon sensor образу
- Перетаговує і завантажує в ваш локальний registry
- Генерує pull secrets для Kubernetes

✅ **Перевірки передумов**
- Python ≥3.8, Helm ≥3.0, kubectl ≥1.20, Docker
- Доступ до Kubernetes кластера
- Автоматична перевірка версій
- Мережевий доступ до CrowdStrike сервісів (обраний регіон)

✅ **Безпека та зручність**
- Не виконує актуальне розгортання автоматично
- Генерує команди для перегляду та затвердження
- Підтримує environment variables для автоматизації
- Зберігає конфігурацію в `/tmp/iitd-csf/` для відновлення при помилках
- Автоматично очищає збережені дані після успішного завершення

## Передумови

1. **Встановлені інструменти:**
   ```bash
   python3 --version  # ≥3.8
   helm version       # ≥3.0
   kubectl version    # ≥1.20
   docker --version   # будь-яка версія
   curl              # для завантаження скрипта
   ```

2. **API credentials від CrowdStrike:**
   - Client ID і Secret з scopes: `Falcon Images Download (read)`, `Sensor Download (read)`
   - CID з checksum з Falcon console

3. **Локальний Docker registry:**
   - Налаштований і доступний (наприклад, Harbor, localhost:5000, etc.)
   - Docker повинен мати доступ для push

4. **Доступ до Kubernetes кластера:**
   ```bash
   kubectl get nodes  # повинно працювати
   ```

## Варіанти використання

### 1. Швидкий старт (рекомендований):
```bash
bash <(curl -sSL https://raw.githubusercontent.com/iIT-Distribution/scripts/refs/heads/master/crowdstrike/cloud/deploy-sensors.sh)
```

### 2. З environment variables:
```bash
export FALCON_CID="YOUR_CID_WITH_CHECKSUM"
export FALCON_CLIENT_ID="your_client_id" 
export FALCON_CLIENT_SECRET="your_client_secret"
export LOCAL_REGISTRY="harbor.company.com"
export FALCON_IMAGE_TAG="latest"

bash <(curl -sSL https://raw.githubusercontent.com/iIT-Distribution/scripts/refs/heads/master/crowdstrike/cloud/deploy-sensors.sh)
```

### 3. Локальне використання (для розробки):
```bash
# Клонувати репозиторій
git clone https://github.com/iIT-Distribution/scripts.git
cd scripts/crowdstrike/cloud

# Запустити безпосередньо
python3 sensor-helm-install.py

# Або через wrapper
./deploy-sensors.sh
```

## Що робить скрипт

1. **Перевіряє системні вимоги** та доступ до кластера
2. **Додає CrowdStrike Helm репозиторій**
3. **Перевіряє збережену конфігурацію** з попередніх запусків
4. **Збирає конфігурацію** через інтерактивні промпти (або використовує збережену)
5. **Перевіряє мережевий доступ** для обраного регіону (критично!)
6. **Автоматично завантажує образ:**
   - Отримує OAuth токен з CrowdStrike API
   - Логінується в CrowdStrike registry
   - Завантажує останню версію Falcon sensor
   - Перетаговує і завантажує в ваш локальний registry
7. **Генерує values.yaml** файл з правильною структурою
8. **Видає команди для розгортання:**
   - Створення namespace з pod security labels
   - Helm install команда з усіма необхідними параметрами
9. **Очищає тимчасові файли** після успішного завершення

## Приклад виводу

Скрипт генерує команди відповідно до документації:

```bash
# Step 1: Create namespace and set pod security labels
kubectl create namespace falcon-system
kubectl label ns --overwrite falcon-system pod-security.kubernetes.io/enforce=privileged
kubectl label ns --overwrite falcon-system pod-security.kubernetes.io/audit=privileged
kubectl label ns --overwrite falcon-system pod-security.kubernetes.io/warn=privileged

# Step 2: Deploy the Falcon sensor  
helm install falcon-sensor crowdstrike/falcon-sensor -n falcon-system --create-namespace -f /tmp/iitd-csf/falcon-values.yml
```

## Структура згенерованого values.yaml

```yaml
falcon:
  cid: "YOUR_CID_WITH_CHECKSUM"
node:
  enabled: true
  image:
    repository: "harbor.company.com/falcon-sensor"
    tag: "7.14.0-15300-1.falcon-linux.Release.EU-1"
    pullPolicy: "Always"
    registryConfigJSON: "YOUR_BASE64_DOCKER_CONFIG"
  backend: "bpf"  # або "kernel"
```

## Файли в `/tmp/iitd-csf/`

Всі тимчасові файли зберігаються в `/tmp/iitd-csf/`:
- **`sensor-helm-install.py`** - основний Python скрипт
- **`.falcon-venv/`** - Python virtual environment (якщо потрібно)
- **`falcon-sensor-config.json`** - збережена конфігурація
- **`falcon-values.yml`** - згенерований Helm values файл

## Підтримувані cloud регіони

- `us-1` - api.crowdstrike.com
- `us-2` - api.us-2.crowdstrike.com  
- `eu-1` - api.eu-1.crowdstrike.com
- `us-gov-1` - api.laggar.gcw.crowdstrike.com
- `us-gov-2` - api.us-gov-2.crowdstrike.mil

## Відповідність документації

Скрипт повністю відповідає офіційній документації CrowdStrike:
- ✅ Step 1: API client creation (manual)
- ✅ Step 2: CID retrieval (manual) 
- ✅ Step 3: Image retrieval (automated)
- ✅ Step 4: Helm chart repository setup (automated)
- ✅ Step 5: Sensor installation (command generation)

## Безпека

- Скрипт **НЕ** виконує розгортання автоматично
- Всі команди генеруються для перегляду та затвердження
- Підтримка clipboard для зручності
- Валідація вхідних даних
- OAuth токени використовуються тільки для завантаження образів
- Всі файли в `/tmp/iitd-csf/` автоматично очищаються системою

## Troubleshooting

### Помилка завантаження скрипта
```
curl: (6) Could not resolve host
```
Перевірте інтернет з'єднання та доступ до GitHub.

### Помилка аутентифікації
```
❌ Failed to get OAuth token
```
Перевірте правильність Client ID та Secret, та що у них є необхідні scopes.

### Помилка завантаження образу
```
❌ Failed to download image
```
Перевірте доступ до інтернету та що CrowdStrike registry доступний.

### Помилка завантаження в локальний registry
```
❌ Failed to push image to local registry
```
Перевірте що:
- Docker запущений
- Ви залогінені в локальний registry (`docker login`)
- Registry доступний і має права на push

### Мережеві проблеми
```
❌ Network connectivity issues detected for EU-1:
• ts01-lanner-lion.cloudsink.net: Connection timeout
• falcon.eu-1.crowdstrike.com: DNS resolution failed
Cannot proceed without access to CrowdStrike services.

❌ Network connectivity issues prevent proceeding.
```
**Скрипт автоматично завершується** при мережевих проблемах.

Перевірте що:
- Брандмауер дозволяє TLS трафік на порт 443
- Проксі правильно налаштований (якщо використовується)
- DNS резолвінг працює для CrowdStrike доменів
- Статичні IP адреси дозволені (якщо мережа обмежена)

**Необхідні домени по регіонах:**
- **US-1**: `*.crowdstrike.com`, `*.cloudsink.net`
- **US-2**: `*.us-2.crowdstrike.com`, `*-maverick.cloudsink.net`
- **EU-1**: `*.eu-1.crowdstrike.com`, `*-lion.cloudsink.net`
- **US-GOV-1**: `*.laggar.gcw.crowdstrike.com`, `*.us-gov-west-1.elb.amazonaws.com`
- **US-GOV-2**: `*.crowdstrike.mil`

## Збереження конфігурації

Скрипт автоматично зберігає конфігурацію в `/tmp/iitd-csf/falcon-sensor-config.json` після заповнення wizard. При наступному запуску:

1. **Автоматично знаходить збережену конфігурацію** і показує її деталі
2. **Пропонує використати збережені дані** замість повторного введення
3. **Просить повторно ввести client_secret** з міркувань безпеки
4. **Автоматично видаляє конфігурацію** після успішного завершення

### Приклад роботи зі збереженою конфігурацією:

```
╭─ Saved Configuration Found ─╮
│ CID: 1234567890ABCDEF...     │
│ Client ID: falcon-client-id  │
│ Cloud Region: eu-1           │
│ Local Registry: harbor.local │
│ Image Tag: latest            │
│ Namespace: falcon-system     │
│ Backend: bpf                 │
│ Note: Client secret will     │
│ need to be re-entered...     │
╰─────────────────────────────────╯

Use saved configuration? [Y/n]: y

Please re-enter sensitive information:
Falcon API client_secret: [hidden]
```

### Переваги:
- ✅ **Швидке відновлення** після помилок
- ✅ **Безпека** - sensitive дані не зберігаються
- ✅ **Зручність** - не потрібно пам'ятати всі параметри
- ✅ **Автоматичне очищення** після успішного завершення

## Структура проекту

```
crowdstrike/cloud/
├── deploy-sensors.sh          # Wrapper скрипт для curl використання
├── sensor-helm-install.py     # Основний Python скрипт
├── falcon-values.yml          # Приклад values файлу
└── README.md                  # Ця документація
```