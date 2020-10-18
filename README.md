## Назначение
Модуль предназначен для подготовки сообщений с дальнейшей отправкой в сервис. Подготовка включает в себя добавление основных полей, таких как *ОГРН* *КПП*, формирования подписанного токена для отправки данных, валидация приходящего токена. Подпись и валидация проводится согласно требованиям сервиса, а именно использования инфраструктуры открытого ключа ГОСТ. Версия Python 3.8  

## Установка
```bash
pip install "https://github.com/ftomza/py-sspvo"
```

## Использование
Пример получения справочника уровней бюджета:
```python
sess = requests.Session()  
sspvo_client = sspvo.client.RequestsClient(sess, ogrn="test", kpp="test", api_url="http://85.142.162.12:8031/api")  
message = sspvo.message.CLSMessage(sspvo.message.CLS.LevelBudget)  
response = sspvo_client.send(message)  
answer = response.data()  
print(answer.decode())

# Output:
#  
# <?xml version="1.0" encoding="UTF-8"?>  
# <LevelBudget>  
# <Budget><ID>1</ID><Code></Code><Name>Федеральный</Name><Actual>true</Actual></Budget>  
# <Budget><ID>2</ID><Code></Code><Name>Региональный</Name><Actual>true</Actual></Budget>  
# <Budget><ID>3</ID><Code></Code><Name>Муниципальный</Name><Actual>true</Actual></Budget>  
# </LevelBudget>
```

Пример получения количества токенов ожидающий получения и подтверждения.
```python
sess = requests.Session()  
sspvo_client = sspvo.client.RequestsClient(sess, ogrn="test", kpp="test", api_url="http://85.142.162.12:8031/api")  
message = sspvo.message.InfoAllMessage()  
response = sspvo_client.send(message)  
answer = response.data()  
print(answer.decode())

# Output:
#  
# {"Messages": 2}
```
Пример отправки данных, получения информации и ее подтверждения.
```python
key = """  
-----BEGIN PRIVATE KEY-----  
...
-----END PRIVATE KEY-----  
"""  
cert = """  
-----BEGIN CERTIFICATE-----  
...
-----END CERTIFICATE-----  
"""   
 
sess = requests.Session()  
sspvo_client = sspvo.client.RequestsClient(sess, ogrn="test", kpp="test", api_url="http://85.142.162.12:8031/api")  

crypto = sspvo.crypto.GOSTCrypto(cert=cert, key=key)  

data = """  
<?xml version="1.0" encoding="utf-8"?>  
<PackageData>  
 <SubdivisionOrg> 
  <UID>TEST69</UID> 
  <Name>Подвал</Name> 
 </SubdivisionOrg>
</PackageData>  
""".encode()  
  
message = sspvo.message.ActionMessage(crypto, action=Actions.Add, data_type=DataTypes.subdivision_org, data=data)
response = sspvo_client.send(message)  
try:  
    answer = response.data()  
except sspvo.response.BadResponse as e:  
    print("Error:", e.body)  
    return  
print(answer.decode())  

sleep(10)  
  
idjwt = int(json.loads(answer)[Fields.idjwt.value])  
  
message = sspvo.message.InfoMessage(crypto, idjwt=idjwt)  
response = sspvo_client.send(message)  
try:  
    answer = response.data()  
except sspvo.response.BadResponse as e:  
    print("Error:", e.body)  
    return  
print(answer.decode()) 
  
message = sspvo.message.ConfirmMessage(crypto, idjwt=idjwt)  
response = sspvo_client.send(message)  
try:  
    answer = response.data()  
except sspvo.response.BadResponse as e:  
    print("Error:", e.body)  
    return  
print(answer.decode())   

# Output:
#
# {"IDJWT":"1405161"}
# {"ResponseToken":".."}
# {"IDJWT":"1405161","Result":"true"}
```

## Содержание
#### Крипто класс `GostCrypto` из файла `crypto.py`
Данный крипто класс поддерживает инфраструктуру открытых ключей ГОСТ Р 34.10-2001 и хэш функцию ГОСТ Р 34.11-2012 Стрибог (Streebog). 
Конструктор:
 - `GOSTCrypto(cert: str, key: Optional[str] = None)`. 
 
 Параметры:
 - `cert: str` - передать сертификат с открытым ключом в формате *PEM*
 - `key: Optional[str] = None` - необязательный, передать закрытый ключ в формате *PEM*

Если будет передан только сертификат, то крипто класс будет поддерживать только проверку подписи.

#### Классы Сообщений, файл `message.py`
Все сообщен возвращают данные в виде байтов.

##### Простые сообщения, `Message`

##### `CLSMessage`
Используется для получения справочников из сервиса, например, уровни бюджета, олимпиады, достижения и так далее. Результат выполнения будет XML ответ содержащий перечисление запрашиваемого справочника:
```XML
<?xml version="1.0" encoding="UTF-8"?>  
<LevelBudget>  
	<Budget><ID>1</ID><Code></Code><Name>Федеральный</Name><Actual>true</Actual></Budget>  
	<Budget><ID>2</ID><Code></Code><Name>Региональный</Name><Actual>true</Actual></Budget>  
	<Budget><ID>3</ID><Code></Code><Name>Муниципальный</Name><Actual>true</Actual></Budget>  
</LevelBudget>
```
Конструктор:
- `CLSMessage(cls: "CLS")`.

Параметры:
- `cls: "CLS"` - принимает значение допустимого *класса* справочника, допустимые *классы* содержатся в перечислении `CLS`  

##### `InfoAllMessage`
Простое сообщение для получения количества токенов ожидающих обработку(получения информации по ним и подтверждения полученной информации). Результатом выполнения будет JSON ответ содержащий количество токенов:
```json
{"Messages": 2}
``` 
Конструктор:
- `InfoAllMessage()`.

##### Крипто сообщения, `MessageSign`
Сообщение с поддержкой подписи отправляемых сообщений и проверкой подписи входящего сообщения.
##### `ActionMessage`
Используется для отправки данных в сервис, например, создание конкурсной группы, направлений и так далее. Результатом выполнения будет JSON ответ содержащий номер токена:
```json
{"IDJWT":"1405161"}
```
Конструктор:
- `ActionMessage(crypto: AbstractCrypto, action: "Actions", data_type: "DataTypes", data: Optional[bytes] = None)`.

Параметры:
- `crypto: AbstractCrypto` - принимает значение крипто класса.
- `action: "Actions"` - принимает значение допустимого *действия* сервиса, допустимые *действия* перечислены в `Actions`.
- `data_type: "DataTypes"` - принимает значение допустимого *типа данных* сервиса, допустимые *типы данных* перечислены в `DataTypes`
- `data: Optional[bytes] = None` - необязательный, принимает байты для передачи в сообщении полезной нагрузки *Payload*.
 
##### `ConfirmMessage`
Используется для отправки подтверждения полученной информации по номеру токена. Результатом выполнения будет JSON ответ содержащий результат подтверждения:
```json
{"IDJWT":"1405161","Result":"true"}
```
Конструктор:
- `ConfirmMessage(crypto: AbstractCrypto, idjwt: int)`.

Параметры:
- `crypto: AbstractCrypto` - принимает значение крипто класса.
- `idjwt: int` - принимает значение идентификатора токена.

##### `InfoMessage`
Используется для получения информации по номеру токена. Результатом выполнения будет JSON ответ содержащий токен:
```json
{"ResponseToken": "[headers in base64].[payload in base64].[sign in base64]"}
```
Конструктор:
- `InfoMessage(crypto: AbstractCrypto, idjwt: int)`.

Параметры:
- `crypto: AbstractCrypto` - принимает значение крипто класса.
- `idjwt: int` - принимает значение идентификатора токена.

Если в качестве параметра идентификатора токена передать `0`, то будет возвращен первый ожидающий обработки токен.

#### Класс клиента отправки сообщений, файл `client.py`
В данном решении для отправки данных сообщения используется http библиотека  `requests`.
Конструктор:
- `RequestsClient(session: Session, *, ogrn: str, kpp: str, api_url: str)` 

Параметры:
- `session: Session` - принимает новую сессию 
- `api_url: str` - задать URL c базовым путем сервиса
- `ogrn: str` - задать ОГРН для аутентификации на сервисе
- `kpp: str` - задать КПП для аутентификации на сервисе
