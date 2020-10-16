from requests import Session

from sspvo.client import RequestsClient
from sspvo.message import CLSMessage, CLS


def main():

    sess = Session()
    sspvo_client = RequestsClient(sess, ogrn="test", kpp="test", api_url="http://85.142.162.12:8031/api")
    message = CLSMessage(CLS.LevelBudget)
    response = sspvo_client.send(message)
    answer = response.data()
    print(answer.decode())


if __name__ == '__main__':
    main()

# Output:
# <?xml version="1.0" encoding="UTF-8"?>
# <LevelBudget>
# <Budget><ID>1</ID><Code></Code><Name>Федеральный</Name><Actual>true</Actual></Budget>
# <Budget><ID>2</ID><Code></Code><Name>Региональный</Name><Actual>true</Actual></Budget>
# <Budget><ID>3</ID><Code></Code><Name>Муниципальный</Name><Actual>true</Actual></Budget>
# </LevelBudget>
