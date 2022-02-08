from getpass import getuser, getpass

from loguru import logger
from cannon.main import account_factory
from cannon import Shell, Account

@logger.catch(default=True)
def main():
    print("Logging into 172.16.1.3")
    acct = account_factory()
    conn = Shell(host='172.16.1.3', account=acct, inventory="", debug=0)
    conn.execute('term len 0')
    conn.execute('show version')
    print("OUTPUT", conn.response)

    conn.execute('show runn', timeout=2)
    config = conn.response

main()
