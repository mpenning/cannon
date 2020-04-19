from getpass import getuser, getpass
from cannon import Shell, Account

print("Logging into 172.16.1.3")
acct = Account(getuser(), getpass())
conn = Shell('172.16.1.3', credentials=(acct,), log_screen=True, debug=False)
conn.execute('term len 0')
conn.execute('show running')
config = conn.response
print(config.splitlines())

