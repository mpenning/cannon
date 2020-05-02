from getpass import getpass, getuser
import re

from cannon import Account, Shell

"""Test for auth fallback, public-key authorization and linux sudo"""

print("Test logging into linux with ssh...")
# Test password fallback and ssh_key authorization...
acct01 = Account('mpenning', 'badPassword')
acct02 = Account(getuser(), getpass(), ssh_key='~/.ssh/id_rsa')

conn = Shell('localhost', credentials=(acct01, acct02), auto_priv_mode=False,
    debug=True, log_screen=True)
conn.execute('ls')
for file in re.split('\s+', conn.response):
    print("FILE "+file)
conn.execute('sudo uname -a')
print("SUDO1 ")
conn.execute('sudo ls /tmp')
print("SUDO2 ")
conn.execute('sudo su -', command_timeout=1)
conn.detect_prompt()
conn.execute('whoami')
conn.execute('exit')
try:
    conn.execute('exit')
except:
    pass
