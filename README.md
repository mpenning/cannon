# Introduction

cannon is a wrapper around [exscript](https://pypi.python.org/pypi/exscript) to connect with remote server or network 
devices with ssh.


## Example Usage - Cisco IOS

This script will login, run a few show commands

```python
from cannon import Shell, Account

sess = Shell(
    host='route-views.routeviews.org',
    # route-views doesn't need password
    account= Account(name='rviews', password=''),
    debug=0,
    )

sess.execute('term len 0')

# relax_prompt reduces prompt matching to a minimum... relax_prompt is
#     useful if the prompt may change while running a series of commands.
sess.execute('show clock')

sess.execute('show version')
version_text = sess.response

# template is a TextFSM template
values = sess.execute('show ip int brief',
    template="""Value INTF (\S+)\nValue IPADDR (\S+)\nValue STATUS (up|down|administratively down)\nValue PROTO (up|down)\n\nStart\n  ^${INTF}\s+${IPADDR}\s+\w+\s+\w+\s+${STATUS}\s+${PROTO} -> Record""")
print("VALUES "+str(values))
sess.close()
```

## Example Usage - Linux

```python
from getpass import getpass

from cannon.main import Shell, Account

account = Account("mpenning", getpass("Login password: "))
conn = Shell(host="127.0.0.1", port=22, account=account, driver="generic", debug=0)
assert conn is not None
example_tfsm_template = """Value UNAME_LINE (.+)

Start
  ^${UNAME_LINE}
"""
print(conn.execute("sudo uname -a", debug=0, template=example_tfsm_template, timeout=2))
print(conn.execute("whoami", debug=0, template=None, timeout=2))
#print("FOO2", conn.response)
conn.close(force=True)
```

## Example test suite setup

- `git clone git@github.com:knipknap/Exscript`
- `cd` into `Exscript/tests/Exscript/protocols` and `chmod 600 id_rsa`
- exscript spawns a local tests ssh daemon, `pytest Exscript/tests/Exscript/protocols/SSH2Test.py`
- Connect with `ssh -i id_rsa -p 1236 user@localhost`
- one command is supported: `ls`


.. _exscript: https://pypi.python.org/pypi/exscript
