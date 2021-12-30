from getpass import getpass, getuser
import time
import sys
import re

from traits.api import (
    Any,
    CStr,
    Str,
    Bool,
    Int,
    Undefined,
    ReadOnly,
    Disallow,
    PrefixList,
)
from traits.api import PrefixList, List, Range, Subclass
from traits.api import HasRequiredTraits
from traits.api import Constant

# Base class for server tests...
# - Exscript/tests/Exscript/protocols/ProtocolTest.py
#
# Test suite for the SSH2 client...
# - Exscript/tests/Exscript/protocols/SSH2Test.py
#
# Test suite for the Dummy client...
# - Exscript/tests/Exscript/protocols/DummyTest.py

from Exscript.protocols.exception import ExpectCancelledException
from Exscript.protocols.exception import InvalidCommandException
from Exscript.protocols.exception import TimeoutException  # <-- expect timeout
from Exscript.util.match import any_match
from Exscript import Account, PrivateKey
from Exscript.protocols import SSH2
import Exscript

from loguru import logger

HOST = ""
USERNAME = getuser()
# PASSWORD = getpass("Host='%s' password for %s: " % (HOST, USERNAME))
DEFAULT_LOGIN_TIMEOUT = 0
DEFAULT_PROMPT_LIST = []
DEFAULT_PROMPT_TIMEOUT = 30


def cast_unicode(line, encoding="utf-8"):
    assert (
        isinstance(line, int)
        or isinstance(line, bytes)
        or isinstance(line, str)
        or isinstance(line, float)
    )
    try:
        line = f"{line}"
    except:
        # line = str(bytes(line, encoding='utf-8'), encoding='utf-8')
        if isinstance(line, bytes):
            line = line.decode("utf-8")
        line = str(line, encoding="utf-8")
    return line


@logger.catch
class Shell(HasRequiredTraits):
    host = Str(required=True)
    username = Str(value=getuser(), required=False)
    password = Str(required=False)
    # FIXME - needs more drivers... -> https://exscript.readthedocs.io/en/latest/Exscript.protocols.drivers.html
    driver = PrefixList(
        value="generic", values=["generic", "shell", "junos", "ios"], required=False
    )
    termtype = PrefixList(
        value="dumb", values=["dumb", "xterm", "vt100"], required=False
    )
    stdout = PrefixList(value=None, values=[None, sys.stdout], required=False)
    stderr = PrefixList(value=sys.stderr, values=[None, sys.stderr], required=False)
    banner_timeout = Range(value=20, low=1, high=30, required=False)
    connect_timeout = Range(value=30, low=1, high=30, required=False)
    prompt_timeout = Range(value=10, low=1, high=65535, required=False)
    prompt_list = List(Str, required=False)
    default_prompt_list = List(re.Pattern, required=False)
    account_list = List(Exscript.account.Account, required=False)
    encoding = PrefixList(value="utf-8", values=["latin-1", "utf-8"], required=False)
    conn = Any(required=False)
    debug = Range(value=0, low=0, high=5, required=False)

    def __init__(self, **kwargs):
        HasRequiredTraits.__init__(self, **kwargs)

        assert len(self.account_list) == 0
        self.append_account()

        self.conn = SSH2(
            driver=self.driver,
            stdout=self.stdout,
            stderr=self.stderr,
            termtype=self.termtype,
            banner_timeout=self.banner_timeout,
            encoding=self.encoding,
            debug=self.debug,
        )
        self.conn.connect(self.host)
        self.conn.set_connect_timeout(self.connect_timeout)
        assert len(self.account_list) > 0
        self.conn.login(self.account_list[0], app_account=None, flush=True)  # <- FIXME this should use any acct
        self.default_prompt_list = self.conn.get_prompt()

        # Populate the initial prompt list...

    def __repr__(self):
        return """<Shell: %s>""" % self.host

    def append_account(self):
        # From the exscript docs...
        #     key = PrivateKey.from_file('~/.ssh/id_rsa', 'my_key_password')
        self.username = getuser()
        self.password = getpass("Password for %s: " % self.username)
        acct = Account(self.username, self.password)
        self.account_list.append(acct)

    def _extend_prompt(self, prompt_list=()):
        retval = list()
        for ii in prompt_list:
            if isinstance(ii, str):
                compiled = re.compile(ii)
                retval.append(compiled)

            elif isinstance(ii, re.Pattern):
                retval.append(ii)

            else:
                raise ValueError("Cannot process prompt:'%s'" % ii)

        for ii in self.conn.get_prompt():
            retval.append(ii)

        self.conn.set_prompt(retval)

    def interact(self):
        raise NotImplementedError
        print("Delegating processing to a human...")
        finished = False
        while not finished:
            cmd = input()
            self.execute(cmd.strip(), consume=False)
            time.sleep(0.1)
            print("HERE", self.response)
            time.sleep(0.1)

    def execute(self, cmd="", prompt_list=(), timeout=0, debug=0, consume=True):
        assert isinstance(cmd, str)
        if len(prompt_list) > 0:
            self._extend_prompt(prompt_list)

        self.conn.execute(cmd, consume=consume)

        # Reset the prompt list at the end of the command...
        if len(prompt_list) > 0:
            self.conn.set_prompt(self.default_prompt_list)

    def send(self, cmd="", prompt_list=(), timeout=0, debug=0):
        assert isinstance(cmd, str)
        self.conn.send(cmd)

    def expect(self, cmd="", prompt_list=(), timeout=0, debug=0):
        assert isinstance(cmd, str)
        self.conn.expect(cmd)

    def close(self, force=False, timeout=0, debug=0, consume=True):
        self.conn.close(force=force)

    @property
    def response(self):
        return self.conn.response

@logger.catch
def reset_conn_parameters(conn=None):
    assert isinstance(conn, SSH2)
    conn.set_connect_timeout(DEFAULT_LOGIN_TIMEOUT)
    conn.set_prompt(DEFAULT_PROMPT_LIST)
    conn.set_timeout(DEFAULT_PROMPT_TIMEOUT)


@logger.catch
def do_command(cmd=None, conn=None, prompt_list=(), prompt_timeout=30):
    assert isinstance(cmd, str)

    output = None
    match_prompt_idx = None

    if prompt_list == () or prompt_list == []:
        conn.set_prompt(DEFAULT_PROMPT_LIST)

    conn.set_timeout(prompt_timeout)
    try:
        prompt_idx, prompt_re_match = conn.execute(cmd)

    except TimeoutException as ee:
        error = "Host=%s timeout after %s seconds while %s waiting for %s" % (
            "FIXME",
            prompt_timeout,
            cmd,
        )
        raise TimeoutException(error)

    output = conn.response
    assert isinstance(output, str)

    reset_conn_parameters(conn=conn)

    # FIXME - add matching prompt index and regex here...
    return prompt_idx, prompt_re_match, output


@logger.catch
def do_login(
    username=None,
    password=None,
    proto="ssh",
    hostname="localhost",
    driver="generic",
    login_timeout=30,
    debug=False,
):
    assert isinstance(username, str)
    assert isinstance(debug, bool)

    global HOST
    global USERNAME
    global PASSWORD
    global DEFAULT_LOGIN_TIMEOUT
    global DEFAULT_PROMPT_LIST
    global DEFAULT_PROMPT_TIMEOUT

    # Set the global hostname var...
    HOST = hostname

    if password is None and PASSWORD == "":
        PASSWORD = getpass("Host='%s' password for %s: " % (hostname, username))
        password = PASSWORD

    elif isinstance(password, str):
        pass

    account = Account(USERNAME, PASSWORD)

    if proto == "ssh":
        conn = SSH2(driver=driver)

        DEFAULT_LOGIN_TIMEOUT = conn.get_connect_timeout()
        DEFAULT_PROMPT_LIST = conn.get_prompt()
        DEFAULT_PROMPT_TIMEOUT = conn.get_timeout()

        conn.set_connect_timeout(login_timeout)
        conn.connect("localhost")
        conn.login(account)

        # Send a blank line to ensure the connection is alive...
        prompt_idx, prompt_re_match, output = do_command(
            cmd="", conn=conn, prompt_timeout=2
        )
        assert isinstance(prompt_idx, int)
        assert isinstance(prompt_re_match, re.Match)
        response = conn.response
        assert isinstance(response, str)

        conn.set_connect_timeout(DEFAULT_LOGIN_TIMEOUT)

        return conn

    else:
        raise ValueError("FATAL: proto='%s' isn't a valid protocol" % proto)


@logger.catch
def main():

    conn = do_login(username="mpenning", hostname="localhost")
    prompt_idx, prompt_re_match, output = do_command("ls -la | wc -l", conn=conn)

    # conn.set_prompt([r"\]\#", r"\]\$"])
    conn.set_prompt([r"---", r"==="])
    conn.set_timeout(10)
    prompt_idx, prompt_re_match, uname_output = do_command(
        "uname -a", conn=conn, prompt_timeout=2
    )  # Execute the "uname -a" command

    # sudo example...
    conn.set_timeout(2)
    conn.send("sudo ls -la\r")
    ex_tuple = conn.expect([":"])  # You might need to customize this sudo passwd prompt
    print("EX_TUPLE re.Match", ex_tuple)
    conn.execute(PASSWORD)

    print("Interacting...")
    conn.interact(key_handlers={}, handle_window_size=False)

    # Parse conn.response for file name and permissions... build a dict with the results
    file_permission_dict = dict()
    for permission_str, filename in any_match(conn, r"^\s*(\S+)\s.+?\s+(\S+)$"):
        file_permission_dict[filename] = permission_str

    conn.send("exit\r")
    conn.close()

