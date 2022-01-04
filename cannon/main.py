from getpass import getpass, getuser
from io import StringIO
import time
import copy
import sys
import re
import os

from traits.api import (
    Any,
    CStr,
    Str,
    Bool,
    Int,
    File,
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
from Exscript.util.log import log_to
from Exscript.protocols import SSH2
import Exscript

from textfsm import TextFSM

from loguru import logger

"""
Copyright 2022 - David Michael Pennington
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1.  Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.

2.  Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

3.  Neither the name of the copyright holder nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

"""
TODO:

1. Incorporate tests against the Cisco free router testbeds
described by bigevilbeard, below...

- https://github.com/bigevilbeard/Basic_NetMiko/README.md
  - https://devnetsandbox.cisco.com/RM/Diagram/Index/e83cfd31-ade3-4e15-91d6-3118b867a0dd?diagramType=Topology
  - https://devnetsandbox.cisco.com/RM/Diagram/Index/38ded1f0-16ce-43f2-8df5-43a40ebf752e?diagramType=Topology

2. Fix Exscript SSH with legacy ciphers and kexexchange algorithms -> https://github.com/knipknap/exscript/issues/215
"""

HOST = ""
USERNAME = getuser()
PASSWORD = ""
DEFAULT_LOGIN_TIMEOUT = 0
DEFAULT_PROMPT_LIST = []
DEFAULT_PROMPT_TIMEOUT = 30

@logger.catch(onerror=lambda _: sys.exit(1))
def account_factory(username="", password=None, private_key=""):
    assert username != ""

    if password is None:
        password = getpass("Login password for %s" % username)

    if isinstance(private_key, str) and private_key!="":
        private_key_path = os.path.expanduser(private_key)
        private_key_obj = PrivateKey(keytype='rsa').from_file(self.private_key_path)


@logger.catch(onerror=lambda _: sys.exit(1))
class Shell(HasRequiredTraits):
    host = Str(value="", required=True)
    port = Range(value=22, low=1, high=65524)
    username = Str(value=getuser(), required=False)
    password = Str(value='', required=False)
    private_key_path = File(value=os.path.expanduser("~/.ssh/id_rsa"))
    # FIXME - needs more drivers... -> https://exscript.readthedocs.io/en/latest/Exscript.protocols.drivers.html
    driver = PrefixList(
        value="generic", values=["generic", "shell", "junos", "ios"], required=False
    )
    termtype = PrefixList(
        value="dumb", values=["dumb", "xterm", "vt100"], required=False
    )
    protocol = PrefixList(value='ssh', values=['ssh'])
    stdout = PrefixList(value=None, values=[None, sys.stdout], required=False)
    stderr = PrefixList(value=sys.stderr, values=[None, sys.stderr], required=False)
    banner_timeout = Range(value=20, low=1, high=30, required=False)
    connect_timeout = Range(value=30, low=1, high=30, required=False)
    prompt_timeout = Range(value=10, low=1, high=65535, required=False)
    prompt_list = List(Str, required=False)
    default_prompt_list = List(re.Pattern, required=False)
    account = Any(value=None, required=True)
    account_list = List(Exscript.account.Account, required=False)
    encoding = PrefixList(value="utf-8", values=["latin-1", "utf-8"], required=False)
    conn = Any(required=False)
    debug = Range(value=0, low=0, high=5, required=False)

    def __init__(self, **kwargs):
        HasRequiredTraits.__init__(self, **kwargs)

        assert self.host != ""
        assert len(self.account_list) == 0
        if isinstance(self.account, Account):
            self.append_account(self.account)
        else:
            raise ValueError("Account must be included in the Shell() call")

        # Ensure this was NOT called with username
        if kwargs.get("username", False) is not False:
            raise ValueError("Shell() calls with username are not supported")

        # Ensure this was NOT called with password
        if kwargs.get("password", False) is not False:
            raise ValueError("Shell() calls with password are not supported")

        self.conn = self.do_ssh_login(login_timeout=30, debug=self.debug)

        # Always store the original prompt(s) so we can fallback to them later
        self.default_prompt_list = self.conn.get_prompt()

        # Populate the initial prompt list...

    def __repr__(self):
        return """<Shell: %s>""" % self.host

    def do_ssh_login(self,
        login_timeout=30,
        debug=0,
    ):
        assert isinstance(debug, int)
        assert len(self.account_list) > 0

        # FIXME - clean up PrivateKey here...
        private_key=PrivateKey(keytype='rsa').from_file(self.private_key_path)

        if self.protocol == "ssh":
            conn = SSH2(driver=self.driver)

            DEFAULT_LOGIN_TIMEOUT = conn.get_connect_timeout()
            DEFAULT_PROMPT_LIST = conn.get_prompt()
            DEFAULT_PROMPT_TIMEOUT = conn.get_timeout()

            conn.set_connect_timeout(login_timeout)
            conn.connect(hostname=self.host, port=self.port)
            login_success = False
            for account in self.account_list:
                conn.login(account)
                try:
                    assert isinstance(conn, SSH2)   # This succeeds if logged in...
                    login_success = True
                    break
                except AssertionError as aa:
                    # login with account failed...
                    continue

            assert login_success is True
            if login_success is True:
                self.password = account.password
            else:
                raise ValueError("Login to host='%s' failed" % self.host)

            conn.set_connect_timeout(DEFAULT_LOGIN_TIMEOUT)

            return conn

        else:
            raise ValueError("FATAL: proto='%s' isn't a valid protocol" % proto)

    def append_account(self, account):
        # From the exscript docs...
        #     key = PrivateKey.from_file('~/.ssh/id_rsa', 'my_key_password')
        self.account_list.append(account)

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

    def tfsm(self, template=None, input_str=None):
        """Run the textfsm template against input_str"""
        assert isinstance(template, str)
        assert isinstance(input_str, str)
        if os.path.isfile(os.path.expanduser(str(template))):
            # open the textfsm template from disk...
            fh = open(template, "r")
        else:
            # build a fake filehandle around textfsm template string
            fh = StringIO(template)
        fsm = TextFSM(fh)
        header = fsm.header
        values = fsm.ParseText(input_str)
        assert values != [], "Could not match any values with the template."

        ## Pack the extracted values into a list of dicts, using keys from
        ##   the header file
        retval = list()

        # Values is a nested list of captured information
        for ii in (values, values[0]):
            if not isinstance(ii, list):
                continue
            for row in ii:
                try:
                    # Require the row to be a list
                    assert isinstance(row, list)
                    # Require row to be exactly as long as the header list
                    assert len(row) == len(header)
                    row_dict = {}
                    for idx, value in enumerate(row):
                        row_dict[header[idx]] = value
                    retval.append(row_dict)
                except AssertionError:
                    break
            if len(retval) > 0:
                return retval
            else:
                raise ValueError("Cannot parse the textfsm template")

    def execute(self, cmd="", prompt_list=(), timeout=0, template=None, debug=0, consume=True):
        assert isinstance(cmd, str)
        if cmd.strip()=="":
            assert len(cmd.splitlines()) == 0
        else:
            assert len(cmd.splitlines()) == 1
        assert isinstance(timeout, int)
        assert (template is None) or isinstance(template, str)
        assert isinstance(debug, int)

        cmd = cmd.strip()

        if len(prompt_list) > 0:
            self._extend_prompt(prompt_list)

        normal_timeout = self.conn.get_timeout()
        if timeout > 0:
            self.conn.set_timeout(timeout)

        # Handle prompt_list...
        self.set_custom_prompts(prompt_list)

        if cmd.strip()[0:4]=="sudo":
            pre_sudo_prompts = self.conn.get_prompt()
            # FIXME I removed re.compile from the sudo prompt. Example prompt:
            #    [sudo] password for mpenning: 
            sudo_prompt = re.compile(r"[\r\n].+?:")
            prompts_w_sudo = copy.deepcopy(pre_sudo_prompts)
            prompts_w_sudo.insert(0, sudo_prompt)
            self.conn.set_prompt(prompts_w_sudo)

            # Sending sudo cmd here...
            self.conn.send(cmd+os.linesep)
            prompt_idx, re_match_object = self.conn.expect_prompt()
            # idx==0 is a sudo password prompt...
            if prompt_idx==0:
                self.conn.set_prompt(self.default_prompt_list)
                self.conn.send(self.password+os.linesep)
                prompt_idx, re_match_object = self.conn.expect_prompt()
                assert isinstance(prompt_idx, int)

            else:
                raise ValueError("Cannot complete 'execute(cmd='%s')" % cmd)
            self.conn.set_prompt(pre_sudo_prompts)

        else:
            if cmd.strip()=="":
                #self.conn.execute(cmd+os.linesep)
                self.conn.execute(cmd)
            else:
                self.conn.execute(cmd)

        # Reset the prompt list at the end of the command...
        if len(prompt_list) > 0:
            self.reset_prompt()

        # Reset the timeout at the end of the command...
        if self.conn.get_timeout() != normal_timeout:
            self.conn.set_timeout(normal_timeout)

        ## TextFSM
        ## If template is specified, parse the response into a list of dicts...
        if isinstance(template, str):
            return self.tfsm(template, self.conn.response)
        else:
            return self.conn.response

    def send(self, cmd="", debug=0):
        assert isinstance(cmd, str)
        assert len(cmd.splitlines()) == 1
        assert isinstance(debug, int)

        self.conn.send(cmd)

    def expect(self, prompt_list=(), timeout=0, debug=0):
        """Expect prompts, including those in prompt_list"""
        assert isinstance(debug, int)
        if debug > 0:
            pass

        normal_timeout = self.conn.get_timeout()
        if timeout > 0:
            self.conn.set_timeout(timeout)

        normal_prompts = self.conn.get_prompt()

        # Handle prompt_list...
        self.set_custom_prompts(prompt_list)

        prompt_idx, re_match_object = self.conn.expect_prompt()

        self.conn.set_timeout(normal_timeout)
        # Reset the prompt list at the end of the command...
        if len(prompt_list) > 0:
            self.reset_prompt()

        return prompt_idx, re_match_object

    def set_timeout(self, timeout=0):
        """Set the command timeout"""
        if isinstance(timeout, int) and timeout>0:
            return self.conn.set_timeout(timeout)

    def set_custom_prompts(self, prompt_list=()):
        """Wrapper around set_prompt()"""
        return self.set_prompt(prompt_list)

    def reset_prompt(self):
        """Reset all prompts to default"""
        return self.conn.set_prompt(self.default_prompt_list)

    def set_prompt(self, prompt_list=()):
        """Extend the expected prompts with prompts in prompt_list"""
        normal_prompts = self.conn.get_prompt()
        custom_prompts = copy.copy(normal_prompts)
        if (isinstance(prompt_list, tuple) or isinstance(prompt_list, list)) and len(prompt_list) > 0:
            prompt_list.reverse()
            for prompt in prompt_list:
                if isinstance(prompt, str):
                    custom_prompts.insert(0, re.compile(prompt))

                elif isinstance(prompt, re.Pattern):
                    custom_prompts.insert(0, prompt)

                else:
                    raise ValueError("Cannot process prompt='%s'" % prompt)
            self.conn.set_prompt(custom_prompts)

        return normal_prompts, custom_prompts

    def close(self, force=True, timeout=0, debug=0):
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
def main():

    # login to this system and demo a few commands...
    conn = Shell(username="mpenning", host="localhost")
    output = conn.execute("ls -la | wc -l")

    # conn.set_prompt([r"\]\#", r"\]\$"])
    conn.set_prompt([r"---", r"==="])
    conn.set_timeout(1)
    uname_output = conn.execute("uname -a")

    # resetting prompts after intentionally adding junk prompt matches above...
    conn.reset_prompt()

    # sudo example...
    conn.set_timeout(2)
    output = conn.execute("sudo ls -la")

    # Parse conn.response for file name and permissions... build a dict with the results
    file_permission_dict = dict()
    for permission_str, filename in any_match(output, r"^\s*(\S+)\s.+?\s+(\S+)\s*$"):
        print("BAR", permission_str, filename)

    conn.send("exit\r")
    conn.close()

if __name__=="__main__":
    main()
