from contextlib import closing
from io import StringIO
import unicodedata
import platform
import socket
import uuid
import time
import sys
import re
import os

assert sys.version_info >= (3, 0, 0), "cannon does not support Python 2"

from rich import print as rich_print
from textfsm import TextFSM
import pexpect as px
import transitions

# import snoop

r"""
cannon - Python ssh automation
Copyright (C) 2022      David Michael Pennington
Copyright (C) 2020-2021 David Michael Pennington at Cisco Systems

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


class UnexpectedPrompt(Exception):
    """Exception for an Unexpected Prompt"""

    def __init__(self, error=""):
        super(UnexpectedPrompt, self).__init__(error)


class PromptDetectionError(Exception):
    """Exception for an Unexpected Prompt"""

    def __init__(self, error=""):
        super(PromptDetectionError, self).__init__(error)


class InvalidLogFile(Exception):
    """Exception for an invalid log file"""

    def __init__(self, error=""):
        super(InvalidLogFile, self).__init__(error)


# DO NOT escape '$' here
EXPECTED_LAST_PROMPT_CHARS = (":", ">", "#", "$")
BASE_PROMPT_REGEX_LENGTH = 7


class TeeStdoutFile(object):
    """Simple class to send stdout to screen and log_file simultaneously"""

    def __init__(self, log_file="", filemode="w", log_screen=False, encoding="utf-8"):
        self.log_file = os.path.expanduser(log_file)
        self.filemode = filemode
        self.log_screen = log_screen
        self.stdout = sys.stdout
        self.encoding = encoding

        # automatically over-write empty log files
        if os.path.isfile(self.log_file):
            log_file_size = int(os.path.getsize(self.log_file))
            if log_file_size == 0:
                os.remove(self.log_file)
            else:
                raise InvalidLogFile("FATAL: can not overwrite %s" % self.log_file)

        self.fh = open(self.log_file, self.filemode, encoding=self.encoding)

    def __del__(self):
        sys.stdout = self.stdout
        try:
            self.fh.close()
        except AttributeError:
            # We hit this if self.fh was never opened such as existing log_file
            pass

    def write(self, line):
        for ii in line:
            if isinstance(ii, bytes):
                self.fh.write(ii.decode(self.encoding))
                self.stdout.write(ii.decode(self.encoding))
            elif isinstance(ii, str):
                self.fh.write(ii)
                self.stdout.write(ii)

    def flush(self):
        self.fh.flush()

    def close(self):
        self.fh.close()

# Globals used by child.interact()...
#     https://stackoverflow.com/a/43383182/667301
filter_buf = ''
filter_buf_size = 256
let_me_out = False
bash_prompt = re.compile('linux>')

class Account(object):
    def __init__(self, user, passwd="", priv_passwd="", ssh_key=""):
        self.user = user
        self.passwd = passwd
        self.priv_passwd = priv_passwd
        self.ssh_key = os.path.expanduser(ssh_key)  # Path to ssh private key

    def __repr__(self):
        return """<Account user:{} passwd:{} priv_passwd:{} ssh_key: {}>""".format(
            self.user, self.passwd, self.priv_passwd, self.ssh_key
        )


class Shell(transitions.Machine):
    def __init__(
        self,
        host="",
        credentials=(),
        ssh_keepalive=60,
        protocols=({"proto": "ssh", "port": 22}, {"proto": "telnet", "port": 23}),
        mode="",
        auto_priv_mode=None,
        log_screen=False,
        log_file="",
        strip_colors=True,
        debug=False,
        command_timeout=30,
        login_timeout=10,
        relogin_delay=120,
        encoding="utf-8",
        login_attempts=3,
    ):

        STATES = (
            "INIT_SESSION",
            "SELECT_TCP_PROTOCOL",
            "SELECT_LOGIN_CREDENTIALS",
            "SEND_LOGIN_USERNAME",
            "SEND_LOGIN_PASSWORD",
            "CONNECT",
            "LOGIN_SUCCESS_UNPRIV",
            "LOGIN_SUCCESS_PRIV",
            "LOGIN_TIMEOUT",
            "SEND_PRIV_PASSWORD",
            "LOGIN_COMPLETE",
            "INTERACT",
            "CLOSE_SESSION",
        )
        super(Shell, self).__init__(states=STATES, initial="INIT_SESSION")

        self.host = host
        self.credentials = credentials
        self.protocols = protocols
        self.auto_priv_mode = auto_priv_mode
        if auto_priv_mode is not None:
            rich_print(
                "[bold red]WARNING: auto_priv_mode will be deprecated.  Please stop using this option.[/bold red]"
            )
            time.sleep(2.5)
        self.log_screen = log_screen
        self.log_file = os.path.expanduser(log_file)
        self.debug = debug
        self.command_timeout = command_timeout
        self.login_timeout = login_timeout
        self.relogin_delay = relogin_delay
        self.encoding = encoding
        self.login_attempts = login_attempts

        self.child = None  # Pexpect's child object
        self.username = None
        self.password = None
        self.ssh_key = ""
        self.ssh_keepalive = int(ssh_keepalive)
        self.ciphers = ""
        self.key_exchanges = ""
        self.connect_cmd = ""
        self.credentials_iterator = self.iter_credentials()
        self.proto_dict = {}

        self.mode = mode
        self.strip_colors = strip_colors

        self.prompt_hostname = ""
        # Detect a typical linux CLI prompt...
        # Build the template before detecting prompt
        self.base_prompt_regex = self.build_base_prompt_regex()

        self.matching_prompt_regex = ""
        self.matching_prompt_regex_index = -1
        self.matching_string = ""

        #######################################################################
        ## Transitions to SELECT_TCP_PROTOCOL state
        #######################################################################
        self.add_transition(
            trigger="_go_SELECT_TCP_PROTOCOL",
            source="INIT_SESSION",
            dest="SELECT_TCP_PROTOCOL",
            after="after_SELECT_TCP_PROTOCOL_cb",
        )

        #######################################################################
        ## Transitions to SELECT_LOGIN_CREDENTIALS state
        #######################################################################
        self.add_transition(
            trigger="_go_SELECT_LOGIN_CREDENTIALS",
            source="SELECT_TCP_PROTOCOL",
            dest="SELECT_LOGIN_CREDENTIALS",
            after="after_SELECT_LOGIN_CREDENTIALS_cb",
        )

        self.add_transition(
            trigger="_go_SELECT_LOGIN_CREDENTIALS",
            source="SEND_LOGIN_PASSWORD",
            dest="SELECT_LOGIN_CREDENTIALS",
            after="after_SELECT_LOGIN_CREDENTIALS_cb",
        )

        # FIXME - removed on 31 Jan 2021
        # self.add_transition(
        #    trigger="_go_SELECT_LOGIN_CREDENTIALS",
        #    source="LOGIN_COMPLETE",
        #    dest="SELECT_LOGIN_CREDENTIALS",
        #    after="after_SELECT_LOGIN_CREDENTIALS_cb",
        # )

        #######################################################################
        ## Transitions to CONNECT state
        #######################################################################
        self.add_transition(
            trigger="_go_CONNECT",
            source="CONNECT",
            dest="CONNECT",
            after="after_CONNECT_cb",
        )

        self.add_transition(
            trigger="_go_CONNECT",
            source="SELECT_LOGIN_CREDENTIALS",
            dest="CONNECT",
            after="after_CONNECT_cb",
        )

        #######################################################################
        ## Transitions to SEND_LOGIN_USERNAME state
        #######################################################################
        self.add_transition(
            trigger="_go_SEND_LOGIN_USERNAME",
            source="CONNECT",
            dest="SEND_LOGIN_USERNAME",
            after="after_SEND_LOGIN_USERNAME_cb",
        )

        # In case we got to LOGIN_COMPLETE prematurely...
        self.add_transition(
            trigger="_go_SEND_LOGIN_USERNAME",
            source="LOGIN_COMPLETE",
            dest="SEND_LOGIN_USERNAME",
            after="after_SEND_LOGIN_USERNAME_cb",
        )

        #######################################################################
        ## Transitions to SEND_LOGIN_PASSWORD state
        #######################################################################
        self.add_transition(
            trigger="_go_SEND_LOGIN_PASSWORD",
            source="CONNECT",
            dest="SEND_LOGIN_PASSWORD",
            after="after_SEND_LOGIN_PASSWORD_cb",
        )

        self.add_transition(
            trigger="_go_SEND_LOGIN_PASSWORD",
            source="SEND_LOGIN_USERNAME",
            dest="SEND_LOGIN_PASSWORD",
            after="after_SEND_LOGIN_PASSWORD_cb",
        )

        # In case we need to try the same password again
        self.add_transition(
            trigger="_go_SEND_LOGIN_PASSWORD",
            source="SEND_LOGIN_PASSWORD",
            dest="SEND_LOGIN_PASSWORD",
            after="after_SEND_LOGIN_PASSWORD_cb",
        )

        # In case we got to LOGIN_COMPLETE prematurely...
        self.add_transition(
            trigger="_go_SEND_LOGIN_PASSWORD",
            source="LOGIN_COMPLETE",
            dest="SEND_LOGIN_PASSWORD",
            after="after_SEND_LOGIN_PASSWORD_cb",
        )

        #######################################################################
        ## Transitions to LOGIN_SUCCESS_UNPRIV state
        #######################################################################
        self.add_transition(
            trigger="_go_LOGIN_SUCCESS_UNPRIV",
            source="SEND_LOGIN_USERNAME",
            dest="LOGIN_SUCCESS_UNPRIV",
            after="after_LOGIN_SUCCESS_UNPRIV_cb",
        )

        self.add_transition(
            trigger="_go_LOGIN_SUCCESS_UNPRIV",
            source="SEND_LOGIN_PASSWORD",
            dest="LOGIN_SUCCESS_UNPRIV",
            after="after_LOGIN_SUCCESS_UNPRIV_cb",
        )

        self.add_transition(
            trigger="_go_LOGIN_SUCCESS_UNPRIV",
            source="CONNECT",
            dest="LOGIN_SUCCESS_UNPRIV",
            after="after_LOGIN_SUCCESS_UNPRIV_cb",
        )

        #######################################################################
        ## Transitions to SEND_PRIV_PASSWORD state
        #######################################################################
        self.add_transition(
            trigger="_go_LOGIN_SUCCESS_UNPRIV",
            source="LOGIN_SUCCESS_UNPRIV",
            dest="SEND_PRIV_PASSWORD",
            after="after_SEND_PRIV_PASSWORD_cb",
        )

        #######################################################################
        ## Transitions to LOGIN_SUCCESS_PRIV state
        #######################################################################
        self.add_transition(
            trigger="_go_LOGIN_SUCCESS_PRIV",
            source="CONNECT",
            dest="LOGIN_SUCCESS_PRIV",
            after="after_LOGIN_SUCCESS_PRIV_cb",
        )

        self.add_transition(
            trigger="_go_LOGIN_SUCCESS_PRIV",
            source="SEND_LOGIN_PASSWORD",
            dest="LOGIN_SUCCESS_PRIV",
            after="after_LOGIN_SUCCESS_PRIV_cb",
        )

        #######################################################################
        ## Transitions to LOGIN_COMPLETE state
        #######################################################################
        self.add_transition(
            trigger="_go_LOGIN_COMPLETE",
            source="LOGIN_SUCCESS_UNPRIV",
            dest="LOGIN_COMPLETE",
            after="after_LOGIN_COMPLETE_cb",
        )

        self.add_transition(
            trigger="_go_LOGIN_COMPLETE",
            source="LOGIN_SUCCESS_PRIV",
            dest="LOGIN_COMPLETE",
            after="after_LOGIN_COMPLETE_cb",
        )

        self.add_transition(
            trigger="_go_LOGIN_COMPLETE",
            source="LOGIN_COMPLETE",
            dest="LOGIN_COMPLETE",
            after="after_LOGIN_COMPLETE_cb",
        )

        #######################################################################
        ## Transitions to INTERACT state
        #######################################################################
        self.add_transition(
            trigger="_go_INTERACT",
            source="LOGIN_COMPLETE",
            dest="INTERACT",
            after="after_INTERACT_cb",
        )

        #######################################################################
        ## Unconditionally transition to the SELECT_TCP_PROTOCOL state
        #######################################################################
        self._go_SELECT_TCP_PROTOCOL()

    def interact_output_filter(self, s):
        """Use this as an interact() output filter"""
        global proc, bash_prompt, filter_buf, filter_buf_size, let_me_out

        filter_buf += str(s)
        filter_buf = filter_buf[-filter_buf_size:]

        if "LET ME OUT" in filter_buf:
            let_me_out = True

        if bash_prompt.search(filter_buf):
            if let_me_out:
                self.child.sendline('exit')
                self.child.expect(pexpect.EOF)
                self.child.wait()
            else:
                self.child.sendline('python')

        return str(s)

    def build_connect_cmd(self):
        if self.debug:
            rich_print("")
            rich_print("    [bold cyan]in build_connect_cmd()[/bold cyan]")
            rich_print(
                "    [bold blue]build_connect_cmd() is configuring ssh parameters for self.connect_cmd[/bold blue]"
            )
            rich_print(
                "    [bold blue]CURRENT STATE:[/bold blue] '[bold magenta]{}[/bold magenta]'".format(
                    self.state
                )
            )

        if self.ciphers:
            cipher_opt = "-c {}".format(self.ciphers)
        else:
            cipher_opt = ""

        if self.key_exchanges:
            key_exchange_opt = "-o KexAlgorithms={}".format(self.key_exchanges)
        else:
            key_exchange_opt = ""

        # Implement ssh or telnet command... ssh with public key
        if self.proto_dict["proto"] == "ssh" and self.ssh_key != "":
            self.connect_cmd = "ssh {} {} -l {} -p {} -i {} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ServerAliveInterval={} {}".format(
                cipher_opt,
                key_exchange_opt,
                self.username,
                self.proto_dict["port"],
                self.ssh_key,
                self.ssh_keepalive,
                self.host,
            )

        elif self.proto_dict["proto"] == "ssh" and self.ssh_key == "":
            # https://serverfault.com/a/1002182/78702
            self.connect_cmd = "ssh {} {} -l {} -p {} -o PubkeyAuthentication=no -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ServerAliveInterval={} {}".format(
                cipher_opt,
                key_exchange_opt,
                self.username,
                self.proto_dict["port"],
                self.ssh_keepalive,
                self.host,
            )

        elif self.proto_dict["proto"] == "telnet":
            self.connect_cmd = "telnet {} {}".format(self.host, self.proto_dict["port"])

        else:
            raise NotImplementedError("")

        if self.debug:
            rich_print("    [bold blue]build_connect_cmd() finished[/bold blue]")
            rich_print("")

    def execute(
        self,
        cmd=None,
        template=None,
        prompts=(),
        timeout=0.0,
        command_timeout=0.0,
        carriage_return=True,
        relax_prompt=False,
    ):
        """Run a command and optionally parse with a TextFSM template

            - `cmd` is the command to execute
            - `template` is a string with the text of a TextFSM template
            - `prompts` is a tuple of prompt regexs to apply to the output of the command
            - `timeout` is how long we should wait for the command prompt to return
            - `carriage_return` indicates whether the command should be followed with a carriage-return.  The values are either True or False (default is True, meaning the CR will be sent after the command).

        execute() returns a list of dicts if `template` is specified; otherwise
        it returns None.
        """
        assert cmd is not None
        assert self.child.isalive()  # Don't issue commands against a dead conn

        if self.debug:
            rich_print("")
            rich_print("    [bold cyan]in execute()[/bold cyan]")
            rich_print(
                "        [bold blue]CURRENT STATE:[/bold blue] '[bold magenta]{}[/bold magenta]'".format(
                    self.state
                )
            )

        if timeout == 0.0 and command_timeout > 0.0:
            timeout = command_timeout

        elif timeout == 0.0 and command_timeout == 0.0:
            timeout = self.command_timeout

        arg_list = (
            "cmd",
            "template",
            "prompts",
            "timeout",
            "command_timeout",
            "carriage_return",
        )
        arg = list()
        if self.debug:
            # build the debugging string...
            for ii in arg_list:
                if ii == "cmd":
                    arg.append("'" + cmd + "'")
                elif ii == "template" and template is not None:
                    arg.append("template=TRUNCATED".format(template))
                elif ii == "template" and template is None:
                    arg.append("template=None")
                elif ii == "prompts":
                    arg.append("prompts={}".format(prompts))
                elif ii == "timeout":
                    arg.append("timeout={}".format(timeout))
                elif ii == "carriage_return":
                    arg.append("carriage_return={}".format(carriage_return))
            logstr = ", ".join(arg)
            rich_print(
                "        [bold blue]execute([/bold blue][bold green]{}[/bold green][bold blue])[/bold blue]".format(
                    logstr
                )
            )

        if self.debug:
            rich_print(
                "        [bold blue]execute() is running with cmd='{}'[/bold blue]".format(
                    cmd
                )
            )
        if carriage_return:
            if self.debug:
                rich_print(
                    "        [bold blue] self.child.sendline('{}')[/bold blue]".format(
                        cmd
                    )
                )
            self.child.sendline(cmd)
        else:
            if self.debug:
                rich_print(
                    "        [bold blue] self.child.send('{}')[/bold blue]".format(cmd)
                )
            self.child.send(cmd)

        # Extend the list of cli_prompts if `prompts` was specified
        cli_prompts = self.build_base_prompt_regex(relax_prompt=relax_prompt)
        if prompts != ():
            assert isinstance(prompts, tuple)
            cli_prompts.extend(prompts)  # Add command-specific prompts here...

        # Look for prompt matches after executing the command
        if self.debug:
            rich_print(
                "        [bold blue]execute() is calling cexpect()[/bold blue]".format(
                    cmd
                )
            )

        index = self.cexpect(cli_prompts, timeout=timeout)

        if self.debug:
            rich_print(
                "        [bold blue]execute() matched index %s: %s in cexpect()[/bold blue]"
                % (index, cli_prompts[index])
            )

        ## If template is specified, parse the response into a list of dicts...
        if template is not None:
            if os.path.isfile(os.path.expanduser(str(template))):
                # open the textfsm template from disk...
                fh = open(template, "r")
            else:
                # build a fake filehandle around textfsm template string
                fh = StringIO(template)
            fsm = TextFSM(fh)
            header = fsm.header
            values = fsm.ParseText(self.response)
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
            return index

    def csendline(self, text):
        if self.debug:
            rich_print("")
            rich_print("    [bold cyan]in csendline()[/bold cyan]")
        assert self.child.isalive()
        if self.debug:
            rich_print("")
            rich_print(
                "            [bold blue]CURRENT STATE:[/bold blue] '[bold magenta]{}[/bold magenta]'".format(
                    self.state
                )
            )
            rich_print(
                "            [bold blue]csendline([/bold blue][bold yellow]'{}'[/bold yellow][bold blue])[/bold blue]".format(
                    text
                )
            )

        if self.debug:
            rich_print(
                "            [bold blue]csendline() calling self.child.sendline()[/bold blue]"
            )
            rich_print(
                "            [bold blue]exiting csendline()[/bold blue]"
            )
        # WARNING: use self.child.sendline(); do not use self.csendline() here
        self.child.sendline(text)

    def cexpect(self, pattern_list, timeout=-1):
        if self.debug:
            rich_print("")
            rich_print("    [bold cyan]in cexpect()[/bold cyan]")
            rich_print(
                "        [bold blue]CURRENT STATE:[/bold blue] '[bold magenta]{}[/bold magenta]'".format(
                    self.state
                )
            )
            rich_print(
                "        [bold blue]cexpect([/bold blue][bold green]pattern_list, timeout={}[/bold green][bold blue]) was called[/bold blue]".format(
                    timeout
                )
            )
            # Expand all pattern_list terms...
            rich_print("        [bold blue]pattern_list = {}[/bold blue]".format("[["))
            for idx, term in enumerate(pattern_list):
                rich_print(
                    "            [bold blue]{} {},[/bold blue]".format(idx, repr(term))
                )
            rich_print("        [bold blue]{}[/bold blue]".format(str("]]")))

        # FIXME - this could break cexpect if ssh connection is still in progress
        # assert self.child.isalive()

        now = time.time()

        try:
            if self.debug:
                rich_print(
                    "        [bold blue]cexpect() calling self.child.expect(pattern_list, timeout={})[/bold blue]".format(
                        timeout
                    )
                )
            match_index = self.child.expect(pattern_list, timeout=timeout)
            self.matching_prompt_regex_index = match_index
            self.matching_prompt_regex = pattern_list[match_index]

            if self.debug:
                delta_secs = round(time.time() - now, 4)
                rich_print("")
                rich_print(
                    "        [bold blue]^^ cexpect() matched regex at match_index {}={}[/bold blue]".format(
                        match_index, repr(pattern_list[match_index])
                    )
                )
                # FIXME why can't I use quotes around self.matching_prompt in rich_print()
                # rich_print(
                #    "      [bold blue]^^ cexpect() matching_prompt={}[/bold blue]".format(
                #        repr(self.matching_prompt)
                #    )
                # )
                rich_print(
                    "        [bold blue]^^ cexpect() match time: {} seconds[/bold blue]".format(
                        delta_secs
                    )
                )
                rich_print("")
                rich_print(
                    "    [bold blue]cexpect() debugs from str(self.child):[/bold blue]"
                )
                for line in str(self.child).splitlines():
                    rich_print("        [bold yellow]{0}[/bold yellow]".format(line))

        except px.exceptions.EOF:
            if self.debug:
                rich_print(
                    "        [bold red]cexpect() EOF exception while waiting for pattern_list[/bold red]"
                )
            match_index = None

        except px.exceptions.TIMEOUT:
            if self.debug:
                rich_print(
                    "        [bold red]cexpect() TIMEOUT exception while waiting for pattern_list[/bold red]"
                )
            match_index = None

        if (match_index is not None) and match_index >= 0:
            try:
                if self.debug:
                    rich_print(
                        "        [bold blue]cexpect() len(pattern_list[match_index])={}".format(
                            len(pattern_list[match_index])
                        )
                    )
                assert not ("UUID~" in pattern_list[match_index][0:6])

            except AssertionError as ee:
                rich_print(
                    "[bold red]cexpect() matched prompt index {}: {}.  {}[/bold red]".format(
                        match_index, pattern_list[match_index], str(ee)
                    )
                )

            return match_index

        else:
            # match_index hit an error... try again...
            self.child.sendline("")
            match_index = self.child.expect(pattern_list, timeout=timeout)

            assert match_index >= 0
            # match_index < 0
            if self.debug:
                rich_print("")
                rich_print(
                    "        [bold blue]cexpect() detected a prompt and is returning '{}' to the calling function[/bold blue]".format(
                        match_index
                    )
                )
            return match_index

    def interact(self):
        self._go_INTERACT()

    def modify_ssh_parameters(self):
        """This method should be called after calling self.cexpect() during ssh spawn.  It returns True or False"""

        if self.debug:
            rich_print("")
            rich_print("    [bold cyan]in modify_ssh_parameters()[/bold cyan]")
            rich_print(
                "    [bold blue]CURRENT STATE:[/bold blue] '[bold magenta]{}[/bold magenta]'".format(
                    self.state
                )
            )

        #  no matching ssh cipher found. Their offer:
        mm = re.search(r"no\s+matching\s+cipher.+?offer:\s+(\S.+)$", self.child.after)
        if mm is not None:
            candidate_cipher_list = mm.group(1).strip()
            self.ciphers = candidate_cipher_list
            if self.debug:
                rich_print(
                    "    [bold blue]modify_ssh_parameters() set self.ciphers: '{}'[/bold blue]".format(
                        self.ciphers
                    )
                )
            # We didn't have a matching prompt character...
            if self.debug:
                rich_print("")
                rich_print(
                    "    [bold blue]modify_ssh_parameters() returning True[/bold blue]"
                )
            return True

        #  no matching key exchange method found. Their offer: diffie-hellman-group14-sha1
        mm = re.search(
            r"no\s+matching\s+key\s+exchange.+?offer:\s+(\S.+)$", self.child.after
        )
        if mm is not None:
            self.key_exchanges = mm.group(1).strip()
            if self.debug:
                rich_print(
                    "    [bold blue]modify_ssh_parameters() set self.key_exchanges.[/bold blue]"
                )
                rich_print(
                    "        valid [bold yellow]key_exchanges={}[/bold yellow]".format(
                        self.key_exchanges
                    )
                )
            # We didn't have a matching prompt character...
            if self.debug:
                rich_print("")
                rich_print(
                    "    [bold blue]modify_ssh_parameters() returning True[/bold blue]"
                )
            return True

        if self.debug:
            rich_print("")
            rich_print(
                "    [bold blue]modify_ssh_parameters() returning False[/bold blue]"
            )
        return False

    @property
    def matching_prompt(self):
        """Get the matching prompt character; return the prompt character. Return None is session is not alive"""
        if self.debug:
            rich_print("    [bold cyan]in matching_prompt()[/bold cyan]")

        # After finds the string which matched...
        after = self.child.after

        self.matching_string = after

        if self.debug:
            rich_print(
                "    [bold blue]matching_prompt() is parsing: '{}'[/bold blue]".format(
                    after
                )
            )

        # Check for a valid CLI prompt character...
        candidate_prompt = None
        if self.child.isalive():
            if self.debug:
                rich_print(
                    "    [bold blue]matching_prompt() is iterating over lines in after.splitlines()[/bold blue]"
                )

            # Process ssh session output line by line...
            for line in after.splitlines():
                if self.debug:
                    rich_print(
                        "        [bold blue]checking line='{}'[/bold blue]".format(line)
                    )
                line = line.strip()
                if len(line) > 0:

                    candidate_prompt = line[-1]
                    prompt_hostname = line.strip()[0:-1]

                    if self.debug:
                        rich_print("    [bold blue]line='{}'[/bold blue]".format(line))
                        rich_print(
                            "    [bold yellow]    candidate_prompt='{}'[/bold yellow]".format(
                                candidate_prompt
                            )
                        )
                        rich_print(
                            "    [bold yellow]    prompt_hostname='{}'[/bold yellow]".format(
                                prompt_hostname
                            )
                        )

            if candidate_prompt in EXPECTED_LAST_PROMPT_CHARS:
                if self.debug:
                    rich_print(
                        "    [bold blue]matching_prompt() is returning candidate_prompt='{}'[/bold blue]".format(
                            candidate_prompt
                        )
                    )
                return candidate_prompt

        else:
            if self.debug:
                rich_print(
                    "    [bold blue]matching_prompt() is returning None='{}'[/bold blue]".format(
                        line
                    )
                )
            candidate_prompt = None
            return candidate_prompt

    @property
    def response(self):
        before = self.child.before
        if self.strip_text_colors:
            return self.strip_text_colors(before)
        else:
            return before

    def exit(self):
        if self.debug:
            rich_print(
                "    [bold blue]exit() is calling self.child.close()[/bold blue]".format(
                    line
                )
            )
        self.child.close()

    def quit(self):
        if self.debug:
            rich_print(
                "    [bold blue]quit() is calling self.exit()[/bold blue]".format(line)
            )
        self.exit()

    def iter_protocols(self):
        if self.debug:
            rich_print("")
            rich_print("    [bold cyan]in iter_protocols()[/bold cyan]")
        for proto_dict in self.protocols:
            yield proto_dict

    def iter_credentials(self):
        if self.debug:
            rich_print("")
            rich_print("    [bold cyan]in iter_credentials()[/bold cyan]")
        for cred in self.credentials:
            if self.debug:
                rich_print("    [bold blue]iter_credentials() is yielding:[/bold blue]")
                rich_print("        [bold yellow]{}[/bold yellow]".format(repr(cred)))
            yield cred

    def sync_prompt(self, require_detect_prompt=True):
        """Catch up with any queued prompts, we know to exit if we get a px.exceptions.TIMEOUT error"""
        if self.debug:
            rich_print("")
            rich_print("    [bold cyan]in sync_prompt()[/bold cyan]")
            rich_print(
                "    [bold blue]CURRENT STATE:[/bold blue] '[bold magenta]{}[/bold magenta]'".format(
                    self.state
                )
            )

        if self.debug:
            rich_print(
                "[bold blue]sync_prompt(require_detect_prompt={}) was called[/bold blue]".format(
                    require_detect_prompt
                )
            )

        # self.detect_prompt() *should* come before self.sync_prompt()
        if (self.prompt_hostname == "") and (require_detect_prompt is True):
            if self.debug:
                rich_print(
                    "[bold blue]detect_prompt() has not assigned a hostname to self.prompt_hostname[/bold blue]".format(
                        self.prompt_hostname
                    )
                )
                rich_print(
                    "[bold red]self.prompt_hostname='{}'.[/bold red]".format(
                        self.prompt_hostname
                    )
                )
            raise PromptDetectionError(
                "Please call detect_prompt() before sync_prompt()"
            )

        # WARNING: use self.child.sendline(); do not use self.csendline() here
        self.child.sendline("")

        finished = False
        while not finished:
            # Use a very short timeout here...
            # WARNING self.child.expect() is required; do not use self.cexpect()
            index = -2
            try:
                index = self.child.expect(self.base_prompt_regex, timeout=2.0)
                if self.debug:
                    rich_print(
                        "    [bold blue]sync_prompt() index={}[/bold blue]".format(
                            index
                        )
                    )

            except px.exceptions.TIMEOUT:
                # We got an EOF or TIMEOUT error...
                self.login_attempts = 0
                finished = True

            except px.exceptions.EOF:
                # We got an EOF or TIMEOUT error...
                self.login_attempts = 0
                finished = True

            except Exception as ee:
                print("ERROR: %s" % ee)

            if index == -2:
                finished = True

            elif index == -1:
                # We got an EOF or TIMEOUT error...
                self.login_attempts = 0
                finished = True

            elif index == 0:
                if self.debug:
                    rich_print(
                        "[bold red]sync_prompt() - found an ssh cipher error[/bold red]".format(
                            index
                        )
                    )

            elif index == 1:
                if self.debug:
                    rich_print(
                        "[bold red]sync_prompt() - found an ssh key exchange error[/bold red]".format(
                            index
                        )
                    )

            elif index == 2 or index == 3:
                if self.debug:
                    rich_print(
                        "[bold red]sync_prompt() - Unexpected index='{}'[/bold red]".format(
                            index
                        )
                    )

            elif index == 4:
                # We should only get to this prompt if auto_priv_mode is
                #     False
                self.login_attempts = 0
                finished = True

            elif index == 5:
                # We should only get to this prompt if auto_priv_mode is
                #     False
                self.login_attempts = 0
                finished = True

            elif index == 6:
                # We don't need to attempt any more logins if we have
                #     a priv prompt
                self.login_attempts = 0
                finished = True

            else:
                raise NotImplementedError()

    def close(self):
        if self.debug:
            rich_print("")
            rich_print("    [bold cyan]in close()[/bold cyan]")
        self.child.close()
        return (self.child.exitstatus, self.child.signalstatus)

    def detect_prompt(self):
        """detect_prompt() checks for premature entry into LOGIN_COMPLETE and also looks for a prompt string"""
        # Detect the prompt as best-possible...
        if self.debug:
            rich_print("")
            rich_print("    [bold cyan]in detect_prompt(mode='{}')[/bold cyan]".format(self.mode))
            rich_print(
                "    [bold blue]CURRENT STATE:[/bold blue] '[bold magenta]{}[/bold magenta]'".format(
                    self.state
                )
            )

        if self.mode == "linux":
            if self.debug:
                rich_print(
                    "    [bold blue]detect_prompt() is calling change_linux_prompt()[/bold blue]"
                )
            # do NOT set detect_prompt=True... that starts an infinite loop...
            self.change_linux_prompt(detect_prompt=False)

            if self.debug:
                rich_print(
                    "    [bold blue]detect_prompt() starting a while loop to catch up with missed expect prompts[/bold blue]"
                )

            # Catch up on missed prompts...
            finished = False
            while not finished:
                try:
                    # FIXME: we need to remove the hard-coded prompt
                    #
                    #     only expect the linux prompt is safe because
                    #     we got self.mode=="linux"
                    self.child.expect([r"linux>"], timeout=1)
                except:
                    rich_print(
                        "        [bold blue]detect_prompt() timed out while expecting prompts with self.child.expect()[/bold blue]"
                    )
                    finished = True

            self.hostname = "linux"
            self.build_base_prompt_regex()  # Adjust the prompt regex after detection
            return self.prompt_hostname

        assert self.mode!="linux"

        if self.debug:
            rich_print(
                "    [bold blue]detect_prompt() using prompt detection heuristics[/bold blue]"
            )
            rich_print(
                "    [bold blue]detect_prompt() is trying to find detailed prompt information.  Sending a blank line to {}[/bold blue]".format(
                    self.host
                )
            )

        self.csendline("")

        # Double check that this isn't a pre-login banner...
        loop_counter = 0
        finished = False
        if self.debug:
            rich_print("    [bold blue]detect_prompt() starting while loop[/bold blue]")
        while not finished:
            # Use a very short timeout here...
            # WARNING use self.child.expect()... do not use self.cexpect()
            if self.debug:
                rich_print(
                    "        [bold blue]in while loop (finished=False)[/bold blue]"
                )
            try:
                loop_counter += 1  # Keep track of how many times we loop through input

                if self.debug:
                    rich_print(
                        "        [bold blue]while loop_counter={}[/bold blue]".format(
                            loop_counter
                        )
                    )
                    rich_print("        [bold blue]calling self.child.expect()[/bold blue]")

                index = self.child.expect(self.base_prompt_regex, timeout=1)

            except px.exceptions.TIMEOUT:
                assert self.child.isalive()
                if self.debug:
                    rich_print("")
                    rich_print(
                            "[bold blue]        detect_prompt() - self.child.expect() timed-out: pexpect.TIMEOUT[/bold blue]"
                    )
                    rich_print(
                            "[bold blue]        detect_prompt() - index=-1.  Exiting while loop[/bold blue]"
                    )
                index = -1
                finished = True

            except px.exceptions.EOF:
                if self.debug:
                    rich_print(
                            "[bold blue]        detect_prompt() - self.child.expect() found pexpect.EOF[/bold blue]"
                    )
                    rich_print(
                            "[bold blue]        detect_prompt() - index=-1.  Exiting while loop[/bold blue]"
                    )
                index = -1
                finished = True

            if index == -1:
                assert self.child.isalive()
                if self.debug:
                    rich_print("")
                    rich_print(
                        "[bold blue]        detect_prompt() index={}[/bold blue]".format(
                            index
                        )
                    )

            elif index == 0 or index == 1:
                # This is an ssh-cipher or ssh key-exchange problem....
                #    fail for now, handle this later if important...
                if self.debug:
                    rich_print("")
                    rich_print(
                        "[bold blue]        detect_prompt() index={}[/bold blue]".format(
                            index
                        )
                    )
                raise NotImplementedError()

            elif index == 2:
                assert self.child.isalive()
                # We probably want to detect_prompt() based on some banner
                # This should be a username prompt...
                if self.debug:
                    rich_print("")
                    rich_print(
                        "[bold blue]        detect_prompt() index={}[/bold blue]".format(
                            index
                        )
                    )
                    rich_print(
                        "        [bold blue]detect_prompt() found a premature entry into detect_prompt().  Redirecting to state SEND_LOGIN_USERNAME[/bold blue]"
                    )
                self._go_SEND_LOGIN_USERNAME()

            elif index == 3:
                assert self.child.isalive()
                # We probably went to detect_prompt() based on some banner
                # This should be a password prompt...
                if self.debug:
                    rich_print("")
                    rich_print(
                        "[bold blue]        detect_prompt() index={}[/bold blue]".format(
                            index
                        )
                    )
                    rich_print(
                        "        [bold blue]detect_prompt() found a premature entry into detect_prompt().  Redirecting to state SEND_LOGIN_PASSWORD[/bold blue]"
                    )

                self._go_SEND_LOGIN_PASSWORD()

            elif index > 3:
                # We got a non-username, non-password prompt... exit this loop!
                # Start prompt detection heuristics...
                if self.debug:
                    # We got a non-username, non-password prompt... exit this loop!
                    rich_print("")
                    rich_print(
                        "        [bold blue]detect_prompt() index={}[/bold blue]".format(
                            index
                        )
                    )
                    rich_print(
                        "        [bold blue]detect_prompt() found a non-username, non-password prompt... exit the while loop.[/bold blue]"
                    )
                    rich_print(
                        "        [bold blue]detect_prompt() set finished=True[/bold blue]"
                    )
                finished = True

            else:
                raise ValueError

            if self.debug:
                rich_print("")
                rich_print(
                    "        [bold blue]detect_prompt() loop_counter={}".format(
                        loop_counter
                    )
                )

        before_retval = list()
        before = self.child.before
        if self.strip_colors:
            before_retval = self.strip_control_chars(before).splitlines()

            # FIXME - I think we can delete this...
            for line in self.strip_text_colors(before).splitlines():
                # https://stackoverflow.com/a/19016117/667301
                no_cntl_char_line = "".join(
                    ch for ch in line if unicodedata.category(ch)[0] != "C"
                )
                before_retval.append(no_cntl_char_line)
        else:
            # I think it's safe to remove these because self.strip_colors==False
            #before = self.strip_control_chars(before)
            #before_retval = self.strip_control_chars(before).splitlines()

            # FIXME - I think we can delete this...
            for line in before.splitlines():
                # https://stackoverflow.com/a/19016117/667301
                no_cntl_char_line = "".join(
                    ch for ch in line if unicodedata.category(ch)[0] != "C"
                )
                before_retval.append(no_cntl_char_line)
        before_stripped = "\r\n".join(before_retval)

        after_retval = list()
        after = self.child.after
        if self.debug:
            rich_print("    [bold blue]detect_prompt() repr(after): {}".format(repr(after)))
            rich_print("        [bold blue]writing output to variable: after_retval")

        if self.strip_colors:
            if self.debug:
                rich_print("        [bold blue]detect_prompt() is stripping colors in variable: after")
                rich_print(
                        "        [bold blue]detect_prompt() after values: '{}'[/bold blue]".format(
                        after
                    )
                )

            for line in self.strip_text_colors(after).splitlines():
                # https://stackoverflow.com/a/19016117/667301
                no_cntl_char_line = "".join(
                    ch for ch in line if unicodedata.category(ch)[0] != "C"
                )
                after_retval.append(no_cntl_char_line)
        else:
            if self.debug:
                rich_print("        [bold blue]detect_prompt() will not strip colors in variable: after")
            for line in after.splitlines():
                # https://stackoverflow.com/a/19016117/667301
                no_cntl_char_line = "".join(
                    ch for ch in line if unicodedata.category(ch)[0] != "C"
                )
                after_retval += no_cntl_char_line
        after_stripped = "\r\n".join(after_retval)

        if self.debug:
            rich_print("")
            rich_print("    [bold blue]detect_prompt(): len(after_stripped)={} lines[/bold blue]".format(len(after_stripped)))
            rich_print(
                "\n    [bold blue]detect_prompt() finished the while loop took {} iterations.  Detected prompt index={}[/bold blue]".format(
                    loop_counter, index
                )
            )

        ## Example of prompt detection on route-views.oregon-ix.org...
        # hostname = self.child.before.strip()  # detect hostname    = route-views
        assert isinstance(after, str)
        if self.debug:
            rich_print("")
            rich_print(
                "        [bold blue]detect_prompt() sent an empty command and saw this in self.child.after: '{}'".format(
                    after_stripped
                )
            )

        assert len(after.splitlines()) > 0

        # Set the hostname
        for line in after_retval:
            if line.strip() == "":
                continue
            else:
                self.prompt_hostname = line.strip()[:-1]
                break

        assert self.prompt_hostname != ""

        if self.debug:
            rich_print(
                "        [bold blue]detect_prompt() searched for the prompt in this output '{}'".format(
                    after_stripped
                )
            )
            rich_print(
                "        [bold yellow]detect_prompt() set prompt_hostname='{}'[/bold yellow]".format(
                    self.prompt_hostname
                )
            )

        assert self.prompt_hostname != ""

        self.build_base_prompt_regex()  # Adjust the prompt regex after detection

        return self.prompt_hostname

    def build_base_prompt_regex(self, relax_prompt=False):
        """Assign self.base_prompt_regex with the latest prompt info"""

        if self.debug:
            rich_print("")
            rich_print("    [bold cyan]in build_base_prompt_regex()[/bold cyan]")

        ####### WARNING #######################################################
        #   Getting this cisco unpriv prompt to work was extremely hard...
        #   there is a bug somewhere that ignores the trailing ">" and
        #   instead matches a space after the hostname.  I forced the
        #   regex to match properly by stripping off the last character of
        #   the hostname and used a negated special character class: [^\n]+?
        #######################################################################
        if relax_prompt is False:
            cisco_unpriv_prompt_str = r"[\r\n]+{0}[^\n]+?{1}".format(
                re.escape(self.prompt_hostname[:-1]), r">"
            )
            linux_prompt_str = r"[\r\n]+{0}[^\n]+?{1}".format(
                re.escape(self.prompt_hostname[:-1]), re.escape("$")
            )
            cisco_priv_prompt_str = r"[\r\n]+{0}[^\n]+?{1}".format(
                re.escape(self.prompt_hostname[:-1]), re.escape("#")
            )

        else:
            cisco_unpriv_prompt_str = r"[\r\n]+[^\n]+?{0}".format(
                r">"
            )
            linux_prompt_str = r"[\r\n]+[^\n]+?{0}".format(
                re.escape("$")
            )
            cisco_priv_prompt_str = r"[\r\n]+[^\n]+?{0}".format(
                re.escape("#")
            )

        self.base_prompt_regex = [
            # Unable to negotiate with 172.16.1.3 port 22: no matching cipher found. Their offer: aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc
            r"no\s+matching\s+cipher\s+found.*$",
            # no matching key exchange method found. Their offer: diffie-hellman-group14-sha1
            r"no\s+matching\s+key\s+exchange\s+method\s+found\..*$",
            r"sername:",
            r"[Pp]assword[^\r\n]{0,20}?:",
            # Cisco unpriv prompt...
            cisco_unpriv_prompt_str,
            # linux prompt
            linux_prompt_str,
            # Cisco priv or linux root prompt...
            cisco_priv_prompt_str,
        ]

        # Remove some prompt matches after successful login
        if self.state in set(
            {
                "LOGIN_SUCCESS_UNPRIV",
                "LOGIN_SUCCESS_PRIV",
                "LOGIN_TIMEOUT",
                "LOGIN_COMPLETE",
            }
        ):

            for index in [0, 1, 2, 3]:
                self.base_prompt_regex[index] = "UUID~" + str(uuid.uuid4())

        if self.debug:
            # Expand all base_prompt_regex terms...
            rich_print(
                "        [bold blue]self.base_prompt_regex = {}[/bold blue]".format(
                    "[["
                )
            )
            for idx, term in enumerate(self.base_prompt_regex):
                rich_print(
                    "            [bold blue]{} {},[/bold blue]".format(idx, repr(term))
                )
            rich_print("        [bold blue]{}[/bold blue]".format(str("]]")))

        assert len(self.base_prompt_regex) == BASE_PROMPT_REGEX_LENGTH
        if self.debug:
            rich_print("    [bold blue]exiting build_base_prompt_regex()[/bold blue]")
        return self.base_prompt_regex

    def change_linux_prompt(self, detect_prompt=True):
        if self.debug:
            rich_print("")
            rich_print("    [bold cyan]in change_linux_prompt()[/bold cyan]")

        self.prompt_hostname = "linux"
        self.base_prompt_regex = self.build_base_prompt_regex()
        if self.debug:
            rich_print("        [bold blue]change_linux_prompt() is running 'precmd_functions=()'[/bold blue]")
        self.child.sendline("precmd_functions=()")
        if self.debug:
            rich_print("        [bold blue]change_linux_prompt() is running 'export PS1={}>'[/bold blue]".format(self.prompt_hostname))
        self.child.sendline("export PS1='{}>'".format(self.prompt_hostname))

        if detect_prompt is True:
            if self.debug:
                rich_print("")
                rich_print(
                    "    [bold blue]change_linux_prompt() is running detect_prompt()[/bold blue]"
                )
            self.detect_prompt()

    def strip_control_chars(self, text_input=""):
        if self.debug:
            rich_print("    [bold cyan]in strip_control_chars(text_input='{}')[/bold cyan]".format(text_input))

        retval = list()
        for line in text_input.splitlines():
            # https://stackoverflow.com/a/19016117/667301
            no_cntl_char_line = "".join(
                ch for ch in line if unicodedata.category(ch)[0] != "C"
            )
            retval.append(no_cntl_char_line)
        return os.linesep.join(retval)

    def strip_text_colors(self, ascii_text=""):
        """This function only works with string inputs, byte inputs fail"""

        if self.debug:
            if isinstance(ascii_text, str) or isinstance(ascii_text, bytes):
                sample = ascii_text[0:10]
                rich_print("")
                rich_print("    [bold cyan]in strip_text_colors(ascii_text='{}...')[/bold cyan]".format(sample))
                rich_print("        [bold blue]ascii_text is type: {}[/bold blue]".format(type(ascii_text)))
        # https://stackoverflow.com/a/14693789/667301...
        assert not isinstance(ascii_text, bytes)
        assert isinstance(ascii_text, str)
        ansi_escape_8bit = re.compile(
            br"(?:\x1B[@-Z\\-_]|[\x80-\x9A\x9C-\x9F]|(?:\x1B\[|\x9B)[0-?]*[ -/]*[@-~])"
        )
        result = ansi_escape_8bit.sub(b"", bytes(ascii_text, self.encoding))
        if self.debug:
            rich_print(
                "        [bold blue]strip_text_colors() returning {} characters[/bold blue]".format(
                    len(result)
                )
            )
        return result.decode(self.encoding)

    def after_SELECT_TCP_PROTOCOL_cb(self):
        """Attempt to make a raw TCP connection to the protocol's TCP port"""

        if self.debug:
            rich_print("")
            rich_print(
                "[bold blue]Entering state: [/bold blue][bold magenta]{}[/bold magenta]".format(
                    self.state
                )
            )

        finished = False
        for ii in range(0, 3):

            if finished is True:
                continue

            if self.debug:
                rich_print("    [bold blue]var ii={}[/bold blue]".format(str(ii)))
            for proto_dict in self.iter_protocols():
                self.proto_dict = proto_dict
                proto_name, proto_port = proto_dict.get("proto"), proto_dict.get("port")
                if self.debug:
                    rich_print(
                        "    [bold blue]Trying TCP socket to {} port {}[/bold blue]".format(
                            self.host, proto_port
                        )
                    )
                with closing(
                    socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ) as proto_sock:
                    proto_sock.settimeout(3)
                    try:
                        if proto_sock.connect_ex((self.host, proto_port)) == 0:
                            ## We completed a tcp connection to proto_port...
                            ##   now, get the credentials
                            if self.debug:
                                rich_print(
                                    "    [bold blue]SUCCESS: port {}[/bold blue]".format(
                                        proto_port
                                    )
                                )
                            finished = True
                            break
                    except socket.gaierror:
                        raise Exception("'{}' is an unknown hostname".format(self.host))

                    except Exception as ee:
                        raise Exception(ee)

                if ((ii == 0) or (ii == 1)) and (finished is False):

                    time.sleep(
                        self.relogin_delay
                    )  # Give the host time to recover from auto-login

        if finished is False:
            raise Exception("Cannot connect to host: '{}'".format(self.host))
        else:
            if self.debug:
                rich_print(
                    "    [bold blue]after_SELECT_TCP_PROTOCOL_cb() is getting credentials from after_SELECT_LOGIN_CREDENTIALS_cb()[/bold blue]"
                )
            self._go_SELECT_LOGIN_CREDENTIALS()  # Get the proper credentials

    def after_SELECT_LOGIN_CREDENTIALS_cb(self):

        if self.debug:
            rich_print("")
            rich_print(
                "[bold blue]Entering state: [/bold blue][bold magenta]{}[/bold magenta]".format(
                    self.state
                )
            )

        if self.debug:
            rich_print(
                "    [bold blue]after_SELECT_LOGIN_CREDENTIALS_cb() is using a while loop to iterate through attempted credentials[/bold blue]"
            )
        while self.login_attempts > 0:
            if self.debug:
                rich_print(
                    "    [bold blue]after_SELECT_LOGIN_CREDENTIALS_cb() login_attempts={}[/bold blue]".format(
                        self.login_attempts
                    )
                )
            cred = next(self.credentials_iterator)
            if self.debug:
                rich_print(
                    "        [bold blue]after_SELECT_LOGIN_CREDENTIALS_cb() self.username={}[/bold blue]".format(
                        cred.user
                    )
                )
                rich_print(
                    "        [bold blue]after_SELECT_LOGIN_CREDENTIALS_cb() self.password={}[/bold blue]".format(
                        cred.passwd
                    )
                )
                rich_print(
                    "        [bold blue]after_SELECT_LOGIN_CREDENTIALS_cb() self.ssh_key={}[/bold blue]".format(
                        cred.ssh_key
                    )
                )
            self.username = cred.user
            self.password = cred.passwd
            self.ssh_key = cred.ssh_key

            if self.child is not None:
                if self.debug:
                    rich_print(
                        "    [bold yellow]after_SELECT_LOGIN_CREDENTIALS_cb() is closing the current connection[/bold yellow]".format(
                            cred.passwd
                        )
                    )
                self.close()  # Make way for a fresh child instance

            if self.debug:
                rich_print(
                    "    [bold blue]after_SELECT_LOGIN_CREDENTIALS_cb() is calling after_CONNECT_cb()[/bold blue]".format(
                        cred.passwd
                    )
                )
            self._go_CONNECT()

            self.login_attempts -= 1

    def after_CONNECT_cb(self):
        """Build an ssh / telnet session to self.host"""

        if self.debug:
            rich_print("")
            rich_print(
                "[bold blue]Entering state: [/bold blue][bold magenta]{}[/bold magenta]".format(
                    self.state
                )
            )

        if self.child is not None:
            if self.debug:
                rich_print(
                    "[bold yellow]after_CONNECT_cb() is closing the existing connection."
                )
            self.close()

        # run the ssh or telnet command
        ready_for_login = False
        while ready_for_login is False:

            try:
                self.build_connect_cmd()

                # Very strange things happen unless this is here...
                #      Transition from LOGIN_COMPLETE to spawning ssh????
                if self.state == "LOGIN_COMPLETE":
                    if self.debug:
                        rich_print(
                            "[bold magenta]Bypassing strange detour to after_CONNECT_cb()[/bold magenta]".format(
                                self.connect_cmd
                            )
                        )
                    ready_for_login = True
                    return None

                if self.debug:
                    rich_print(
                        "    [bold blue]after_CONNECT_cb() is calling pexpect.spawn()[/bold blue]"
                    )
                    rich_print(
                        "    [bold blue]pexpect.spawn([/bold blue]'{}'[bold blue])[/bold blue]".format(
                            self.connect_cmd
                        )
                    )

                # spawnu Ref: https://stackoverflow.com/a/37654748/667301
                self.child = px.spawn(
                    self.connect_cmd, timeout=self.login_timeout, encoding=self.encoding, echo=False
                )

            except px.exceptions.EOF as ee:
                time.sleep(70)

            # Ensure the pexpect connection is alive.
            try:
                assert self.child.isalive()

            except AssertionError as ee:
                rich_print(
                    "    [bold red]after_CONNECT_cb()\n        FATAL Assertion: self.child.isalive().\n        AssertionError: %s[/bold red]"
                    % str(ee)
                )
                sys.exit(1)

            # log to screen if requested
            if self.log_screen and self.log_file == "":
                self.child.logfile = sys.stdout

            # log to file if requested
            elif (self.log_screen is False) and self.log_file != "":
                self.child.logfile = open(self.log_file, "w")

            # log to both screen and file if requested
            elif (self.log_screen is True) and self.log_file != "":
                #self.child.logfile = TeeStdoutFile(
                self.child.logfile = TeeStdoutFile(
                    log_file=self.log_file, log_screen=self.log_screen
                )

            if self.debug:
                rich_print(
                    "    [bold blue]after_CONNECT_cb() calling cexpect()[/bold blue]"
                )
            index = self.cexpect(self.base_prompt_regex, timeout=self.login_timeout)

            # Ensure we did not match a UUID prompt...
            assert self.base_prompt_regex[index][0:6] != "UUID~"

            if self.debug:
                rich_print(
                    "    [bold blue]after_CONNECT_cb() call to cexpect() returned index={}[/bold blue]".format(
                        index
                    )
                )

            # Fix ssh cipher and key exchange problems and re-spawn ssh...
            if self.modify_ssh_parameters() is True:
                if self.debug:
                    rich_print(
                        "[bold yellow]modify_ssh_parameters() is closing and reconfiguring ssh[/bold yellow]"
                    )
                self.close()
                self.build_connect_cmd()

                if self.debug:
                    rich_print(
                        "    [bold blue]after_CONNECT_cb() calling itself[/bold blue]"
                    )
                self._go_CONNECT()

            # Do *not* delete or move self.match_prompt; cipher & key exchange detection is there
            # self.matching_prompt

            # FIXME - prompt index should NOT be zero here... need to know why
            if self.debug:
                rich_print(
                    "        [bold blue]self.cexpect() matched prompt index=[/bold blue]{}".format(
                        index
                    )
                )
                rich_print(
                    "        [bold blue]self.cexpect() matching prompt:[/bold blue]'{}'".format(
                        self.base_prompt_regex[index]
                    )
                )

            if index == -1:
                if self.debug:
                    rich_print(
                        "    [bold blue]after_CONNECT_cb() did not match a prompt.[/bold blue]"
                    )
                    rich_print(
                        "    [bold blue]after_CONNECT_cb() is sleeping for 70 seconds.[/bold blue]"
                    )
                time.sleep(70)
                self.build_connect_cmd()
                if self.debug:
                    rich_print(
                        "    [bold blue]after_CONNECT_cb() calling itself[/bold blue]"
                    )
                self._go_CONNECT()

            elif index >= 2:
                # Exit while() loop... ready for username / password...
                ready_for_login = True

        if index == 2:
            if self.debug:
                rich_print("")
                rich_print(
                    "    [bold blue]after_CONNECT_cb() calling after_SEND_LOGIN_USERNAME_cb()[/bold blue]"
                )
            self._go_SEND_LOGIN_USERNAME()
        elif index == 3:
            if self.debug:
                rich_print("")
                rich_print(
                    "    [bold blue]after_CONNECT_cb() calling after_SEND_LOGIN_PASSWORD_cb()[/bold blue]"
                )
            self._go_SEND_LOGIN_PASSWORD()
        elif index == 4:
            if self.debug:
                rich_print("")
                rich_print(
                    "    [bold blue]after_CONNECT_cb() calling after_LOGIN_SUCCESS_UNPRIV_cb()[/bold blue]"
                )
            self._go_LOGIN_SUCCESS_UNPRIV()
        elif index == 5:
            if self.debug:
                rich_print("")
                rich_print(
                    "    [bold blue]after_CONNECT_cb() calling after_LOGIN_SUCCESS_UNPRIV_cb()[/bold blue]"
                )
            self._go_LOGIN_SUCCESS_UNPRIV()
        elif index == 6:
            # Login priv in router prompt=#
            if self.debug:
                rich_print("")
                rich_print(
                    "    [bold blue]after_CONNECT_cb() calling _after_LOGIN_SUCCESS_PRIV_cb()[/bold blue]"
                )
            self._go_LOGIN_SUCCESS_PRIV()
        else:
            raise NotImplementedError()

    def after_SEND_LOGIN_PASSWORD_cb(self):

        if self.debug:
            rich_print("")
            rich_print(
                "[bold blue]Entering state: [/bold blue][bold magenta]{}[/bold magenta]".format(
                    self.state
                )
            )

        self.csendline(self.password)

        try:

            assert len(self.base_prompt_regex) == BASE_PROMPT_REGEX_LENGTH
            if self.debug:
                rich_print(
                    "    [bold blue]after_SEND_LOGIN_PASSWORD_cb() calling cexpect()[/bold blue]"
                )
            index = self.cexpect(self.base_prompt_regex, timeout=self.login_timeout)

            if self.debug:
                rich_print(
                    "\n   [bold blue]after_SEND_LOGIN_PASSWORD_cb() - self.child.expect() matched prompt index:[/bold blue] {}".format(
                        index
                    )
                )
                rich_print(
                    "\n   [bold blue]after_SEND_LOGIN_PASSWORD_cb() - self.child.expect() matching_ prompt:[/bold blue] {}".format(
                        re.escape(self.base_prompt_regex[index])
                    )
                )

            assert index >= 2

            if index == 0:  # This was the wrong ssh cipher...
                if self.debug:
                    rich_print(
                        "        [bold blue]after_SEND_LOGIN_PASSWORD_cb() found index={}.  Closing connection.[/bold blue]".format(
                            index
                        )
                    )
                self.close()
                raise NotImplementedError()

            elif index == 1:  # This was the wrong ssh key exchange...
                if self.debug:
                    rich_print(
                        "        [bold blue]after_SEND_LOGIN_PASSWORD_cb() found index={}.  Closing connection.[/bold blue]".format(
                            index
                        )
                    )
                self.close()
                raise NotImplementedError()

            elif index == 2:
                if self.debug:
                    rich_print(
                        "        [bold blue]after_SEND_LOGIN_PASSWORD_cb() found index={}.  Calling after_SELECT_LOGIN_CREDENTIALS_cb()[/bold blue]".format(
                            index
                        )
                    )
                foo_credentials = (
                    self._go_SELECT_LOGIN_CREDENTIALS()
                )  # Restart login with different creds
                rich_print("[bold red]{}[/bold red]".format(foo_credentials))

                if self.debug:
                    rich_print(
                        "        [bold blue]after_SEND_LOGIN_PASSWORD_cb() found index={}.  Calling after_SEND_LOGIN_USERNAME_cb()[/bold blue]".format(
                            index
                        )
                    )
                self._go_SEND_LOGIN_USERNAME()

            elif index == 3:
                # Send login password again... just in case...
                if self.debug:
                    rich_print(
                        "        [bold blue]after_SEND_LOGIN_PASSWORD_cb() found index={}.  Calling itself with the same password.[/bold blue]".format(
                            index
                        )
                    )
                self._go_SEND_LOGIN_PASSWORD()

            elif index == 4:
                if self.debug:
                    rich_print(
                        "        [bold blue]after_SEND_LOGIN_PASSWORD_cb() found index={}.  Calling after_LOGIN_SUCCESS_UNPRIV_cb()[/bold blue]".format(
                            index
                        )
                    )
                self._go_LOGIN_SUCCESS_UNPRIV()  # We got an unpriv prompt

            elif index == 5:
                if self.debug:
                    rich_print(
                        "        [bold blue]after_SEND_LOGIN_PASSWORD_cb() found index={}.  Calling after_LOGIN_SUCCESS_UNPRIV_cb()[/bold blue]".format(
                            index
                        )
                    )
                self._go_LOGIN_SUCCESS_UNPRIV()  # We got an unpriv prompt

            elif index == 6:
                if self.debug:
                    rich_print(
                        "        [bold blue]after_SEND_LOGIN_PASSWORD_cb() found index={}.  Calling after_LOGIN_SUCCESS_PRIV_cb()[/bold blue]".format(
                            index
                        )
                    )
                self._go_LOGIN_SUCCESS_PRIV()  # We got a priv prompt

            else:
                raise NotImplementedError()

        except px.exceptions.EOF:
            if self.debug:
                rich_print(
                    "   [bold red]after_SEND_LOGIN_PASSWORD_cb() - pexpect.exceptions.EOF error[/bold red]"
                )
            self.close()
            # self._go_SELECT_LOGIN_CREDENTIALS()  # Restart login with different creds
            self._go_CONNECT()  # Restart login with different creds

        except px.exceptions.TIMEOUT:
            if self.debug:
                rich_print(
                    "   [bold red]after_SEND_LOGIN_PASSWORD_cb() - pexpect error: TIMEOUT[/bold red]"
                )
            self.close()
            # self._go_SELECT_LOGIN_CREDENTIALS()  # Restart login with different creds
            if self.debug:
                rich_print(
                    "    [bold blue]after_SEND_LOGIN_PASSWORD_cb() calling after_CONNECT_cb()[/bold blue]"
                )
            self._go_CONNECT()  # Restart login with different creds

    def after_SEND_LOGIN_USERNAME_cb(self):

        if self.debug:
            rich_print("")
            rich_print(
                "[bold blue]Entering state: [/bold blue][bold magenta]{}[/bold magenta]".format(
                    self.state
                )
            )

        self.csendline(self.username)

        if self.debug:
            rich_print(
                "    [bold blue]after_SEND_LOGIN_USERNAME_cb() calling cexpect()[/bold blue]"
            )
        index = self.cexpect(self.base_prompt_regex, timeout=self.login_timeout)

        if self.debug:
            rich_print(
                "   [bold blue]after_SEND_LOGIN_USERNAME_cb() - self.child.expect() matched prompt index:[/bold blue] {}".format(
                    index
                )
            )
            rich_print(
                "   [bold blue]after_SEND_LOGIN_USERNAME_cb() - self.child.expect() matching_prompt:[/bold blue] {}".format(
                    self.base_prompt_regex[index]
                )
            )

        assert index >= 2  # We at least got another username prompt...
        # if index==0:
        #    self._go_SELECT_LOGIN_CREDENTIALS()

        if index == 2:
            self._go_SEND_LOGIN_USERNAME()

        elif index == 3:
            self._go_SEND_LOGIN_PASSWORD()

        elif index == 4:
            self._go_LOGIN_SUCCESS_UNPRIV()  # We got an unpriv prompt here

        elif index == 5:
            self._go_LOGIN_SUCCESS_UNPRIV()  # We got an unpriv prompt here

        elif index == 6:
            self._go_LOGIN_SUCCESS_PRIV()  # We got a priv prompt here

        else:
            raise NotImplementedError()

    def after_LOGIN_SUCCESS_UNPRIV_cb(self):

        if self.debug:
            rich_print("")
            rich_print(
                "[bold blue]Entering state: [/bold blue][bold magenta]{}[/bold magenta]".format(
                    self.state
                )
            )

        if self.debug:
            rich_print(
                "    [bold blue]after_LOGIN_SUCCESS_UNPRIV_cb() calling detect_prompt()[/bold blue]"
            )
        self.detect_prompt()

        if False:
            if self.debug and False:
                rich_print(
                    "   [bold blue]after_LOGIN_SUCCESS_UNPRIV_cb() - self.child.expect() matched prompt index:[/bold blue] {}".format(
                        index
                    )
                )
                rich_print(
                    "   [bold blue]after_LOGIN_SUCCESS_UNPRIV_cb() - self.child.expect() matching_prompt:[/bold blue] {}".format(
                        self.base_prompt_regex[index]
                    )
                )

            assert index >= 3
            if index == 3:
                if self.debug:
                    rich_print(
                        "    [bold blue]after_LOGIN_SUCCESS_UNPRIV_cb() calling after_SEND_PRIV_PASSWORD_cb()[/bold blue]"
                    )
                # Got a 'assword:' prompt
                self._go_SEND_PRIV_PASSWORD()

            elif index == 4:
                # Got a '>' prompt
                if self.debug:
                    rich_print(
                        "    [bold blue]after_LOGIN_SUCCESS_UNPRIV_cb() calling after_LOGIN_COMPLETE_cb()[/bold blue]"
                    )
                self._go_LOGIN_COMPLETE()  # FIXME - is this the right call?

            elif index == 5:
                # Got a '$' prompt
                if self.debug:
                    rich_print(
                        "    [bold red]after_LOGIN_SUCCESS_UNPRIV_cb() hit a fatal exception[/bold red]"
                    )
                raise Exception("index=5 Don't know what to do here")

            elif index == 6:
                if self.debug:
                    rich_print(
                        "    [bold blue]after_LOGIN_SUCCESS_UNPRIV_cb() calling after_LOGIN_SUCCESS_PRIV_cb()[/bold blue]"
                    )
                self._go_LOGIN_SUCCESS_PRIV()  # We got a priv prompt here

            else:
                raise NotImplementedError()

        if self.debug:
            rich_print(
                "    [bold blue]after_LOGIN_SUCCESS_UNPRIV_cb() calling after_LOGIN_COMPLETE_cb()[/bold blue]"
            )
        self._go_LOGIN_COMPLETE()

    def after_SEND_PRIV_PASSWORD_cb(self):

        if self.debug:
            rich_print("")
            rich_print(
                "[bold blue]Entering state: [/bold blue][bold magenta]{}[/bold magenta]".format(
                    self.state
                )
            )

        self.csendline(self.password)

        if self.debug:
            rich_print(
                "    [bold blue]after_SEND_PRIV_PASSWORD_cb() calling cexpect()[/bold blue]"
            )
        index = self.cexpect(self.base_prompt_regex, timeout=self.command_timeout)

        if self.debug:
            rich_print(
                "   [bold blue]after_SEND_PRIV_PASSWORD_cb() - self.child.expect() matched prompt index:[/bold blue] {}".format(
                    index
                )
            )
            rich_print(
                "   [bold blue]after_SEND_PRIV_PASSWORD_cb() - self.child.expect() matching_prompt:[/bold blue] {}".format(
                    self.base_prompt_regex[index]
                )
            )

        if index == 0:
            raise UnexpectedPrompt("Unexpected prompt: 'name:'")
        elif index == 1:
            self._go_SEND_PRIV_PASSWORD()
        elif index == 2:
            raise UnexpectedPrompt("Unexpected prompt: '>'")
        elif index == 3:
            raise UnexpectedPrompt("Unexpected prompt: '$'")
        elif index == 4:
            self._go_LOGIN_SUCCESS_PRIV()  # We got a priv prompt here

    def after_LOGIN_SUCCESS_PRIV_cb(self):

        if self.debug:
            rich_print("")
            rich_print(
                "[bold blue]Entering state: [/bold blue][bold magenta]{}[/bold magenta]".format(
                    self.state
                )
            )

        if self.prompt_hostname == "":
            if self.debug:
                rich_print("    [bold blue]self.prompt_hostname is empty.[/bold blue]")
                rich_print(
                    "    [bold blue]after_LOGIN_COMPLETE_cb() calling detect_prompt()[/bold blue]"
                )
            self.detect_prompt()  # detect_prompt() *should* come before sync_prompt()

        self._go_LOGIN_COMPLETE()

    def after_LOGIN_COMPLETE_cb(self):
        """Clean up on any queued command prompts and accept user commands"""
        # Ensure we don't try to cycles through any more passwords...
        self.login_attempts = 0

        if self.debug:
            rich_print("")
            rich_print(
                "[bold blue]Entering state: [/bold blue][bold magenta]{}[/bold magenta]".format(
                    self.state
                )
            )

        assert self.prompt_hostname != ""

    def after_INTERACT_cb(self):
        """Allow unscripted interaction with the system"""

        if self.debug:
            rich_print("")
            rich_print(
                "[bold blue]Entering state: [/bold blue][bold magenta]{}[/bold magenta]".format(
                    self.state
                )
            )

        assert self.child.isalive()
        rich_print(
            "[bold magenta]Enter INTERACT mode; use Cntl-] to escape[/bold magenta]"
        )

        # FIXME - build a proper output_filter
        self.child.interact(
            escape_character=chr(4), input_filter=None, output_filter=self.interact_output_filter
        )


if __name__ == "__main__":
    sess = Shell(
        host="route-views.oregon-ix.net",
        credentials=(Account(user="rviews", passwd=""),),
        log_screen=False,
        auto_priv_mode=False,
        debug=True,
    )
    sess.execute("term len 0")
    values = sess.execute(
        "show ip int brief",
        template="""Value INTF (\S+)\nValue IPADDR (\S+)\nValue STATUS (up|down|administratively down)\nValue PROTO (up|down)\n\nStart\n  ^${INTF}\s+${IPADDR}\s+\w+\s+\w+\s+${STATUS}\s+${PROTO} -> Record""",
    )
    print("VALUES " + str(values))
    sess.close()
