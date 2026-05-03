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
                name="logon_type",
                cli_name="logon_type",
                display_name="Logon Type",
                type=ParameterType.ChooseOne,
                choices=["2 - Interactive", "3 - Network", "8 - NetworkCleartext", "9 - NewCredentials"],
                default_value="9 - NewCredentials",
                description=(
                    "2=Interactive (local session, requires SeAssignPrimaryTokenPrivilege), "
                    "3=Network (no local creds, like PSExec), "
                    "8=NetworkCleartext (creds sent in cleartext, useful for WinRM/SMB), "
                    "9=NewCredentials (inherits current token, changes only network creds - like runas /netonly)"
                ),
                parameter_group_info=[
                    ParameterGroupInfo(group_name="credential_store", required=False, ui_position=2),
                    ParameterGroupInfo(required=False, ui_position=3),
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
                    ParameterGroupInfo(required=True, ui_position=4),
                ],
            ),
            CommandParameter(
                name="arguments",
                cli_name="arguments",
                display_name="Arguments",
                type=ParameterType.String,
                default_value="/c whoami /all",
                description="Arguments passed to the application.",
                parameter_group_info=[
                    ParameterGroupInfo(group_name="credential_store", required=False, ui_position=4),
                    ParameterGroupInfo(required=False, ui_position=5),
                ],
            ),
        ]

    async def parse_arguments(self):
        self.load_args_from_json_string(self.command_line)


class RunAsCommand(CommandBase):
    cmd = "runas"
    needs_admin = False
    help_cmd = "runas -username DOMAIN\\user -password Password123! -logon_type '9 - NewCredentials' -application cmd.exe -arguments '/c whoami /all'"
    description = (
        "Spawn a process under alternate credentials via LogonUser + CreateProcessAsUser (RunasCS-style). "
        "Captures stdout/stderr via anonymous pipes."
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

        # Extract the number from "9 - NewCredentials"
        logon_choice = taskData.args.get_arg("logon_type") or "9 - NewCredentials"
        logon_type_int = int(logon_choice.split(" ")[0])
        taskData.args.remove_arg("logon_type")
        taskData.args.add_arg("logon_type", logon_type_int, type=ParameterType.Number)

        target = f"{realm}\\{account}" if realm else account
        app  = taskData.args.get_arg("application")
        args = taskData.args.get_arg("arguments") or ""
        logon_labels = {2: "Interactive", 3: "Network", 8: "NetworkCleartext", 9: "NewCredentials"}
        mode = logon_labels.get(logon_type_int, str(logon_type_int))

        response.DisplayParams = f"{target} -> {app} {args} [{mode}]"
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
