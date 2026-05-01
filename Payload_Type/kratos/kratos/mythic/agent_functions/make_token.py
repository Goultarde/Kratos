from mythic_container.MythicCommandBase import *


class MakeTokenArguments(TaskArguments):
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
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=True,
                        ui_position=1,
                    )
                ],
            ),
            CommandParameter(
                name="password",
                cli_name="password",
                display_name="Password",
                type=ParameterType.String,
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False,
                        ui_position=2,
                    )
                ],
            ),
            CommandParameter(
                name="netOnly",
                cli_name="netOnly",
                display_name="NetOnly Logon",
                description="Use LOGON32_LOGON_NEW_CREDENTIALS instead of LOGON32_LOGON_INTERACTIVE.",
                default_value=True,
                type=ParameterType.Boolean,
                parameter_group_info=[
                    ParameterGroupInfo(
                        group_name="credential_store",
                        required=False,
                        ui_position=2,
                    ),
                    ParameterGroupInfo(
                        required=False,
                        ui_position=3,
                    ),
                ],
            ),
        ]

    async def parse_arguments(self):
        self.load_args_from_json_string(self.command_line)


class MakeTokenCommand(CommandBase):
    cmd = "make_token"
    needs_admin = False
    help_cmd = "make_token -username domain\\user -password abc123"
    description = "Create a logon token from plaintext credentials and use it for subsequent commands."
    version = 1
    author = "@goultarde"
    argument_class = MakeTokenArguments
    attackmapping = ["T1134"]
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
        else:
            username = taskData.args.get_arg("username")
            password = taskData.args.get_arg("password")
            taskData.args.remove_arg("username")
            taskData.args.remove_arg("password")
            if "\\" in username:
                username_pieces = username.split("\\", 1)
                realm = username_pieces[0]
                account = username_pieces[1]
            elif "@" in username:
                realm = ""
                account = username
            else:
                realm = taskData.Callback.Host
                account = username
            cred = {
                "type": "plaintext",
                "realm": realm,
                "credential": password if password is not None else "",
                "account": account,
            }
            taskData.args.add_arg("credential", cred, type=ParameterType.Credential_JSON)

        mode = "netOnly" if taskData.args.get_arg("netOnly") else "interactive"
        if cred.get("realm"):
            target = f"{cred.get('realm')}\\{cred.get('account')}"
        else:
            target = cred.get("account")
        response.DisplayParams = f"{target} {cred.get('credential')} ({mode})"
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
