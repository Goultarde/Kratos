import json
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class SocksArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="port",
                cli_name="Port",
                display_name="Port",
                type=ParameterType.Number,
                description="Local port on which Mythic will listen for SOCKS5 connections.",
                parameter_group_info=[ParameterGroupInfo(ui_position=0, required=True)],
            ),
            CommandParameter(
                name="action",
                cli_name="Action",
                display_name="Action",
                type=ParameterType.ChooseOne,
                choices=["start", "stop"],
                default_value="start",
                description="Start or stop the SOCKS5 proxy.",
                parameter_group_info=[ParameterGroupInfo(ui_position=1, required=False)],
            ),
            CommandParameter(
                name="username",
                cli_name="Username",
                display_name="Username (auth proxy)",
                type=ParameterType.String,
                description="Optional authentication username for the SOCKS port.",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=2)],
            ),
            CommandParameter(
                name="password",
                cli_name="Password",
                display_name="Password (auth proxy)",
                type=ParameterType.String,
                description="Optional authentication password for the SOCKS port.",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=3)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Port required.")
        try:
            self.load_args_from_json_string(self.command_line)
        except Exception:
            try:
                self.add_arg("port", int(self.command_line.strip()))
            except Exception:
                raise Exception(f"Invalid port: {self.command_line}")


class SocksCommand(CommandBase):
    cmd = "socks"
    needs_admin = False
    help_cmd = "socks -Port 7000 -Action start"
    description = (
        "Enable a SOCKS5 proxy compatible with proxychains/proxychains4. "
        "Mythic opens the local port; the agent relays connections through the target. "
        "Sleep is set to 0 on start for continuous polling."
    )
    version = 1
    script_only = True
    author = "@goultarde"
    argument_class = SocksArguments
    attackmapping = ["T1090"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

        port     = taskData.args.get_arg("port")
        action   = taskData.args.get_arg("action") or "start"
        username = taskData.args.get_arg("username") or ""
        password = taskData.args.get_arg("password") or ""

        response.DisplayParams = f"-Action {action} -Port {port}"
        if username:
            response.DisplayParams += f" -Username {username}"

        if action == "start":
            resp = await SendMythicRPCProxyStartCommand(MythicRPCProxyStartMessage(
                TaskID=taskData.Task.ID,
                PortType="socks",
                LocalPort=port,
                Username=username,
                Password=password,
            ))
            if not resp.Success:
                response.TaskStatus = MythicStatus.Error
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=taskData.Task.ID,
                    Response=resp.Error.encode(),
                ))
            else:
                response.TaskStatus = MythicStatus.Success
                response.Completed = True
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=taskData.Task.ID,
                    Response=f"SOCKS5 started on port {port}. Use: proxychains -q <cmd>".encode(),
                ))
                # Sleep to 0 for continuous polling
                await SendMythicRPCTaskCreateSubtask(MythicRPCTaskCreateSubtaskMessage(
                    TaskID=taskData.Task.ID,
                    CommandName="sleep",
                    Params=json.dumps({"interval": 0}),
                ))
        else:
            resp = await SendMythicRPCProxyStopCommand(MythicRPCProxyStopMessage(
                TaskID=taskData.Task.ID,
                PortType="socks",
                Port=port,
                Username=username,
                Password=password,
            ))
            if not resp.Success:
                response.TaskStatus = MythicStatus.Error
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=taskData.Task.ID,
                    Response=resp.Error.encode(),
                ))
            else:
                response.TaskStatus = MythicStatus.Success
                response.Completed = True
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=taskData.Task.ID,
                    Response=f"SOCKS5 stopped on port {port}.".encode(),
                ))
                await SendMythicRPCTaskCreateSubtask(MythicRPCTaskCreateSubtaskMessage(
                    TaskID=taskData.Task.ID,
                    CommandName="sleep",
                    Params=json.dumps({"interval": 5}),
                ))

        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
