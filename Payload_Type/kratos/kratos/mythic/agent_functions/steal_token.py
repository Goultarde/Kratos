from mythic_container.MythicCommandBase import *


class StealTokenArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                type=ParameterType.Number,
                description="PID of the process whose token to steal",
                parameter_group_info=[ParameterGroupInfo(
                    required=True,
                    ui_position=1
                )]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("pid", int(self.command_line.strip()))


class StealTokenCommand(CommandBase):
    cmd = "steal_token"
    needs_admin = False
    help_cmd = "steal_token <pid>"
    description = (
        "Steal the access token of a target process and impersonate it. "
        "Requires SeDebugPrivilege to target privileged processes. "
        "Use rev2self to revert."
    )
    version = 1
    author = "@goultarde"
    supported_ui_features = ["steal_token", "process_browser:steal_token"]
    argument_class = StealTokenArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        pid = taskData.args.get_arg("pid")
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
            DisplayParams=f"PID: {pid}"
        )
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
