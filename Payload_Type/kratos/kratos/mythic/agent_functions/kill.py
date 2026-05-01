from mythic_container.MythicCommandBase import *


class KillArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                type=ParameterType.Number,
                description="PID of the process to terminate",
                parameter_group_info=[ParameterGroupInfo(
                    required=True,
                    ui_position=1
                )]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("No PID given.")
        if self.command_line[0] == "{":
            import json
            d = json.loads(self.command_line)
            if "pid" in d:
                self.add_arg("pid", d["pid"])
            elif "process_id" in d:
                self.add_arg("pid", d["process_id"])
            else:
                self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("pid", int(self.command_line.strip()))


class KillCommand(CommandBase):
    cmd = "kill"
    needs_admin = False
    help_cmd = "kill <pid>"
    description = "Forcefully terminate a process by PID."
    version = 1
    author = "@goultarde"
    argument_class = KillArguments
    supported_ui_features = ["kill", "process_browser:kill"]
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
