from mythic_container.MythicCommandBase import *


class LigoloStopArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="pid",
                cli_name="PID",
                display_name="PID (0 = kill all)",
                type=ParameterType.Number,
                default_value=0,
                description="PID of the ligolo-ng session to stop. 0 kills all sessions.",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=0)],
            ),
        ]

    async def parse_arguments(self):
        if not self.command_line:
            return
        cmd = self.command_line.strip()
        if cmd.startswith("{"):
            self.load_args_from_json_string(cmd)
        else:
            try:
                self.add_arg("pid", int(cmd))
            except ValueError:
                pass


class LigoloStopCommand(CommandBase):
    cmd = "ligolo_stop"
    needs_admin = False
    help_cmd = "ligolo_stop  |  ligolo_stop -PID 1234"
    description = "Stop a ligolo-ng session by PID. PID 0 kills all sessions."
    version = 1
    author = "@goultarde"
    argument_class = LigoloStopArguments
    supported_ui_features = ["ligolo:stop"]
    attackmapping = ["T1090"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        pid = taskData.args.get_arg("pid") or 0
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        response.DisplayParams = f"stop PID {pid}" if pid else "stop all"
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
