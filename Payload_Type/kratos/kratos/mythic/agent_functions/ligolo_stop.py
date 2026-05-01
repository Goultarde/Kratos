from mythic_container.MythicCommandBase import *


class LigoloStopArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="remote_path",
                cli_name="RemotePath",
                display_name="Session Path (blank = kill all)",
                type=ParameterType.String,
                default_value="",
                description="Path of the ligolo-ng binary to stop. Leave blank to kill all sessions.",
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
            self.add_arg("remote_path", cmd)


class LigoloStopCommand(CommandBase):
    cmd = "ligolo_stop"
    needs_admin = False
    help_cmd = "ligolo_stop  |  ligolo_stop C:\\Windows\\Temp\\svchost32.exe"
    description = "Stop a ligolo-ng session. Leave path blank to kill all sessions."
    version = 1
    author = "@goultarde"
    argument_class = LigoloStopArguments
    supported_ui_features = ["ligolo:stop"]
    attackmapping = ["T1090"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        remote_path = taskData.args.get_arg("remote_path") or ""
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        response.DisplayParams = f"stop {remote_path}" if remote_path else "stop all"
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
