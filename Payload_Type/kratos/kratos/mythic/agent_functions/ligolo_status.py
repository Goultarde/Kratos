from mythic_container.MythicCommandBase import *


class LigoloStatusArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class LigoloStatusCommand(CommandBase):
    cmd = "ligolo_status"
    needs_admin = False
    help_cmd = "ligolo_status"
    description = "List active ligolo-ng sessions."
    version = 1
    author = "@goultarde"
    argument_class = LigoloStatusArguments
    browser_script = BrowserScript(script_name="ligolo", author="@goultarde")
    attackmapping = ["T1090", "T1572"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
            DisplayParams="status",
        )

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
