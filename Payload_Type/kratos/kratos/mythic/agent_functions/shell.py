from mythic_container.MythicCommandBase import *
import json

class ShellArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        if len(self.command_line.strip()) == 0:
             raise Exception("shell requires a command to run.")
        pass

class ShellCommand(CommandBase):
    cmd = "shell"
    attributes = CommandAttributes(
        dependencies=["run"],
        suggested_command=True,
    )
    needs_admin = False
    help_cmd = "shell [command]"
    description = "Run a shell command using cmd.exe /c (Alias for run)"
    version = 2
    author = "@goultarde"
    argument_class = ShellArguments
    attackmapping = ["T1059"]

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
            CommandName="run"
        )
        taskData.args.add_arg("executable", "cmd.exe")
        taskData.args.add_arg("arguments", f"/c {taskData.args.command_line}")
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
