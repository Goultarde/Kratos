from mythic_container.MythicCommandBase import *


class SpawntoArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                cli_name="Path",
                type=ParameterType.String,
                description="Process to use for fork+run injection (e.g. svchost.exe or full path). Default: C:\\Windows\\System32\\svchost.exe",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise ValueError("Must supply a process path")
        self.add_arg("path", self.command_line)

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)


class SpawntoCommand(CommandBase):
    cmd = "spawnto"
    needs_admin = False
    help_cmd = "spawnto svchost.exe"
    description = "Change the process spawned for fork+run injection (spawn command). Bare name is resolved from C:\\Windows\\System32\\."
    version = 1
    author = "@goultarde"
    attackmapping = []
    argument_class = SpawntoArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
            DisplayParams=taskData.args.get_arg("path"),
        )
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
