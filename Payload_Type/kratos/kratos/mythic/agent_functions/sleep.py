from mythic_container.MythicCommandBase import *

class SleepArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="interval",
                type=ParameterType.Number,
                description="Sleep interval in seconds",
                default_value=10,
                parameter_group_info=[ParameterGroupInfo(
                    required=False,
                    ui_position=0
                )],
            )
        ]

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            # No parameters = get current sleep time
            pass
        else:
            try:
                self.set_arg("interval", int(self.command_line.strip()))
            except:
                raise Exception("Sleep interval must be a valid number")

class SleepCommand(CommandBase):
    cmd = "sleep"
    needs_admin = False
    help_cmd = "sleep [interval]"
    description = "Get or set the callback interval in seconds. Call without parameters to see current value."
    version = 1
    author = "@goultarde"
    argument_class = SleepArguments
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
