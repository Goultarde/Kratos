from mythic_container.MythicCommandBase import *
import json

class LsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                cli_name="path",
                display_name="Path",
                type=ParameterType.String,
                default_value=".",
                description="Directory to list (default: current directory).",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=1)],
            ),
            CommandParameter(
                name="recursive",
                cli_name="r",
                display_name="Recursive (-r)",
                type=ParameterType.Boolean,
                default_value=False,
                description="Recursively list all subdirectories.",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=2)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                parts = self.command_line.split()
                recursive = False
                path_parts = []
                for p in parts:
                    if p == "-r":
                        recursive = True
                    else:
                        path_parts.append(p)
                if path_parts:
                    self.add_arg("path", " ".join(path_parts))
                if recursive:
                    self.add_arg("recursive", True)


class LsCommand(CommandBase):
    cmd = "ls"
    needs_admin = False
    help_cmd = "ls [path] [-r]"
    description = "List files and directories. Results are displayed in the file browser."
    version = 2
    author = "@goultarde"
    supported_ui_features = ["file_browser:list"]
    argument_class = LsArguments
    attackmapping = ["T1083"]
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)
        path      = taskData.args.get_arg("path") or "."
        recursive = taskData.args.get_arg("recursive") or False
        response.DisplayParams = path
        if recursive:
            response.DisplayParams += " [-r]"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
