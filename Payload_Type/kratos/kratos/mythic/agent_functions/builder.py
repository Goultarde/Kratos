import logging
import pathlib
from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
import asyncio
import tempfile
from distutils.dir_util import copy_tree
import json

class Kratos(PayloadType):
    name = "kratos"
    file_extension = "exe"
    author = "@goultarde"
    supported_os = [SupportedOS.Windows]
    wrapper = False
    wrapped_payloads = []
    note = "A simple C agent named Kratos."
    supports_dynamic_loading = True
    mythic_encrypts = False
    c2_profiles = ["http"]
    build_parameters = [
        BuildParameter(
            name="debug",
            parameter_type=BuildParameterType.Boolean,
            default_value=False,
            description="Enable debug output"
        )
    ]
    agent_path = pathlib.Path(".") / "kratos" / "mythic"
    agent_code_path = pathlib.Path(".") / "kratos" / "agent_code"
    agent_icon_path = agent_path / "agent_functions" / "kratos.svg"

    build_steps = [
        BuildStep(step_name="Gathering Files", step_description="Copying agent code to build directory"),
        BuildStep(step_name="Configuring", step_description="Stamping in configuration values"),
        BuildStep(step_name="Compiling", step_description="Compiling the agent"),
    ]

    async def build(self) -> BuildResponse:
        resp = BuildResponse(status=BuildStatus.Success)
        
        # 1. Gathering Files
        try:
            agent_build_path = tempfile.TemporaryDirectory(suffix=self.uuid)
            copy_tree(str(self.agent_code_path), agent_build_path.name)
            
            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Gathering Files",
                StepStdout="Copied agent code",
                StepSuccess=True
            ))

            # 2. Configuring
            # Parse C2 profile
            c2_profile = self.c2info[0]
            c2_conf = c2_profile.get_parameters_dict()
            
            # Simple config stamping
            # specific for http profile
            callback_host = c2_conf.get("callback_host", "http://127.0.0.1")
            callback_port = c2_conf.get("callback_port", 80)
            callback_interval = c2_conf.get("callback_interval", 10)
            post_uri = c2_conf.get("post_uri", "/api/v1.4/agent_message")
            if not post_uri.startswith("/"):
                post_uri = "/" + post_uri
            
            # User Agent extraction
            headers = c2_conf.get("headers", {})
            user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
            if isinstance(headers, dict):
                 user_agent = headers.get("User-Agent", user_agent)

            is_debug = self.get_parameter("debug")
            debug_val = 1 if is_debug else 0

            # Read the template config.h file
            config_path = pathlib.Path(agent_build_path.name) / "config.h"
            with open(config_path, "r") as f:
                config_content = f.read()
            
            # Perform replacements (Xenon Style) - Handle potential spaces
            config_content = config_content.replace("%AGENT_UUID%", self.uuid).replace("% AGENT_UUID %", self.uuid)
            config_content = config_content.replace("%CALLBACK_HOST%", callback_host).replace("% CALLBACK_HOST %", callback_host)
            config_content = config_content.replace("%CALLBACK_PORT%", str(callback_port)).replace("% CALLBACK_PORT %", str(callback_port))
            config_content = config_content.replace("%POST_URI%", post_uri).replace("% POST_URI %", post_uri)
            config_content = config_content.replace("%USER_AGENT%", user_agent).replace("% USER_AGENT %", user_agent)
            config_content = config_content.replace("%SLEEP_TIME%", str(callback_interval)).replace("% SLEEP_TIME %", str(callback_interval))
            config_content = config_content.replace("%DEBUG_VAL%", str(debug_val)).replace("% DEBUG_VAL %", str(debug_val))

            # Write the patched content back
            with open(config_path, "w") as f:
                f.write(config_content)

            # 3. Compiling
            
            # Construct command defines based on selected commands
            command_defines = ""
            # self.commands.get_commands() returns a list of command names included in the payload
            for cmd in self.commands.get_commands():
                # cmd is the command name (e.g. "ls")
                command_defines += f"-D INCLUDE_CMD_{cmd.upper()} "
                
            # Log the defines for debugging
            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Configuring",
                StepStdout=f"Command Defines: {command_defines}",
                StepSuccess=True
            ))

            # Pass CFLAGS to make
            command = f"make CC=x86_64-w64-mingw32-gcc CFLAGS=\"{command_defines}\""
            
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=agent_build_path.name
            )
            stdout, stderr = await proc.communicate()
            
            if proc.returncode != 0:
                resp.status = BuildStatus.Error
                resp.build_stderr = stderr.decode()
                resp.build_message = "Compilation failed"
                await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="Compiling",
                    StepStdout=stdout.decode() + "\n" + stderr.decode(),
                    StepSuccess=False
                ))
                return resp

            resp.payload = open(pathlib.Path(agent_build_path.name) / "kratos.exe", "rb").read()
            resp.updated_filename = self.filename
            resp.build_message = "Successfully built Kratos agent"
            resp.status = BuildStatus.Success
            
            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Compiling",
                StepStdout=stdout.decode(),
                StepSuccess=True
            ))

        except Exception as e:
            resp.status = BuildStatus.Error
            resp.build_stderr = str(e)
            resp.build_message = "Error invoking build: " + str(e)
        
        return resp
