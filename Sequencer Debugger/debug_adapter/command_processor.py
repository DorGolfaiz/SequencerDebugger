import os
import sys
import json
from debug_adapter import schema, base_schema, utils
from debug_adapter.command import Command
from debugger.debugger_utils import State
from debug_adapter.log import debug, debug_exception
from pathlib import Path

class CommandProcessor(object):
    """
    This is the class that actually processes commands.

    It's created in the main thread and then control is passed on to the reader thread so that whenever
    something is read the json is handled by this processor.

    The queue it receives in the constructor should be used to talk to the writer thread, where it's expected
    to post protocol messages (which will be converted with 'to_dict()' and will have the 'seq' updated as
    needed).
    """

    def __init__(self, from_json):
        self.from_json = from_json
        self._launch_request_done = False

    def on_initialize_request(self, main_db, request):
        body = schema.Capabilities(
            # Supported.
            supportsConfigurationDoneRequest=True,
            supportsConditionalBreakpoints=True,
            supportsSetVariable=True,
            supportsModulesRequest=True,
            supportsValueFormattingOptions=True,
            supportsReadMemoryRequest=True,
            supportTerminateDebuggee=True,
            supportsDelayedStackTraceLoading=True,
            supportsLogPoints=False,
            supportsSetExpression=True,
            supportsTerminateRequest=True,
            exceptionBreakpointFilters=[],
            supportsClipboardContext=True,
            # Not supported.
            supportsRestartRequest=False,
            supportsBreakpointLocationsRequest=False,
            supportsDataBreakpoints=False,
            supportsHitConditionalBreakpoints=False,
            supportsExceptionInfoRequest=False,
            supportsExceptionOptions=False,
            supportsCompletionsRequest=False,
            supportsEvaluateForHovers=False,
            supportsGotoTargetsRequest=False,
            supportsFunctionBreakpoints=False,
            supportsStepBack=False,
            supportsRestartFrame=False,
            supportsStepInTargetsRequest=False,
            supportsLoadedSourcesRequest=False,
            supportsTerminateThreadsRequest=False,
            supportsDisassembleRequest=False,
            supportsSteppingGranularity=False,
            additionalModuleColumns=[],
            completionTriggerCharacters=[],
            supportedChecksumAlgorithms=[]).to_dict()
        initialize_response = schema.InitializeResponse(request.seq, True, request.command, body=body)
        initialize_response = Command(0, initialize_response, True)

        # Not regular return because initialized event should be sent ASAP ,
        # see - https://github.com/Microsoft/vscode/issues/4902
        self._send_initialize_response_and_event(initialize_response, main_db)
        return None

    def on_launch_request(self, main_db, request):
        req_dict = request.to_dict()
        prog_to_run = req_dict['arguments']['program']
        device_to_debug = req_dict['arguments']['device_model']
        
        main_db.rec_api_dll_path = Path(req_dict['arguments']['RecAPI'])
        main_db.db_folder_path = Path(req_dict['arguments']['vayyarDB'])
        main_db.version = req_dict['arguments']['version']
        if req_dict['arguments']['vayyar_config'] != 'No':
            main_db.vayyar_config = Path(req_dict['arguments']['vayyar_config'])


        main_db.initialize_debugger_api()
        main_db.verify_all_files_exist_and_legal(prog_to_run)
        main_db.set_device_to_debug(device_to_debug)
        main_db.initialize_debugger()


        self._send_process_event(main_db)

        self._launch_request_done = True
        response = schema.LaunchResponse(request.seq, True, request.command)
        self.launch_response = Command(0, response, is_json=True)
        return None

    def _send_initialize_response_and_event(self, initialize_response, main_db):
        initialized_event = Command(0, schema.InitializedEvent(), True)
        main_db.writer.add_command(initialize_response)
        main_db.writer.add_command(initialized_event)

    def _send_process_event(self, main_db):
        if len(sys.argv) > 0:
            name = sys.argv[0]
        else:
            name = ''

        if isinstance(name, bytes):
            file_system_encoding = utils.get_filesystem_encoding()
            name = name.decode(file_system_encoding, 'replace')
            name = name.encode('utf-8')

        body = schema.ProcessEventBody(
            name=name,
            systemProcessId=os.getpid(),
            isLocalProcess=True,
            startMethod='launch',
        )
        event = schema.ProcessEvent(body)
        cmd = Command(0, event, is_json=True)
        main_db.writer.add_command(cmd)

    def on_setbreakpoints_request(self, main_db, request):
        arguments = request.arguments  # : :type arguments: SetBreakpointsArguments
        source_code = arguments.source.path

        main_db.prog_txt = source_code
        main_db.debugger_api.remove_all_breakpoints(main_db.device)

        breakpoints_set = []

        for source_breakpoint in arguments.breakpoints:
            source_breakpoint = schema.SourceBreakpoint(**source_breakpoint)
            line = source_breakpoint.line
            condition = source_breakpoint.condition
            breakpoint_id = line

            res = main_db.debugger_api.insert_breakpoint(main_db.device, line, code_line_relates_to_code_txt=True)
            if res:
                breakpoints_set.append(
                    schema.Breakpoint(verified=True, id=line, line=line, source=arguments.source).to_dict())
            else:
                breakpoints_set.append(
                    schema.Breakpoint(verified=False, id=line, message="Can't Breakpoint on [RET] or [JMP] ",
                                      line=line, source=arguments.source).to_dict())

        body = schema.SetBreakpointsResponseBody(breakpoints_set)
        set_breakpoints_response = schema.SetBreakpointsResponse(request.seq, True, request.command, body=body)
        return Command(0, set_breakpoints_response, is_json=True)

    def on_configurationdone_request(self, main_db, request):
        """
        :param ConfigurationDoneRequest request:
        """
        configuration_done_response = schema.ConfigurationDoneResponse(request.seq, True, request.command)
        main_db.writer.add_command(Command(0, configuration_done_response, is_json=True))
        main_db.writer.add_command(self.launch_response)
        main_db.start_debug_prog()
        return None

    def on_threads_request(self, main_db, request):
        threads = []
        main_thread = utils.get_main_thread()
        thread_schema = schema.Thread(id=utils.get_thread_unique_id(main_thread),
                                      name=utils.get_thread_name(main_thread))
        threads.append(thread_schema.to_dict())
        body = schema.ThreadsResponseBody(threads)
        response = schema.ThreadsResponse(request_seq=request.seq, success=True, command='threads', body=body)
        return Command(0, response, is_json=True)

    def on_continue_request(self, main_db, request):
        """
        :param ContinueRequest request:
        """
        arguments = request.arguments  # : :type arguments: ContinueArguments
        thread_id = arguments.threadId
        main_db.debugger_api.remove_all_stepping_breakpoints(main_db.device)
        main_db.debugger_api.release_breakpoint(main_db.device)
        main_db.state = State.Running
        body = schema.ContinuedEventBody(threadId=thread_id, allThreadsContinued=True)
        response = schema.ContinuedEvent(body, request.seq)
        cmd = Command(0, response, is_json=True)

        return cmd

    def on_next_request(self, main_db, request):
        """
        :param NextRequest request:
        """
        arguments = request.arguments  # : :type arguments: NextArguments
        thread_id = arguments.threadId
        response = schema.NextResponse(request.seq, True, request.command)
        main_db.writer.add_command(Command(0, response, is_json=True))
        main_db.debugger_api.step(main_db.device, step_type='next')
        self._send_stopped_event(main_db, 'step')

    def on_stepin_request(self, main_db, request):
        """
        :param StepInRequest request:
        """
        arguments = request.arguments  # : :type arguments: NextArguments
        thread_id = arguments.threadId
        response = schema.StepInResponse(request.seq, True, request.command)
        main_db.writer.add_command(Command(0, response, is_json=True))
        main_db.debugger_api.step(main_db.device, step_type='in')
        self._send_stopped_event(main_db, 'step')

    def on_stepout_request(self, main_db, request):
        """
        :param StepOutRequest request:
        """
        arguments = request.arguments  # : :type arguments: NextArguments
        thread_id = arguments.threadId
        response = schema.StepOutResponse(request.seq, True, request.command)
        main_db.writer.add_command(Command(0, response, is_json=True))
        main_db.debugger_api.step(main_db.device, step_type='out')
        self._send_stopped_event(main_db, 'step')

    def on_stacktrace_request(self, main_db, request):
        """
        :param StackTraceRequest request:
        """
        # : :type stack_trace_arguments: StackTraceArguments
        stack_trace_arguments = request.arguments
        thread_id = stack_trace_arguments.threadId
        start_frame = stack_trace_arguments.startFrame
        levels = stack_trace_arguments.levels

        stack_frames = []
        debugger_stack_frames = main_db.debugger_api.get_stack_frames(main_db.device)
        for frame in debugger_stack_frames[start_frame:start_frame + levels]:
            frame_id = frame.txt_code_line
            frame_name = frame.func_scope_obj.name
            # TODO: mapping first thing?
            f_line = frame.txt_code_line
            f_column = 1
            f_source = {
                'name': '',  # frame.func_scope
                'path': main_db.prog_txt,
                'sourceReference': 0
            }

            stack_frame = schema.StackFrame(id=frame_id, name=frame_name, line=f_line, column=f_column, source=f_source)
            stack_frames.append(stack_frame)

        total_frames = len(stack_frames)

        response = schema.StackTraceResponse(
            request_seq=request.seq,
            success=True,
            command='stackTrace',
            body=schema.StackTraceResponseBody(stackFrames=stack_frames, totalFrames=total_frames))
        return Command(0, response, is_json=True)

    def on_scopes_request(self, main_db, request):
        arguments = request.arguments
        dap_frame_id = int(arguments.frameId)
        frame_id = arguments._dap_id_to_obj_id[dap_frame_id]

        variables_scope = schema.Scope(name='Arguments', variablesReference=frame_id, expensive=False)

        scopes = [variables_scope]

        body = schema.ScopesResponseBody(scopes)
        response = schema.ScopesResponse(request.seq, True, request.command, body)
        return Command(0, response, is_json=True)

    def on_variables_request(self, main_db, request):
        arguments = request.arguments  # : :type arguments: VariablesArguments
        dap_frame_id = arguments.variablesReference
        variables_id = arguments._dap_id_to_obj_id[dap_frame_id]
        variables = []
        stack_frame_variables = main_db.debugger_api.get_stack_frame_variables(main_db.device, variables_id)
    
        if main_db.debugger_api.obj_is_StackFrameVariable_list(stack_frame_variables):
            for v in stack_frame_variables:
                if v.variable_obj:
                    display_name = v.variable_obj.__name__
                    variable_id = v.id
                else:
                    display_name = 'InValid Register'
                    variable_id = 0
                variables.append(schema.Variable(v.name, display_name, variable_id))

        # single variable (param/reg/fields)
        else:
            main_db.device.sequencer.access_memory(host=True)
            obj = stack_frame_variables

            if main_db.debugger_api.obj_is_Param(obj) or main_db.debugger_api.obj_is_RxMemReg(obj):
                variables.append(schema.Variable(obj.__name__, str(obj.Read()), 0))

            elif main_db.debugger_api.obj_is_Reg(obj):
                variables.append(schema.Variable('value', str(obj.Read()), 0))
                variables.append(schema.Variable('addr', hex(obj._addr), 0))
                variables.append(schema.Variable('access', obj.access, 0))
                variables.append(schema.Variable('description', obj.description, 0))
                variables.append(schema.Variable('fields', '', id(obj.fields)))
            elif main_db.debugger_api.obj_is_RegField_list(obj):
                for field in obj:
                    name = field.__name__
                    field_id = id(field)
                    variables.append(schema.Variable(name, '', field_id))

            elif main_db.debugger_api.obj_is_RegField(obj):
                variables.append(schema.Variable('value', str(obj.GetValue()), 0))
                variables.append(schema.Variable('description', obj.description, 0))
                variables.append(schema.Variable('bitOffset', str(obj.bitOffset), 0))
                variables.append(schema.Variable('bitWidth', str(obj.bitWidth), 0))
                variables.append(schema.Variable('enumValues', str(obj.enumValues), 0))


            else:
                pass
            main_db.device.sequencer.access_memory(host=False)

        body = schema.VariablesResponseBody(variables)
        response = schema.VariablesResponse(request.seq, True, request.command, body)
        return Command(0, response, is_json=True)

    def on_setvariable_request(self, main_db, request):
        arguments = request.arguments  # : :type arguments: VariablesArguments
        variable_ref = arguments.variablesReference
        container_variable_id = arguments._dap_id_to_obj_id[variable_ref]

        variable_name = arguments.name
        desired_val = arguments.value

        obj = main_db.debugger_api.get_stack_frame_variables(main_db.device, container_variable_id)
        main_db.device.sequencer.access_memory(host=True)
        if main_db.debugger_api.obj_is_StackFrameVariable_list(obj):
            sf_variable = [sf for sf in obj if sf.name == variable_name][0]
            value = sf_variable.variable_obj.__name__  # current value
            var_ref = sf_variable.id

        elif main_db.debugger_api.obj_is_Param(obj) or main_db.debugger_api.obj_is_RxMemReg(obj):
            try:
                obj.Write(int(desired_val))
                value = desired_val
            except:
                value = obj.Value
            var_ref = 0

        elif main_db.debugger_api.obj_is_Reg(obj):

            if variable_name == 'value':
                try:
                    obj.Write(int(desired_val))
                    value = desired_val
                except:
                    value = obj.Value
                var_ref = 0
            elif variable_name == 'addr':
                value = hex(obj._addr)
                var_ref = 0
            elif variable_name == 'access' or variable_name == 'description':
                value = obj.__getattribute__(variable_name)
                var_ref = 0
            elif variable_name == 'fields':
                value = ''
                var_ref = id(obj.fields)

        elif main_db.debugger_api.obj_is_RegField_list(obj):
            value = ''
            var_ref = id([field for field in obj if field.__name__ == variable_name][0])

        elif main_db.debugger_api.obj_is_RegField(obj):
            if variable_name == 'value':
                try:
                    obj.SetValue(int(desired_val))
                    value = desired_val
                except:
                    value = obj.Value
            else:
                value = obj.__getattribute__(variable_name)
            var_ref = 0

        else:
            pass
        main_db.device.sequencer.access_memory(host=False)
        body = schema.SetVariableResponseBody(str(value), variablesReference=var_ref)
        response = schema.SetVariableResponse(request.seq, True, request.command, body)
        return Command(0, response, is_json=True)

    def on_terminate_request(self, main_db, request):
        """
        :param TerminateRequest request:
        """
        main_db.debugger_api.stop_debugging(main_db.device)
        response = schema.TerminateResponse(request.seq, True, request.command)
        main_db.writer.add_command(Command(0, response, is_json=True))
        self.handle_termination_event(main_db)

    def on_disconnect_request(self, main_db, request):
        main_db.debugger_api.stop_debugging(main_db.device)
        response = schema.DisconnectResponse(request.seq, True, request.command)
        main_db.writer.add_command(Command(0, response, is_json=True))
        self.handle_termination_event(main_db)

    def process_command(self, main_db, json_contents, send_response=True):
        """
        Processes a debug adapter protocol json command.
        """

        try:
            # debug(f'process_command : \n  json_contents : {json_contents} \n')
            if isinstance(json_contents, bytes):
                json_contents = json_contents.decode('utf-8')

            request = self.from_json(json_contents)
        except Exception as e:
            try:
                loaded_json = json.loads(json_contents)
                request = schema.Request(loaded_json.get('command', '<unknown>'), loaded_json['seq'])
            except:
                # There's not much we can do in this case...
                debug_exception(f'Error loading json: {json_contents}')
                return

            error_msg = str(e)
            if error_msg.startswith("'") and error_msg.endswith("'"):
                error_msg = error_msg[1:-1]

            # This means a failure processing the request (but we were able to load the seq,
            # so, answer with a failure response).
            def on_request(main_db, request):
                error_response = {
                    'type': 'response',
                    'request_seq': request.seq,
                    'success': False,
                    'command': request.command,
                    'message': error_msg,
                }
                return Command(0, error_response)

        else:
            debug(f'Process {request.__class__.__name__}  :  {json.dumps(request.to_dict(), indent=4, sort_keys=True)}')
            assert request.type == 'request'
            method_name = f'on_{request.command.lower()}_request'
            on_request = getattr(self, method_name, None)
            if on_request is None:
                debug(f'\n Unhandled: {method_name} not available in CommandProcessor.\n')
                return

            else:
                debug(f'\n Handled: {method_name}  in CommandProcessor \n')

        with main_db._main_lock:
            debug(f'Processing command-function : {on_request}')
            cmd = on_request(main_db, request)
            if cmd is not None and send_response:
                main_db.writer.add_command(cmd)

    def _send_stopped_event(self, main_db, stop_reason):

        desc = f'Paused on {stop_reason}'
        thread_id = utils.get_thread_unique_id(utils.get_main_thread())

        preserve_focus_hint = stop_reason not in ['step', 'exception', 'breakpoint', 'entry', 'goto']

        body = schema.StoppedEventBody(
            reason=stop_reason,
            description=desc,
            threadId=thread_id,
            preserveFocusHint=preserve_focus_hint,
            text='stopped',
            allThreadsStopped=True)
        event = schema.StoppedEvent(body)
        main_db.writer.add_command(Command(0, event, is_json=True))

    def on_evaluate_request(self, main_db, request):
        """
        :param EvaluateRequest request:
        """
        # : :type arguments: EvaluateArguments
        arguments = request.arguments
        result = 'What do you want from me ?'
        if arguments.context == 'repl':
            # Value assignment
            if '=' in arguments.expression:
                addr, new_val = arguments.expression.split('=')
                result = main_db.debugger_api.write_memory_repl(main_db.device, addr, new_val)
                response_msg = f'New Value in {addr} is : {result}'
            # Value read
            else:
                result = main_db.debugger_api.read_memory_repl(main_db.device, arguments.expression)
                response_msg = f'Value in {arguments.expression} is : {result}'

            body = schema.EvaluateResponseBody(response_msg, 0)
            response = schema.EvaluateResponse(request.seq, success=True, command=request.command, body=body)

            return Command(0, response, is_json=True)

        elif arguments.context == 'watch':
            addr_to_watch = arguments.expression
            sf_variable = main_db.debugger_api.get_watched_variable(main_db.device, addr_to_watch)
            if sf_variable:
                body = schema.EvaluateResponseBody(sf_variable.variable_obj.__name__, sf_variable.id)
            else:
                body = schema.EvaluateResponseBody('Invalid Watch', 0)
            response = schema.EvaluateResponse(request.seq, success=True, command=request.command, body=body)

            return Command(0, response, is_json=True)

        elif arguments.context == 'hover':
            pass

    # maybe exited

    def handle_termination_event(self, main_db, output_msg=None):
        if output_msg:
            self._send_output_event(main_db, str(output_msg))
        body = schema.TerminatedEventBody()
        event = schema.TerminatedEvent(body=body)
        main_db.writer.add_command(Command(0, event, is_json=True))

    def _send_output_event(self, main_db, output_str):
        body = schema.OutputEventBody(output_str, 'console')
        event = schema.OutputEvent(body)
        main_db.writer.add_command(Command(0, event, is_json=True))
