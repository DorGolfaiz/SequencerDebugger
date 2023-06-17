from debug_adapter import utils
import json


class Command:
    """
    Command represents command received from the debugger,
    """
    next_seq = 0  # sequence numbers

    _showing_debug_info = 0

    def __init__(self, seq, text, is_json=False):
        """
        If sequence is 0, new sequence will be generated (otherwise, this was the response
        to a command from the client).
        """
        if seq == 0:
            Command.next_seq += 2
            seq = Command.next_seq

        self.seq = seq

        if is_json:
            if hasattr(text, 'to_dict'):
                as_dict = text.to_dict(update_ids_to_dap=True)
            else:
                assert isinstance(text, dict)
                as_dict = text
            as_dict['seq'] = seq
            self.as_dict = as_dict
            text = json.dumps(as_dict)

        assert isinstance(text, str)

        if is_json:
            msg = text
        else:
            encoded = utils.quote_smart(utils.to_string(text), '/<>_=" \t')
            msg = f'{seq}\t{encoded}\n'

        if isinstance(msg, str):
            msg = msg.encode('utf-8')

        assert isinstance(msg, bytes)
        self._as_bytes = msg

    def as_bytes(self):
        return self._as_bytes
