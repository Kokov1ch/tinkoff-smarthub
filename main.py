import requests
import sys
import base64
from enum import Enum


class CommandType(Enum):
    WHO_IS_HERE = 0x01
    I_AM_HERE = 0x02
    GET_STATUS = 0x03
    STATUS = 0x04
    SET_STATUS = 0x05
    TICK = 0x06


class DeviceType(Enum):
    SMARTHUB = 0x01
    ENV_SENSOR = 0x02
    SWITCH = 0x03
    LAMP = 0x04
    SOCKET = 0x05
    CLOCK = 0x06


class SensorType(Enum):
    TEMPERATURE = 0x01
    HUMIDITY = 0x02
    LIGHT = 0x04
    POLLUTION = 0x08


class SwitchProps(Enum):
    SWITCH_TOGGLE = 0b00000001
    CONDITION = 0b00000010
    TYPE = 0b00001100


class Payload:
    def __init__(self, src, dst, serial, dev_type, cmd, cmd_body):
        self.src = src
        self.dst = dst
        self.serial = serial
        self.dev_type = dev_type
        self.cmd = cmd
        self.cmd_body = cmd_body


class Packet:
    def __init__(self, length, payload, crc8):
        self.length = length
        self.payload = payload
        self.crc8 = crc8


class TimerCmdBody:
    def __init__(self, timestamp):
        self.timestamp = timestamp


class Trigger:
    def __init__(self, op=None, value=None, name=None):
        self.op = op
        self.value = value
        self.name = name


class Device:
    def __init__(self, dev_name, dev_props):
        self.dev_name = dev_name
        self.dev_props = dev_props


class DeviceInfo:
    def __init__(self, address, dev_name, dev_type):
        self.address = address
        self.dev_name = dev_name
        self.dev_type = dev_type


class DeviceState:
    def __init__(self):
        self.dev_name = ""
        self.src = 0
        self.serial = 0
        self.dev_type = 0
        self.broadcast = 0
        self.start_time = 0
        self.current_time = 0
        self.possible_delay = 0
        self.switch_connections = {}
        self.device_info_by_name = {}
        self.device_info_by_address = {}
        self.connection_states = {}
        self.device_states = {}
        self.sensors_info = {}
        self.last_message_sent = {}


class EnvSensorProps:
    def __init__(self, sensors=None, triggers=None):
        self.sensors = sensors
        self.triggers = triggers if triggers is not None else []


class EnvSensorStatusCmdBody:
    def __init__(self, values):
        self.values = values


class EnvSensorInfo:
    def __init__(self, available_sensors, triggers):
        self.available_sensors = available_sensors
        self.triggers = triggers


def main():
    error = False
    url = sys.argv[1]
    input_address = bytes(sys.argv[2], encoding='utf-8')
    address = int(input_address, 16)

    state = DeviceState()
    state.dev_name = "SMARTHUB"
    state.src = address
    state.serial = 0
    state.dev_type = DeviceType.SMARTHUB
    state.broadcast = 0x3FFF
    state.possible_delay = 300
    state.connection_states = {}
    state.device_info_by_name = {}
    state.switch_connections = {}
    state.device_states = {}
    state.sensors_info = {}
    state.last_message_sent = {}
    state.device_info_by_name = {}

    data = who_is_here(state)
    session = requests.Session()
    while True:
        encoded_data = encode(data)
        status_code, response, err = make_request(url, encoded_data, session)
        if err:
            error = True
            break

        if status_code != 200:
            if status_code != 204:
                error = True
            break
        data = handle_response(response, state)
    session.close()
    if error:
        sys.exit(99)


def make_request(url, data, session):
    try:
        response = session.post(url, data=data, verify=False)
        status_code = response.status_code
        response_data = response.content.decode('utf-8')
        return status_code, response_data, None
    except Exception as e:
        return None, None, e


def handle_response(response, state):
    data = b''

    decoded, error = decode(response)
    if error is not None:
        return b''

    index = 0
    while index < len(decoded):
        received_packet = decode_packet(decoded[index:])
        index += 2 + received_packet.length
        p = decode_payload(received_packet.payload)
        crc8 = calculate_crc8(received_packet.payload)

        if crc8 != received_packet.crc8:
            break

        if not is_connected(p.src, state) and p.cmd != CommandType.WHO_IS_HERE and p.cmd != CommandType.I_AM_HERE:
            continue

        if p.cmd == CommandType.WHO_IS_HERE or p.cmd == CommandType.I_AM_HERE:

            if p.cmd == CommandType.WHO_IS_HERE:
                data += i_am_here(state)

            if p.cmd == CommandType.I_AM_HERE and state.start_time + state.possible_delay < state.current_time:
                continue

            c = decode_device(p.cmd_body)
            device_info = DeviceInfo(address=p.src, dev_name=c.dev_name, dev_type=p.dev_type)
            connect(device_info, state)
            data += get_status(state, p.src, p.dev_type)

            if p.dev_type == DeviceType.SWITCH:
                props = decode_switch_dev_props(c.dev_props)
                connection = []

                for s in props:
                    connection.append(state.device_info_by_name[s])
                state.switch_connections[p.src] = connection

            elif p.dev_type == DeviceType.ENV_SENSOR:
                props = decode_env_sensor_props(c.dev_props)
                available_sensors = b''

                for i in range(1, 9):
                    if props.sensors & i > 0:
                        available_sensors += bytes([i])
                triggers = {}

                for trigger in props.triggers:
                    sensor = 1 << ((trigger.op & SwitchProps.TYPE) >> 2)
                    if sensor not in triggers:
                        triggers[sensor] = []
                    triggers[sensor].append(trigger)

                state.sensors_info[p.src] = EnvSensorInfo(available_sensors, triggers)
        elif p.cmd == CommandType.STATUS:
            should_track_delay = state.last_message_sent[p.src] != 0
            delay_exceeded = state.last_message_sent[p.src] + state.possible_delay < state.current_time

            if should_track_delay and delay_exceeded:
                disconnect(state.device_info_by_address[p.src], state)
                continue
            state.last_message_sent[p.src] = 0

            if p.dev_type == DeviceType.SWITCH:
                status = p.cmd_body[0]
                state.device_states[p.src] = status

                for device_info in state.switch_connections[p.src]:
                    data += set_status(state, device_info.address, device_info.dev_type, status)
            elif p.dev_type == DeviceType.ENV_SENSOR:
                count = int(p.cmd_body[0])
                body = p.cmd_body[1:]

                for i in range(count):
                    value, read_bytes = decode_varuint(body)
                    body = body[read_bytes:]
                    sensors_triggers = state.sensors_info[p.src]
                    sensor = sensors_triggers.available_sensors[i]

                    if sensor not in sensors_triggers.triggers:
                        continue
                    triggers = sensors_triggers.triggers[sensor]

                    for trigger in triggers:
                        if trigger.name not in triggers:
                            continue
                        target = state.device_info_by_name[trigger.name]
                        limit = trigger.value
                        status = trigger.op & SwitchProps.SWITCH_TOGGLE

                        if trigger.op & SwitchProps.CONDITION > 0 and value > limit:
                            set_status(state, target.address, target.dev_type, status)

                        if trigger.op & SwitchProps.CONDITION == 0 and value < limit:
                            set_status(state, target.address, target.dev_type, status)

        elif p.cmd == CommandType.TICK:
            c = decode_timer_cmd_body(p.cmd_body)

            if state.start_time == 0:
                state.start_time = c.timestamp
            state.current_time = c.timestamp
    return data


def encode(data):
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip("=")


def decode(encoded):
    try:
        decoded_bytes = base64.urlsafe_b64decode(encoded + "==")
        return decoded_bytes, None
    except Exception as e:
        return bytes(), e


def encode_varuint(value):
    bytes_list = []
    while True:
        byte_val = value & 0b01111111
        value >>= 7
        if value != 0:
            byte_val |= 0b10000000
        bytes_list.append(byte_val)
        if value == 0:
            break
    return bytes(bytes_list)


def decode_varuint(data):
    value = 0
    shift = 0
    read_bytes = 0
    for byte_val in data:
        value |= (byte_val & 0b01111111) << shift
        shift += 7
        read_bytes += 1
        if (byte_val & 0b10000000) == 0:
            break
    return value, read_bytes


def encode_string(value):
    length = len(value)
    result = bytes([length])
    result += bytes(value, encoding='utf-8')
    return result


def decode_string(data):
    length = data[0]
    value = data[1:1 + length].decode('utf-8')
    read = 1 + length
    return value, read


def who_is_here(state):
    cmd_body = Device(dev_name=state.dev_name, dev_props=b'')

    payload = Payload(
        src=state.src,
        dst=state.broadcast,
        serial=increment_serial(state),
        dev_type=state.dev_type,
        cmd=CommandType.WHO_IS_HERE,
        cmd_body=encode_device(cmd_body),
    )

    encoded_payload = encode_payload(payload)
    packet = Packet(
        length=len(encoded_payload),
        payload=encoded_payload,
        crc8=calculate_crc8(encoded_payload),
    )
    encoded_packet = encode_packet(packet)
    return encoded_packet


def i_am_here(state):
    cmd_body = Device(dev_name=state.dev_name, dev_props=b'')

    payload = Payload(
        src=state.src,
        dst=state.broadcast,
        serial=increment_serial(state),
        dev_type=state.dev_type,
        cmd=CommandType.I_AM_HERE,
        cmd_body=encode_device(cmd_body),
    )

    encoded_payload = encode_payload(payload)
    packet = Packet(
        length=len(encoded_payload),
        payload=encoded_payload,
        crc8=calculate_crc8(encoded_payload),
    )
    encoded_packet = encode_packet(packet)
    return encoded_packet


def get_status(state, dst, dev_type):
    if not is_connected(dst, state):
        return b''

    state.last_message_sent[dst] = state.current_time
    payload = Payload(
        src=state.src,
        dst=dst,
        serial=increment_serial(state),
        dev_type=dev_type,
        cmd=CommandType.GET_STATUS,
        cmd_body=bytes()
    )
    encoded_payload = encode_payload(payload)
    return create_encoded_packet(encoded_payload)


def set_status(state, dst, dev_type, status):
    if not is_connected(dst, state):
        return b''

    state.last_message_sent[dst] = state.current_time
    payload = Payload(
        src=state.src,
        dst=dst,
        serial=increment_serial(state),
        dev_type=dev_type,
        cmd=CommandType.SET_STATUS,
        cmd_body=bytes([status]),
    )
    encoded_payload = encode_payload(payload)
    return create_encoded_packet(encoded_payload)


def increment_serial(state):
    serial = state.serial
    state.serial += 1
    return serial


def decode_switch_dev_props(props):
    length = int(props[0])
    result = []
    props = props[1:]
    for i in range(length):
        str_value, read = decode_string(props)
        result.append(str_value)
        props = props[read:]
    return result


def decode_env_sensor_props(data):
    props = EnvSensorProps()
    props.sensors = data[0]
    triggers_length = int(data[1])
    props.triggers = []
    data = data[2:]
    for i in range(triggers_length):
        trigger = Trigger()
        trigger.op = data[0]
        data = data[1:]
        trigger.value, read_bytes = decode_varuint(data)
        data = data[read_bytes:]
        trigger.name, read_bytes = decode_string(data)
        data = data[read_bytes:]
        props.triggers.append(trigger)
    return props


def create_encoded_packet(encoded_payload):
    packet = Packet(
        length=len(encoded_payload),
        payload=encoded_payload,
        crc8=calculate_crc8(encoded_payload),
    )
    return encode_packet(packet)


def is_connected(src, state):
    return state.connection_states.get(src, False)


def connect(info, state):
    state.connection_states[info.address] = True
    state.device_info_by_name[info.dev_name] = info
    state.device_info_by_address[info.address] = info


def disconnect(info, state):
    state.connection_states[info.address] = False
    if info.dev_name in state.device_info_by_name:
        del state.device_info_by_name[info.dev_name]
    if info.address in state.device_info_by_address:
        del state.device_info_by_address[info.address]


def calculate_crc8(data):
    generator = 0x1D
    crc = 0x0

    for currByte in data:
        crc ^= currByte

        for _ in range(8):
            if crc & 0x80 != 0:
                crc = ((crc << 1) ^ generator)
            else:
                crc <<= 1

    return crc & 0xFF  # Ensure that the result is an 8-bit value


def decode_timer_cmd_body(data):
    value, _ = decode_varuint(data)
    return TimerCmdBody(timestamp=value)


def encode_packet(data):
    result = bytes([data.length])
    result += data.payload
    crc8 = data.crc8 & 0xFF
    result += bytes([crc8])
    return result


def decode_packet(data):
    length = data[0]
    return Packet(
        length=length,
        payload=data[1:length + 1],
        crc8=data[length + 1],
    )


def encode_payload(data):
    result = encode_varuint(data.src)
    result += encode_varuint(data.dst)
    result += encode_varuint(data.serial)
    result += bytes([data.dev_type.value])
    result += bytes([data.cmd.value])
    result += data.cmd_body
    return result


def decode_payload(data):
    index = 0
    src_decoded, read_bytes = decode_varuint(data)
    index += read_bytes
    dst_decoded, read_bytes = decode_varuint(data[index:])
    index += read_bytes
    serial_decoded, read_bytes = decode_varuint(data[index:])
    index += read_bytes

    return Payload(
        src=src_decoded,
        dst=dst_decoded,
        serial=serial_decoded,
        dev_type=data[index],
        cmd=data[index + 1],
        cmd_body=data[index + 2:],
    )


def encode_device(device):
    result = encode_string(device.dev_name)
    result += device.dev_props
    return result


def decode_device(data):
    dev_name, read = decode_string(data)
    return Device(dev_name=dev_name, dev_props=data[read:])


if __name__ == "__main__":
    main()
