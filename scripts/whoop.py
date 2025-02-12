import sys, argparse, asyncio
from packet import *
from bleak import BleakClient, BleakScanner

WHOOP_SERVICE = "61080001-8d6d-82b8-614a-1c8cb0f8dcc6"
WHOOP_CHAR_CMD_TO_STRAP = "61080002-8d6d-82b8-614a-1c8cb0f8dcc6"
WHOOP_CHAR_CMD_FROM_STRAP = "61080003-8d6d-82b8-614a-1c8cb0f8dcc6"
WHOOP_CHAR_EVENTS_FROM_STRAP = "61080004-8d6d-82b8-614a-1c8cb0f8dcc6"
WHOOP_CHAR_DATA_FROM_STRAP = "61080005-8d6d-82b8-614a-1c8cb0f8dcc6"
WHOOP_CHAR_MEMFAULT = "61080007-8D6D-82B8-614A-1C8CB0F8DCC6"

cmdresp = asyncio.Queue()
meta_queue = asyncio.Queue()
verbose = False
fp = open("whoop_hist.bin", "wb")
logsfp = open("logs.bin", "ab")

async def cmd_handler(sender, data):
    packet = WhoopPacket.from_data(data)
    await cmdresp.put(packet)

    if verbose:
        print(f"cmd: {data.hex()}")
        print(packet)

def events_handler(sender, data):
    try:
        packet = WhoopPacket.from_data(data)
    except:
        print("events exception")
        return

    if verbose:
        print(f"events: {data.hex()}")
        print(packet)

async def data_handler(sender, data):
    packet = WhoopPacket.from_data(data)

    if verbose:
        print(f"data: {data.hex()}")
        print(packet)

    # write this to disk
    if packet.type == PacketType.HISTORICAL_DATA:
        fp.write(data)
        fp.flush()
        #print(packet)

    if packet.type == PacketType.METADATA:
        print(packet)
        await meta_queue.put(packet)
    
    if packet.type == PacketType.CONSOLE_LOGS:
        logsfp.write(packet.__str__().encode().replace(b"\x34\x00\x01", b""))
        logsfp.flush()

def memfault_handler(sender, data):
    #print(f"memfault: {data.hex()}")
    pass

#pkt = WhoopPacket(PacketType.COMMAND, 10, CommandNumber.GET_HELLO_HARVARD, data=b"\x00").framed_packet()
#aa8c004a2419230a0104ba02000000eedf6e67a0680000344331383635323239006233636265376430373232323366393138666261623236666536643061393962666236643932656634393436663231653930623031340600000002000000100000002900000010000000060000000000000008020100000000000011000000020000000200000000000000c3425a4e

running = True

from prompt_toolkit import prompt
from prompt_toolkit.history import InMemoryHistory
command_history = InMemoryHistory()
def get_input():
    user_input = prompt("> ", history=command_history)
    return user_input.strip().lower()

async def command_listener(client):
    global history_index, verbose, running
    
    while running:
        command = await asyncio.to_thread(get_input)
        #command = (await asyncio.to_thread(input, "> ")).strip().lower()
        if command:
            command_history.append_string(command)
        if command == "startreal":
            pkt = WhoopPacket(PacketType.COMMAND, 10, CommandNumber.TOGGLE_REALTIME_HR, data=b"\x01").framed_packet()
            await client.write_gatt_char(WHOOP_CHAR_CMD_TO_STRAP, pkt)
        elif command == "stopreal":
            pkt = WhoopPacket(PacketType.COMMAND, 10, CommandNumber.TOGGLE_REALTIME_HR, data=b"\x00").framed_packet()
            await client.write_gatt_char(WHOOP_CHAR_CMD_TO_STRAP, pkt)
        elif command == "clock":
            pkt = WhoopPacket(PacketType.COMMAND, 10, CommandNumber.GET_CLOCK, data=b"\x00").framed_packet()
            await client.write_gatt_char(WHOOP_CHAR_CMD_TO_STRAP, pkt)
        elif command == "ghr_on":
            pkt = WhoopPacket(PacketType.COMMAND, 10, CommandNumber.TOGGLE_GENERIC_HR_PROFILE, data=b"\x01").framed_packet()
            await client.write_gatt_char(WHOOP_CHAR_CMD_TO_STRAP, pkt)
        elif command == "ghr_off":
            pkt = WhoopPacket(PacketType.COMMAND, 10, CommandNumber.TOGGLE_GENERIC_HR_PROFILE, data=b"\x00").framed_packet()
            await client.write_gatt_char(WHOOP_CHAR_CMD_TO_STRAP, pkt)
        elif command == "battery":
            pkt = WhoopPacket(PacketType.COMMAND, 10, CommandNumber.GET_BATTERY_LEVEL, data=b"\x00").framed_packet()
            print(pkt.hex())
            await client.write_gatt_char(WHOOP_CHAR_CMD_TO_STRAP, pkt)
            pkt = await cmdresp.get()
            print(pkt)
        elif command == "version":
            # aa50000c24b8070a0101290000001000000006000000000000001100000002000000020000000000000003000000050000000000000000000000030000000c00000001000000000000000802010000002006f9a7
            # aa50000c24b9070a0101290000001000000006000000000000001100000002000000020000000000000003000000050000000000000000000000030000000c0000000100000000000000080201000000bdc1a75b
            # aa50000c24ba070a0101290000001000000006000000000000001100000002000000020000000000000003000000050000000000000000000000030000000c00000001000000000000000802010000005b8f3584
            pkt = WhoopPacket(PacketType.COMMAND, 10, CommandNumber.REPORT_VERSION_INFO, data=b"\x00").framed_packet()
            await client.write_gatt_char(WHOOP_CHAR_CMD_TO_STRAP, pkt)
            pkt = await cmdresp.get()
            print(pkt)
        elif command == "force":
            # from https://github.com/bWanShiTong/reverse-engineering-whoop-post/blob/master/README.md#erase-device
            hex_strings = [
                "aa10005723cf19fefefefefefefefe002f8744f6",
                "aa10005723d219fefefefefefefefe00e30e2693",
                "aa10005723d319fefefefefefefefe0023d1a852"
            ]

            for s in hex_strings:
                data = bytes.fromhex(s)

                pkt = WhoopPacket(PacketType.COMMAND, 10, CommandNumber.FORCE_TRIM, data=data).framed_packet()
                await client.write_gatt_char(WHOOP_CHAR_CMD_TO_STRAP, data)

        elif command == "test":
            
            verbose = True
            # pkt = WhoopPacket(PacketType.COMMAND, 10, CommandNumber.RUN_HAPTICS_PATTERN, data=b"\x00").framed_packet()
            # pkt = WhoopPacket(PacketType.COMMAND, 10, CommandNumber.RUN_ALARM, data=b"\x00").framed_packet()
            # pkt = WhoopPacket(PacketType.COMMAND, 10, CommandNumber.START_DEVICE_CONFIG_KEY_EXCHANGE, data=b"\x01").framed_packet()
            # await client.write_gatt_char(WHOOP_CHAR_CMD_TO_STRAP, pkt)
            
            # pkt = await cmdresp.get()
            # print(pkt)

            # for i in range(20):
            #     pkt = WhoopPacket(PacketType.COMMAND, 10, CommandNumber.SEND_NEXT_DEVICE_CONFIG, data=struct.pack("<B", i)).framed_packet()
            #     await client.write_gatt_char(WHOOP_CHAR_CMD_TO_STRAP, pkt)
                
            #     pkt = await cmdresp.get()
                # print(pkt)
            pkt = WhoopPacket(PacketType.COMMAND, 10, CommandNumber.GET_HELLO_HARVARD, data=b"\x00").framed_packet()
            await client.write_gatt_char(WHOOP_CHAR_CMD_TO_STRAP, pkt)

            # 0a0104a0030000003e8e7967e8730000344331383635323239006233636265376430373232323366393138666261623236666536643061393962666236643932656634393436663231653930623031340600000002000000100000002900000010000000060000000000000008020100000000000011000000020000000200000000000000, off wrist
            # 0a0104a0030000005f8e7967483e0000344331383635323239006233636265376430373232323366393138666261623236666536643061393962666236643932656634393436663231653930623031340600000002000000100000002900000010000000060000000000000008020100000000000111000000020000000200000000000000, on wrist
            # 0a0104a003000000858e7967284f0000344331383635323239006233636265376430373232323366393138666261623236666536643061393962666236643932656634393436663231653930623031340600000002000000100000002900000010000000060000000000000008020100000000000111000000020000000200000000000000, on wrist
            # 0a01049f030000009f8e7967706b0000344331383635323239006233636265376430373232323366393138666261623236666536643061393962666236643932656634393436663231653930623031340600000002000000100000002900000010000000060000000000000008020100000000000011000000020000000200000000000000, off wrist
            # 0a01048d030000008faa7967e8130000344331383635323239006233636265376430373232323366393138666261623236666536643061393962666236643932656634393436663231653930623031340600000002000000100000002900000010000000060000000000000008020100000000000111000000020000000200000000000000
            # 0a01048e03000001a3aa796718300000344331383635323239006233636265376430373232323366393138666261623236666536643061393962666236643932656634393436663231653930623031340600000002000000100000002900000010000000060000000000000008020100000000000111000000020000000200000000000000
            # 0a01049303000000c1aa796730390000344331383635323239006233636265376430373232323366393138666261623236666536643061393962666236643932656634393436663231653930623031340600000002000000100000002900000010000000060000000000000008020100000000000111000000020000000200000000000000        
            # 0a01049503000001eaaa7967500b0000344331383635323239006233636265376430373232323366393138666261623236666536643061393962666236643932656634393436663231653930623031340600000002000000100000002900000010000000060000000000000008020100000000000111000000020000000200000000000000
        elif command == "history":
            pkt = WhoopPacket(PacketType.COMMAND, 10, CommandNumber.SEND_HISTORICAL_DATA, data=b"\x00").framed_packet()
            await client.write_gatt_char(WHOOP_CHAR_CMD_TO_STRAP, pkt)
            pkt = await cmdresp.get()
            print(pkt)
            # 0a020b0000

            # wait until the end, we will receive a few of these
            while True:
                # this should be the start metadata
                metapkt = await meta_queue.get()

                # get the first history end
                while MetadataType(metapkt.cmd) != MetadataType.HISTORY_END and MetadataType(metapkt.cmd) != MetadataType.HISTORY_COMPLETE:
                    print(metapkt)
                    metapkt = await meta_queue.get()

                # reached the complete metadata
                if MetadataType(metapkt.cmd) == MetadataType.HISTORY_COMPLETE:
                    break

                unix, subsec, unk0, trim = struct.unpack("<LHLL", metapkt.data[:14])
                data = struct.pack("<BLL", 1, trim, 0)
                pkt = WhoopPacket(PacketType.COMMAND, 10, CommandNumber.HISTORICAL_DATA_RESULT, data=data).framed_packet()
                await client.write_gatt_char(WHOOP_CHAR_CMD_TO_STRAP, pkt)
        elif command == "startraw":
            pkt = WhoopPacket(PacketType.COMMAND, 10, CommandNumber.START_RAW_DATA, data=b"\x01").framed_packet()
            await client.write_gatt_char(WHOOP_CHAR_CMD_TO_STRAP, pkt)
        elif command == "stopraw":
            pkt = WhoopPacket(PacketType.COMMAND, 10, CommandNumber.STOP_RAW_DATA, data=b"\x01").framed_packet()
            await client.write_gatt_char(WHOOP_CHAR_CMD_TO_STRAP, pkt)
        elif command == "reboot":
            pkt = WhoopPacket(PacketType.COMMAND, 10, CommandNumber.REBOOT_STRAP, data=b"\x00").framed_packet()
            await client.write_gatt_char(WHOOP_CHAR_CMD_TO_STRAP, pkt)
            running = False
        elif command == "exit":
            print("exiting")
            running = False
        else:
            print(f"unknown command: {command}")

async def whoop_bluetooth(address):
    client = BleakClient(address)
    await client.connect()
    if client.is_connected:
        print(f"connected to {address}")
        # setup notify
        await client.start_notify(WHOOP_CHAR_CMD_FROM_STRAP, cmd_handler)
        await client.start_notify(WHOOP_CHAR_EVENTS_FROM_STRAP, events_handler)
        await client.start_notify(WHOOP_CHAR_DATA_FROM_STRAP, data_handler)
        await client.start_notify(WHOOP_CHAR_MEMFAULT, memfault_handler)
        await command_listener(client)
    else:
        print(f"failed to connect to {address}")

async def main():
    parser = argparse.ArgumentParser(description="WHOOP debug client")
    parser.add_argument(
        "--address",
        "-a",
        type=str,
        help="Bluetooth device address or name (e.g., 'FF117189-1DC4-687E-359C-ECB5B16152E3')."
    )
    parser.add_argument(
        "--name",
        "-n",
        type=str,
        help="Bluetooth device name (e.g., 'WHOOP XXXXXXXXX')."
    )

    args = parser.parse_args()

    if args.address is None:
        if args.name is None:
            print("need to provide an address or name!")
            sys.exit(1)
    else:
        address = args.address

    # Validate that at least one of address or name is provided
    if args.address is None and args.name is None:
        print("error: you must provide either an address or a name for the Bluetooth device")
        sys.exit(1)

    address = args.address

    if address is None:
        print(f"resolving device by name: {args.name}")
        try:
            address = await BleakScanner.find_device_by_name(args.name)
            if address is None:
                print(f"error: device with name '{args.name}' not found")
                sys.exit(1)
        except Exception as e:
            print(f"error during device discovery: {e}")
            sys.exit(1)

    print(address)

    await whoop_bluetooth(address)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("program terminated")
        running = False
