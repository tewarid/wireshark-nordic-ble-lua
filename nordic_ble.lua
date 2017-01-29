-- create nordic_ble protocol dissector and its fields
p_nordic_ble = Proto ("nordic_ble", "Nordic BLE sniffer meta")

local hf_nordic_ble_sync_word = ProtoField.uint16("nordic_ble.sync_word", "Sync word. Always 0xBEEF.", base.HEX)
local hf_nordic_ble_board_id = ProtoField.uint8("nordic_ble.board_id", "board", base.DEC)
local hf_nordic_ble_header_length = ProtoField.uint8("nordic_ble.hlen", "length of header", base.DEC)
local hf_nordic_ble_payload_length = ProtoField.uint8("nordic_ble.plen", "length of payload", base.DEC)
local hf_nordic_ble_protocol_version = ProtoField.uint8("nordic_ble.protover", "protocol version", base.DEC, nil, 0, "Version of nordic_ble protocol, only for Sniffer v1.0.0 and upwards")
local hf_nordic_ble_packet_counter = ProtoField.uint16("nordic_ble.packet_counter", "uart packet counter", base.DEC, nil, 0, "Global packet counter for packets sent on UART.")
local hf_nordic_ble_id = ProtoField.uint8("nordic_ble.id", "packet id", base.DEC, nil, 0, "Packet ID. Specifies the type of the packet")
local hf_nordic_ble_ble_header_length = ProtoField.uint8("nordic_ble.hlen", "length of header", base.DEC)
local hf_nordic_ble_flags = ProtoField.uint8("nordic_ble.flags", "flags", base.DEC, nil, 0, "Flags")
local crc_tfs = {
    "OK",
    "Incorrect"
    }
local hf_nordic_ble_crcok = ProtoField.bool("nordic_ble.crcok", "CRC", base.None, crc_tfs, 0, "Cyclic Redundancy Check state")
local direction_tfs = {
    "Master -> Slave",
    "Slave -> Master"
    }
local hf_nordic_ble_direction = ProtoField.bool("nordic_ble.direction", "direction", base.None, direction_tfs, 0, "Direction")
local encrypted_tfs = {
    "Yes",
    "No"
    }
local hf_nordic_ble_encrypted = ProtoField.bool("nordic_ble.encrypted", "encrypted", base.None, encrypted_tfs, 0, "Was the packet encrypted")
mic_tfs = {
    "OK",
    "Incorrect"
    }
local hf_nordic_ble_micok = ProtoField.bool("nordic_ble.micok", "MIC", base.None, mic_tfs, 0, "Message Integrity Check state")
local hf_nordic_ble_channel = ProtoField.uint8("nordic_ble.channel", "channel", base.DEC, nil, 0, "Channel")
local hf_nordic_ble_rssi = ProtoField.int16("nordic_ble.rssi", "RSSI (dBm)", base.DEC, nil, 0, "Received Signal Strength Indicator")
local hf_nordic_ble_event_counter = ProtoField.uint16("nordic_ble.event_counter", "event counter", base.HEX, nil, 0, "Event Counter")
local hf_nordic_ble_delta_time = ProtoField.uint32("nordic_ble.delta_time", "delta time (us end to start)", base.DEC, nil, 0, "Delta time: us since last reported packet.")
local hf_nordic_ble_delta_time_ss = ProtoField.uint32("nordic_ble.delta_time_ss", "delta time (us start to start)", base.DEC, nil, 0, "Delta time: us since start of last reported packet.")

p_nordic_ble.fields = {
    hf_nordic_ble_sync_word,
    hf_nordic_ble_board_id,
    hf_nordic_ble_header_length,
    hf_nordic_ble_payload_length,
    hf_nordic_ble_protocol_version,
    hf_nordic_ble_packet_counter,
    hf_nordic_ble_id,
    hf_nordic_ble_ble_header_length,
    hf_nordic_ble_flags,
    hf_nordic_ble_crcok,
    hf_nordic_ble_direction,
    hf_nordic_ble_encrypted,
    hf_nordic_ble_micok,
    hf_nordic_ble_channel,
    hf_nordic_ble_rssi,
    hf_nordic_ble_event_counter,
    hf_nordic_ble_delta_time,
    hf_nordic_ble_delta_time_ss
}

-- Size of various UART Packet header fields
local BEEF_LENGTH_BYTES       = 2
local HEADER_LEN_LENGTH_BYTES = 1
local PACKET_LEN_LENGTH_BYTES = 1
local PROTOVER_LENGTH_BYTES   = 1
local COUNTER_LENGTH_BYTES    = 2
local ID_LENGTH_BYTES         = 1

local BLE_HEADER_LEN_LENGTH_BYTES = 1
local FLAGS_LENGTH_BYTES          = 1
local CHANNEL_LENGTH_BYTES        = 1
local RSSI_LENGTH_BYTES           = 1
local EVENT_COUNTER_LENGTH_BYTES  = 2
local TIMESTAMP_LENGTH_BYTES      = 4

local BOARD_ID_INDEX  = 0
local BOARD_ID_LENGTH = 1

-- Define the index of the various fields in the UART_PACKET header
local UART_PACKET_HEADER_LEN_INDEX     = 0
local UART_PACKET_PACKET_LEN_INDEX     = UART_PACKET_HEADER_LEN_INDEX       + HEADER_LEN_LENGTH_BYTES
local UART_PACKET_PROTOVER_INDEX       = UART_PACKET_PACKET_LEN_INDEX       + PACKET_LEN_LENGTH_BYTES
local UART_PACKET_COUNTER_INDEX        = UART_PACKET_PROTOVER_INDEX         + PROTOVER_LENGTH_BYTES
local UART_PACKET_ID_INDEX             = UART_PACKET_COUNTER_INDEX          + COUNTER_LENGTH_BYTES

local UART_PACKET_BLE_HEADER_LEN_INDEX = UART_PACKET_ID_INDEX               + ID_LENGTH_BYTES
local UART_PACKET_FLAGS_INDEX          = UART_PACKET_BLE_HEADER_LEN_INDEX   + BLE_HEADER_LEN_LENGTH_BYTES
local UART_PACKET_CHANNEL_INDEX        = UART_PACKET_FLAGS_INDEX            + FLAGS_LENGTH_BYTES
local UART_PACKET_RSSI_INDEX           = UART_PACKET_CHANNEL_INDEX          + CHANNEL_LENGTH_BYTES
local UART_PACKET_EVENT_COUNTER_INDEX  = UART_PACKET_RSSI_INDEX             + RSSI_LENGTH_BYTES
local UART_PACKET_TIMESTAMP_INDEX      = UART_PACKET_EVENT_COUNTER_INDEX    + EVENT_COUNTER_LENGTH_BYTES
local UART_PACKET_ACCESS_ADDRESS_INDEX = UART_PACKET_TIMESTAMP_INDEX        + TIMESTAMP_LENGTH_BYTES

local INDEX_OF_LENGTH_FIELD_IN_BLE_PACKET = 5
local INDEX_OF_LENGTH_FIELD_IN_EVENT_PACKET = UART_PACKET_TIMESTAMP_INDEX + TIMESTAMP_LENGTH_BYTES + INDEX_OF_LENGTH_FIELD_IN_BLE_PACKET

local UART_HEADER_LEN                     = 6
local BLE_HEADER_LEN                      = 10
local PROTOVER                            = 1

local US_PER_BYTE                                     = 8
local NOF_BLE_BYTES_NOT_INCLUDED_IN_BLE_LENGTH        = 10 -- Preamble (1) + AA (4) + Header (1) + Length (1) + CRC (3)             = 10 Bytes
local BLE_METADATA_TRANFER_TIME_US                    = US_PER_BYTE * NOF_BLE_BYTES_NOT_INCLUDED_IN_BLE_LENGTH

local UART_HEADER_LENGTH = UART_PACKET_ACCESS_ADDRESS_INDEX
local BLE_MIN_PACKET_LENGTH = NOF_BLE_BYTES_NOT_INCLUDED_IN_BLE_LENGTH
local BLE_MAX_PACKET_LENGTH = 50
local MIN_TOTAL_LENGTH = BLE_HEADER_LEN + BLE_MIN_PACKET_LENGTH
local MAX_TOTAL_LENGTH = UART_HEADER_LENGTH + BLE_MAX_PACKET_LENGTH
local BLE_LENGTH_POS = UART_HEADER_LENGTH + 5

local bad_length = false
local bad_mic = false
local btle_dissector_handle = Dissector.get("btle")

function dissect_board_id_and_strip_it_from_tvb (tvb, pinfo, tree)
    tree:add(hf_nordic_ble_board_id, tvb(BOARD_ID_INDEX, BOARD_ID_LENGTH))
    return tvb(BOARD_ID_LENGTH):tvb()
end

function dissect_lengths (tvb, pinfo, tree)
    local bad_length = false

    local hlen = tvb(UART_PACKET_HEADER_LEN_INDEX, 1):uint()
    local plen = tvb(UART_PACKET_PACKET_LEN_INDEX, 1):uint()

    if (hlen + plen) ~= tvb:len() then

        tree:add(hf_nordic_ble_header_length, tvb(UART_PACKET_HEADER_LEN_INDEX, 1))
        item = tree:add(hf_nordic_ble_payload_length, tvb(UART_PACKET_PACKET_LEN_INDEX, 1))        
        item:add_expert_info(PI_MALFORMED, PI_ERROR, "UART packet lengths do not match actual packet length.")
        bad_length = true

    elseif (hlen + plen) < MIN_TOTAL_LENGTH then

        tree:add(hf_nordic_ble_header_length, tvb(UART_PACKET_HEADER_LEN_INDEX, 1))
        item = tree:add(hf_nordic_ble_payload_length, tvb(UART_PACKET_HEADER_LEN_INDEX, 1))
        item:add_expert_info(PI_MALFORMED, PI_ERROR, "UART packet length is too small (likely corrupted).")
        bad_length = true

    elseif (hlen + plen) > MAX_TOTAL_LENGTH then

        tree:add(hf_nordic_ble_header_length, tvb(UART_PACKET_HEADER_LEN_INDEX, 1))
        item = tree:add(hf_nordic_ble_payload_length, tvb(UART_PACKET_PACKET_LEN_INDEX, 1))
        item:add_expert_info(PI_MALFORMED, PI_ERROR, "UART packet length is too large (likely corrupted).")
        bad_length     = true
    end

    return bad_length
end

function dissect_protover (tvb, tree)
    local protover = tvb(UART_PACKET_PROTOVER_INDEX, 1):uint()
end

function dissect_packet_counter (tvb, tree)
    tree:add_le(hf_nordic_ble_packet_counter, tvb(UART_PACKET_COUNTER_INDEX, 2))
end

function dissect_id (tvb, tree)
    local id = tvb(UART_PACKET_ID_INDEX, 1):uint()
end

function dissect_ble_hlen (tvb, tree)
    local ble_hlen = tvb(UART_PACKET_BLE_HEADER_LEN_INDEX, 1):uint()
end

function dissect_flags (tvb, pinfo, tree)
    local bad_mic  = false
    local flags = tvb(UART_PACKET_FLAGS_INDEX, 1):uint()
    local crcok = bit.band(flags, 1)
    local dir = bit.band(flags, 2)
    local encrypted = bit.band(flags, 4)
    local micok =  bit.band(flags, 8)
    
    if dir > 0 then
        pinfo.cols.src:set("Master")
        pinfo.cols.dst:set("Slave")
    else
        pinfo.cols.src:set("Slave")
        pinfo.cols.dst:set("Master")
    end

    local flags_item = tree:add(hf_nordic_ble_flags, tvb(UART_PACKET_FLAGS_INDEX, 1))
    if encrypted > 0 then -- if encrypted, add MIC status
        local item  = tree:add_le(hf_nordic_ble_micok, tvb(UART_PACKET_FLAGS_INDEX, 1), micok > 0)
        if micok == 0 then
            -- MIC is bad
            item:add_expert_info(PI_CHECKSUM, PI_WARN, "MIC is bad")
            item:add_expert_info(PI_UNDECODED, PI_WARN, "Decryption failed (wrong key?)")
            bad_mic = true
        end
    end

    tree:add_le(hf_nordic_ble_encrypted, tvb(UART_PACKET_FLAGS_INDEX, 1), encrypted > 0)
    tree:add_le(hf_nordic_ble_direction, tvb(UART_PACKET_FLAGS_INDEX, 1), dir > 0)
    local item = tree:add_le(hf_nordic_ble_crcok, tvb(UART_PACKET_FLAGS_INDEX, 1), crcok > 0)
    local bad_crc = false
    if crcok == 0 then
        -- CRC is bad
        item:add_expert_info(PI_MALFORMED, PI_ERROR, "CRC is bad")
        bad_crc = true
    end

    return bad_mic
end

function dissect_channel (tvb, tree)
    tree:add(hf_nordic_ble_channel, tvb(UART_PACKET_CHANNEL_INDEX, 1))
end

function dissect_rssi (tvb, tree)
    local rssi = (-1)*(tvb(UART_PACKET_RSSI_INDEX, 1):uint())
    tree:add(hf_nordic_ble_rssi, tvb(UART_PACKET_RSSI_INDEX, 1), rssi)
end

function dissect_event_counter (tvb, tree)
    local adv_aa = 0x8e89bed6
    local aa = tvb(UART_HEADER_LENGTH, 4):le_uint()
    if aa ~= adv_aa then
        tree:add_le(hf_nordic_ble_event_counter, tvb(UART_PACKET_EVENT_COUNTER_INDEX, 2))
    end
end

local previous_ble_packet_length = 0

function dissect_ble_delta_time (tvb, tree)
    -- end - start
    local delta_time = tvb(UART_PACKET_TIMESTAMP_INDEX, 4):le_uint()
    tree:add_le(hf_nordic_ble_delta_time, tvb(UART_PACKET_TIMESTAMP_INDEX, 4))

    -- start - start
    local delta_time_ss = BLE_METADATA_TRANFER_TIME_US + (US_PER_BYTE * previous_ble_packet_length) + delta_time
    tree:add(hf_nordic_ble_delta_time_ss, tvb(UART_PACKET_TIMESTAMP_INDEX, 4), delta_time_ss)

    previous_ble_packet_length = tvb(UART_PACKET_PACKET_LEN_INDEX, 1):uint()
end

function dissect_header_1_0_0 (tvb, pinfo, tree)
    local nordic_ble_tree = tree:add(p_nordic_ble, tvb(0))

    tvb = dissect_board_id_and_strip_it_from_tvb(tvb, pinfo, nordic_ble_tree)
    bad_length = dissect_lengths(tvb, pinfo, nordic_ble_tree)
    dissect_protover(tvb, nordic_ble_tree)
    dissect_packet_counter(tvb, nordic_ble_tree)
    dissect_id(tvb, nordic_ble_tree)
    dissect_ble_hlen(tvb, nordic_ble_tree)

    bad_mic = dissect_flags(tvb, pinfo, nordic_ble_tree)

    dissect_channel(tvb, nordic_ble_tree)
    dissect_rssi(tvb, nordic_ble_tree)
    dissect_event_counter(tvb, nordic_ble_tree)

    dissect_ble_delta_time(tvb, nordic_ble_tree)
end

-- nordic_ble dissector function
function p_nordic_ble.dissector (tvb, pinfo, tree)
    local payload_tvb = nil

    bad_length  = false
    bad_mic     = false;

    dissect_header_1_0_0(tvb, pinfo, tree)

    -- have to take BOARD_ID into account, as the stripped version is local to dissect_1_0_0
    payload_tvb = tvb:range(UART_HEADER_LENGTH + BOARD_ID_LENGTH,
                    tvb:len() - UART_HEADER_LENGTH - BOARD_ID_LENGTH):tvb()

    if bad_length == false then
        btle_dissector_handle:call(payload_tvb, pinfo, tree)
    end

    if bad_mic == true then
        pinfo.cinfo = "Encrypted packet decrypted incorrectly (bad MIC)"
    end

    return UART_HEADER_LENGTH + BOARD_ID_LENGTH
end

-- Initialization routine
function p_nordic_ble.init()
end

local wtap_encap_table = DissectorTable.get("wtap_encap")
wtap_encap_table:add(wtap.USER10, p_nordic_ble) -- corresponds to pcap network type value 157, user type 10
