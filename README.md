# Wireshark Dissector in Lua for Nordic nRF BLE Sniffer

This is a Lua port of Nordic's native dissector for the nRF BLE Sniffer. Legacy header (version 0.9.7) and call to `nordic_debug` dissector have not been ported. Submit a pull request if you port that portion of code.

This dissector should work on all Wireshark versions starting at 1.12.x. It will not work with Wireshark 1.10.x due to the lack of the native `btle` dissector. That can be resolved by porting Nordic's native `btle` dissector to Lua, but I think the effort is not worthwhile.

Download `nordic_ble.lua` and add the following to Wireshark's `init.lua`

```lua
dofile("C:\\path_to_folder\\nordic_ble.lua")
```

Note the need for two backslashes to represent a single backslash (path separator) on Windows. On Linux and OS X just a single forward slash `/` works fine.
