#!/bin/sh
arm-none-eabi-objcopy -O binary "$1" firmware.bin &&
openocd -f board/ti/mspm0-launchpad.cfg -c \
    "init; halt;
    flash write_image erase firmware.bin 0x00000000 bin;
    reset run; exit;"