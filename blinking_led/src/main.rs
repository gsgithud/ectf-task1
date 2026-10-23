/*
*   Tests GPIO and Trng
*   Randomly tries lighting all 3 LEDS
* */

#![no_std]
#![no_main]

// pick a panicking behavior
use panic_halt as _; // you can put a breakpoint on `rust_begin_unwind` to catch panics
// use panic_abort as _; // requires nightly
// use panic_itm as _; // logs messages over ITM; requires ITM support
// use panic_semihosting as _; // logs messages to the host stderr; requires a debugger

use cortex_m_rt::entry;

use core::arch::asm;
use mspm0l2228_hal::{pac, trng};

#[inline(always)]
fn delay(millis: u32) {
    // 75449 -> .98126864
    for _ in 0..(millis * 76889 / 1000) {
        unsafe { asm!("nop") };
    }
}

#[entry]
fn main() -> ! {
    let p = pac::Peripherals::take().unwrap();
    let gpiob = mspm0l2228_hal::gpio::gpiob::new(p.gpiob);
    let gpiob_pins = gpiob.pins();
    let mut red_led = gpiob_pins.pin10.into_output();

    let gpioa = mspm0l2228_hal::gpio::gpioa::new(p.gpioa);
    let gpioa_pins = gpioa.pins();
    let mut blue_led = gpioa_pins.pin16.into_output();
    let mut red_led = gpiob_pins.pin10.into_output();
    let mut green_led = gpiob_pins.pin9.into_output();


    loop{
        red_led.set_low();
        delay(100000);
        red_led.set_high();
        delay(100000);
        // green_led.set_low();
        // delay(500);
        // green_led.set_high();
        // delay(500);
        // blue_led.set_low();
        // delay(500);
        // blue_led.set_high();
        // delay(500);
    }

}


