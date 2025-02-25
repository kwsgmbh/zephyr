#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/gpio.h>

// Define the LED node using the device tree
#define LED_NODE DT_ALIAS(led0)

#if !DT_NODE_HAS_STATUS(LED_NODE, okay)
#error "Unsupported board: led0 devicetree alias is not defined"
#endif

// Get the GPIO controller and pin information from the device tree
static const struct gpio_dt_spec led = GPIO_DT_SPEC_GET(LED_NODE, gpios);

// Define the LED toggle delay (in milliseconds)
#define LED_TOGGLE_DELAY_MS 500

void main(void)
{
    int ret;

    // Check if the GPIO device is ready
    if (!device_is_ready(led.port)) {
        printk("Error: LED device %s is not ready\n", led.port->name);
        return;
    }

    // Configure the LED GPIO pin
    ret = gpio_pin_configure_dt(&led, GPIO_OUTPUT_ACTIVE);
    if (ret < 0) {
        printk("Error: Failed to configure LED pin (%d)\n", ret);
        return;
    }

    printk("Zephyr LED toggle example started\n");

    // Main loop: Toggle the LED
    while (1) {
        gpio_pin_toggle_dt(&led); // Toggle the LED state
        k_msleep(LED_TOGGLE_DELAY_MS); // Wait for the delay
    }
}
