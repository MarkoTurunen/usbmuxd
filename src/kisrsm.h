/*
 * kisrsm.h
 *
 * Restore mode over the KIS RSM channel of Apple devices that do not
 * re-enumerate after iBoot (MacBook Neo): the restore OS's USB device is
 * tunnelled through a virtual host controller (RSM channel type 3) inside
 * the KIS ("Debug USB", 05ac:1881) connection.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 or version 3.
 */

#ifndef KISRSM_H
#define KISRSM_H

#include <stdint.h>
#include <libusb.h>

#define KIS_PRODUCT_ID 0x1881

struct kisrsm_dev;

typedef void (*kisrsm_rx_cb)(void *user_data, unsigned char *data, int length);

enum kisrsm_state {
	KISRSM_PENDING = 0, /* bringing up the port / enumerating */
	KISRSM_READY,       /* usbmux endpoints open (returned once) */
	KISRSM_RUNNING,     /* data phase */
	KISRSM_CLOSED       /* channel gone or failed; free the engine */
};

/* Opens a KIS device and returns an engine if it offers a restore channel (type 3).
 * Returns NULL (device closed again) if it does not or is in use. */
struct kisrsm_dev *kisrsm_probe(libusb_device *device);

/* Milliseconds the last kisrsm_probe suggests waiting before probing that device again (0: the usual
 * interval): longer for a channel in use and for a device that does not answer. */
int kisrsm_probe_delay_ms(void);

/* Drives the channel; call often (see kisrsm_poll_interval). */
enum kisrsm_state kisrsm_pump(struct kisrsm_dev *dev);

/* Milliseconds until the next pump is useful. */
int kisrsm_poll_interval(struct kisrsm_dev *dev);

/* Queues one bulk OUT transfer on the usbmux endpoint. On success the engine owns buf (free()). */
int kisrsm_send(struct kisrsm_dev *dev, unsigned char *buf, int length);

/* Bulk IN data from the usbmux endpoint is passed to cb. */
void kisrsm_set_rx_callback(struct kisrsm_dev *dev, kisrsm_rx_cb cb, void *user_data);

const struct libusb_device_descriptor *kisrsm_device_descriptor(struct kisrsm_dev *dev);
const char *kisrsm_serial(struct kisrsm_dev *dev);
libusb_device_handle *kisrsm_handle(struct kisrsm_dev *dev);
int kisrsm_max_packet_size(struct kisrsm_dev *dev);

/* Releases the KIS device and frees the engine (queued data is dropped). */
void kisrsm_free(struct kisrsm_dev *dev);

#endif
