/*
 * kisrsm.c
 *
 * Restore mode over the KIS RSM channel (MacBook Neo).
 *
 * After iBoot, the Neo stays on USB as its KIS device ("Debug USB", 05ac:1881)
 * and tunnels its USB devices through RSM channels: rings in device memory that
 * the host writes and reads with KIS memory requests, signalled with doorbells.
 * In restore mode the channel (type 3) is a virtual USB host controller (VHCI):
 * the host brings up a root port, enumerates the restore device (05ac:12ac) and
 * exchanges transfers with it as ring records. This file implements that host
 * side, as decoded from a macOS KIS sniffer capture of an Apple Configurator
 * restore (YWME repository, .claude/skills/apple-device-bringup/reference.md,
 * "Wire protocol"), and runs usbmux over the device's usbmux interface.
 *
 * Ring records: u32 header (class << 24 | length), payload padded to 4 bytes.
 *   0x80 host: controller command [cmd, arg0, arg1, arg2]
 *   0x81 device: command reply [0x18000 | cmd, ...] or port event [0x18, port, status]
 *   0x84 both: transfer records [code, endpoint id, length, 0]
 *        0x1000 host: queue a transfer (IN read / control data stage)
 *        0x1000 device: credit (ep 0: ready for SETUP; OUT endpoint: one transfer)
 *        0x?1005 device: control transfer complete (status in bits 16-19, 1 = ok)
 *   addr << 4 | ep       host: SETUP (ep 0) or bulk OUT data
 *   0x40 | addr << 4 | ep device: IN data (completes one queued read)
 * Endpoint id = endpoint address << 8 | device address.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 or version 3.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include "kisrsm.h"
#include "log.h"

#define KIS_PORTAL_CONFIG       0x01
#define KIS_PORTAL_RSM          0x10
#define KIS_INDEX_MEMORY        0x0D
#define KIS_INDEX_DOORBELLS     0x100
#define KIS_INDEX_PORTAL_ENABLE 0x16
#define KIS_PORTAL_ENABLE_RSM   0x30000 /* as macOS: portals 0x10 and 0x11 */
#define KIS_TIMEOUT             2000

#define RSM_MAGIC        0x52534D31 /* 'RSM1' in doorbell 0 */
#define DB_CHAN_DESC     16
#define DB_H2D_BASE      32
#define DB_D2H_BASE      64
#define DB_HOST_WP       96
#define DB_DEVICE_WP     112
#define CHANNEL_VHCI     3
#define RING_SIZE        0x100000
#define RING_MARGIN      0x10000
#define MAX_RECORD       0x10000
#define D2H_READ_CHUNK   0x10000

#define DEV_ADDR         1      /* the restore device's address on the virtual port */
#define PORT             1
#define BULK_CHUNK       0x8000 /* credits are one transfer of up to 32 KB */
#define IN_READS         4
#define IN_READ_SIZE     0x8000
#define STEP_TIMEOUT_MS  5000
#define CONNECT_TIMEOUT_MS 180000

#define CLS_CMD    0x80
#define CLS_REPLY  0x81
#define CLS_XFER   0x84

enum step {
	ST_CMD_START = 0,
	/* controller and port bring-up, as macOS */
	ST_WAIT_CONNECT = 100,
	ST_PORT_START = 200,
	ST_ENUM_START = 300,
	ST_OPEN_EPS = 400,
	ST_RUNNING = 500,
	ST_FAILED = 900
};

struct txbuf {
	unsigned char *data;
	uint32_t length;
	uint32_t offset;
	int zlp;
	struct txbuf *next;
};

struct kisrsm_dev {
	libusb_device_handle *handle;
	int ch;
	uint32_t desc;
	uint64_t h2d, d2h;
	uint32_t hw, dr, drp;
	uint32_t last_doorbell;

	int step;
	uint64_t step_deadline;
	uint64_t next_status_poll;
	int ready_reported;

	/* pending controller command */
	uint32_t cmd_wait;
	int cmd_done;
	uint32_t cmd_reply[4];
	uint32_t port_status;

	/* endpoint 0 */
	int ep0_credit;
	int ctrl_active;
	int ctrl_done;
	uint32_t ctrl_status;
	unsigned char ctrl_data[1024];
	int ctrl_len;

	struct libusb_device_descriptor devdesc;
	char serial[256];
	uint8_t ep_out, ep_in;
	uint16_t config_total;

	/* bulk */
	int out_credits;
	int in_queued;
	struct txbuf *tx_head, *tx_tail;
	kisrsm_rx_cb rx_cb;
	void *rx_user;

	/* H2D entries collected during a pump */
	unsigned char *batch;
	uint32_t batch_len, batch_cap;
	uint32_t batch_last; /* offset of the last entry in the batch */
	unsigned char *d2h_buf;
	uint64_t last_activity;
};

static uint64_t now_ms(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static void put32(unsigned char *p, uint32_t v)
{
	p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF; p[2] = (v >> 16) & 0xFF; p[3] = (v >> 24) & 0xFF;
}

static uint32_t get32(const unsigned char *p)
{
	return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* ---------------------------------------------------------------- KIS requests */

/* One KIS request; reply receives the payload after the 12-byte header. */
static int kis_request(libusb_device_handle *handle, uint8_t portal, uint16_t index, const uint32_t *args, int argc,
		const unsigned char *payload, uint32_t payload_size, uint16_t rpl_words,
		unsigned char *reply, uint32_t *reply_size, uint8_t *reply_index)
{
	uint32_t req_size = 12 + 4 * argc + payload_size;
	unsigned char *req = malloc(req_size);
	uint32_t rpl_cap = 12 + *reply_size + 64;
	unsigned char *rpl = malloc(rpl_cap);
	int res, sent = 0, got = 0, i;
	uint8_t ep = (portal == KIS_PORTAL_CONFIG) ? 0x01 : 0x03;
	if (!req || !rpl) {
		free(req);
		free(rpl);
		return LIBUSB_ERROR_NO_MEM;
	}
	req[0] = 0; req[1] = 0; req[2] = 0xA0; req[3] = portal; req[4] = (uint8_t)argc;
	req[5] = index & 0xFF;
	req[6] = ((index >> 8) & 0x3) | ((rpl_words << 2) & 0xFC);
	req[7] = (rpl_words >> 6) & 0xFF;
	put32(req + 8, 4 * argc + payload_size);
	for (i = 0; i < argc; i++)
		put32(req + 12 + 4 * i, args[i]);
	if (payload_size)
		memcpy(req + 12 + 4 * argc, payload, payload_size);
	res = libusb_bulk_transfer(handle, ep, req, req_size, &sent, KIS_TIMEOUT);
	if (res == 0 && sent != (int)req_size)
		res = LIBUSB_ERROR_IO;
	if (res == 0)
		res = libusb_bulk_transfer(handle, ep | 0x80, rpl, rpl_cap, &got, KIS_TIMEOUT);
	if (res == 0 && got < 12)
		res = LIBUSB_ERROR_IO;
	if (res == 0) {
		uint32_t n = got - 12;
		if (n > *reply_size)
			n = *reply_size;
		memcpy(reply, rpl + 12, n);
		*reply_size = n;
		if (reply_index)
			*reply_index = rpl[5];
	}
	free(req);
	free(rpl);
	return res;
}

static int read_doorbells(libusb_device_handle *handle, uint32_t bells[256], int *available)
{
	unsigned char reply[1024 + 8];
	uint32_t size = sizeof(reply);
	uint8_t index = 0;
	int i, res = kis_request(handle, KIS_PORTAL_RSM, KIS_INDEX_DOORBELLS, NULL, 0, NULL, 0, 256, reply, &size, &index);
	if (res != 0)
		return res;
	*available = (index == 0 && size >= 1024);
	for (i = 0; i < 256; i++)
		bells[i] = *available ? get32(reply + 4 * i) : 0;
	return 0;
}

static int mem_write(libusb_device_handle *handle, uint64_t address, const unsigned char *data, uint32_t size)
{
	uint32_t args[3] = { (uint32_t)address, (uint32_t)(address >> 32), size };
	unsigned char reply[8];
	uint32_t reply_size = sizeof(reply);
	int res = kis_request(handle, KIS_PORTAL_RSM, KIS_INDEX_MEMORY, args, 3, data, size, 0, reply, &reply_size, NULL);
	if (res == 0 && (reply_size < 8 || get32(reply + 4) != 0)) {
		usbmuxd_log(LL_ERROR, "KIS RSM: memory write to 0x%llx failed, status 0x%x", (unsigned long long)address, reply_size < 8 ? 0 : get32(reply + 4));
		res = LIBUSB_ERROR_IO;
	}
	return res;
}

static int mem_read(libusb_device_handle *handle, uint64_t address, uint32_t size, unsigned char *out)
{
	uint32_t args[2] = { (uint32_t)address, (uint32_t)(address >> 32) };
	unsigned char payload[4];
	uint32_t reply_size = size + 8;
	unsigned char *reply = malloc(reply_size);
	int res;
	if (!reply)
		return LIBUSB_ERROR_NO_MEM;
	put32(payload, size);
	res = kis_request(handle, KIS_PORTAL_RSM, KIS_INDEX_MEMORY, args, 2, payload, 4, 0, reply, &reply_size, NULL);
	if (res == 0 && (reply_size < size + 8 || get32(reply + size + 4) != 0))
		res = LIBUSB_ERROR_IO;
	if (res == 0)
		memcpy(out, reply, size);
	free(reply);
	return res;
}

static int doorbell_write(libusb_device_handle *handle, int doorbell, uint32_t value)
{
	unsigned char reply[8];
	uint32_t reply_size = sizeof(reply);
	return kis_request(handle, KIS_PORTAL_RSM, (uint16_t)(KIS_INDEX_DOORBELLS + doorbell), &value, 1, NULL, 0, 1, reply, &reply_size, NULL);
}

static int config_write(libusb_device_handle *handle, uint16_t index, uint32_t value)
{
	unsigned char reply[8];
	uint32_t reply_size = sizeof(reply);
	return kis_request(handle, KIS_PORTAL_CONFIG, index, &value, 1, NULL, 0, 1, reply, &reply_size, NULL);
}

static int find_channel(const uint32_t *bells, int type)
{
	int ch;
	if (bells[0] != RSM_MAGIC)
		return -1;
	for (ch = 0; ch < 16; ch++) {
		if ((bells[DB_CHAN_DESC + ch] >> 24) == (uint32_t)type
		    && (bells[DB_H2D_BASE + 2 * ch] || bells[DB_H2D_BASE + 2 * ch + 1])
		    && (bells[DB_D2H_BASE + 2 * ch] || bells[DB_D2H_BASE + 2 * ch + 1]))
			return ch;
	}
	return -1;
}

/* ---------------------------------------------------------------- H2D entries */

static void emit(struct kisrsm_dev *dev, uint8_t cls, const unsigned char *payload, uint32_t length)
{
	uint32_t size = 4 + ((length + 3) & ~3u);
	if (dev->batch_len + size > dev->batch_cap) {
		uint32_t cap = dev->batch_cap ? dev->batch_cap : 0x10000;
		while (cap < dev->batch_len + size)
			cap *= 2;
		dev->batch = realloc(dev->batch, cap);
		dev->batch_cap = cap;
	}
	dev->batch_last = dev->batch_len;
	put32(dev->batch + dev->batch_len, ((uint32_t)cls << 24) | length);
	memset(dev->batch + dev->batch_len + 4, 0, size - 4);
	if (length)
		memcpy(dev->batch + dev->batch_len + 4, payload, length);
	dev->batch_len += size;
}

static void emit_words(struct kisrsm_dev *dev, uint8_t cls, uint32_t w0, uint32_t w1, uint32_t w2, uint32_t w3)
{
	unsigned char p[16];
	put32(p, w0); put32(p + 4, w1); put32(p + 8, w2); put32(p + 12, w3);
	emit(dev, cls, p, sizeof(p));
}

static uint32_t ring_used(struct kisrsm_dev *dev)
{
	return (dev->hw + RING_SIZE - dev->drp) % RING_SIZE;
}

static void command(struct kisrsm_dev *dev, uint32_t cmd, uint32_t a0, uint32_t a1, uint32_t a2)
{
	emit_words(dev, CLS_CMD, cmd, a0, a1, a2);
	dev->cmd_wait = cmd;
	dev->cmd_done = 0;
}

static int control(struct kisrsm_dev *dev, uint8_t bm, uint8_t request, uint16_t value, uint16_t index, uint16_t length)
{
	unsigned char setup[8];
	if (!dev->ep0_credit)
		return 0;
	setup[0] = bm; setup[1] = request;
	setup[2] = value & 0xFF; setup[3] = value >> 8;
	setup[4] = index & 0xFF; setup[5] = index >> 8;
	setup[6] = length & 0xFF; setup[7] = length >> 8;
	emit(dev, (DEV_ADDR << 4) | 0, setup, sizeof(setup));
	if ((bm & 0x80) && length)
		emit_words(dev, CLS_XFER, 0x1000, DEV_ADDR, length, 0);
	dev->ep0_credit = 0;
	dev->ctrl_active = 1;
	dev->ctrl_done = 0;
	dev->ctrl_len = 0;
	return 1;
}

/* ---------------------------------------------------------------- D2H records */

static void handle_record(struct kisrsm_dev *dev, uint8_t cls, const unsigned char *p, uint32_t length)
{
	uint16_t ep_in_id = ((uint16_t)dev->ep_in << 8) | DEV_ADDR;
	uint16_t ep_out_id = ((uint16_t)dev->ep_out << 8) | DEV_ADDR;
	if ((cls == CLS_REPLY || cls == CLS_XFER) && length >= 16) {
		uint32_t w0 = get32(p), w1 = get32(p + 4), w2 = get32(p + 8);
		if (w0 == 0x18) {
			/* port status change event */
			dev->port_status = w2;
			usbmuxd_log(LL_DEBUG, "KIS RSM: port %u status 0x%x", w1, w2);
		} else if ((w0 & 0xFF000) == 0x18000) {
			if ((w0 & 0xFFF) == dev->cmd_wait) {
				memcpy(dev->cmd_reply, (uint32_t[4]){ w0, w1, w2, get32(p + 12) }, sizeof(dev->cmd_reply));
				dev->cmd_done = 1;
			}
		} else if (w0 == 0x1000) {
			if (w1 == DEV_ADDR)
				dev->ep0_credit = 1;
			else if (dev->ep_out && w1 == ep_out_id)
				dev->out_credits++;
		} else if ((w0 & 0xFFFF) == 0x1005) {
			if (w1 == DEV_ADDR) {
				dev->ctrl_done = 1;
				dev->ctrl_status = (w0 >> 16) & 0xF;
			}
		} else {
			usbmuxd_log(LL_DEBUG, "KIS RSM: unhandled record 0x%02x [%x %x %x]", cls, w0, w1, w2);
		}
		return;
	}
	if ((cls & 0xC0) == 0x40) {
		uint8_t ep = cls & 0x0F;
		if (ep == 0) {
			uint32_t n = length > sizeof(dev->ctrl_data) ? sizeof(dev->ctrl_data) : length;
			memcpy(dev->ctrl_data, p, n);
			dev->ctrl_len = (int)n;
		} else if (dev->ep_in && ep == (dev->ep_in & 0x0F)) {
			if (dev->in_queued > 0)
				dev->in_queued--;
			dev->last_activity = now_ms();
			if (dev->rx_cb && length)
				dev->rx_cb(dev->rx_user, (unsigned char *)p, (int)length);
		}
		(void)ep_in_id;
		return;
	}
	usbmuxd_log(LL_DEBUG, "KIS RSM: unexpected record class 0x%02x length %u", cls, length);
}

/* Reads and handles all new D2H records. Returns 0, or -1 if the channel is gone. */
static int read_records(struct kisrsm_dev *dev)
{
	uint32_t bells[256];
	int available = 0;
	if (read_doorbells(dev->handle, bells, &available) != 0)
		return -1;
	if (!available || bells[0] != RSM_MAGIC || bells[DB_CHAN_DESC + dev->ch] != dev->desc)
		return -1;
	uint32_t device = bells[DB_DEVICE_WP + dev->ch];
	dev->drp = (device >> 24) * 0x1000;
	uint32_t wp = (device & 0xFFFFF) * 4 % RING_SIZE;
	while (wp != dev->dr) {
		uint32_t avail = (wp + RING_SIZE - dev->dr) % RING_SIZE;
		uint32_t chunk = avail > D2H_READ_CHUNK ? D2H_READ_CHUNK : avail;
		/* Records are contiguous, also one that crosses the ring end; the next one starts at the
		 * base again, so a read never goes past the end except to complete such a record. */
		if (chunk > RING_SIZE - dev->dr)
			chunk = RING_SIZE - dev->dr;
		if (chunk < 4)
			break;
		if (mem_read(dev->handle, dev->d2h + dev->dr, chunk, dev->d2h_buf) != 0)
			return -1;
		uint32_t pos = 0;
		while (pos + 4 <= chunk) {
			uint32_t hdr = get32(dev->d2h_buf + pos);
			uint8_t cls = hdr >> 24;
			uint32_t length = hdr & 0xFFFFFF;
			uint32_t size = 4 + ((length + 3) & ~3u);
			if (length > MAX_RECORD) {
				usbmuxd_log(LL_ERROR, "KIS RSM: invalid record 0x%08x at D2H offset 0x%x", hdr, dev->dr + pos);
				return -1;
			}
			if (pos + size > chunk) {
				if (pos == 0) {
					/* record larger than what we read: read it whole */
					unsigned char *rec = malloc(size);
					if (!rec || mem_read(dev->handle, dev->d2h + dev->dr, size, rec) != 0) {
						free(rec);
						return -1;
					}
					handle_record(dev, cls, rec + 4, length);
					free(rec);
					pos = size;
				}
				break;
			}
			handle_record(dev, cls, dev->d2h_buf + pos + 4, length);
			pos += size;
		}
		dev->dr = (dev->dr + pos) % RING_SIZE;
		if (pos == 0)
			break;
	}
	return 0;
}

/* Writes entries batch[from, to) at ring offset at. A KIS request whose length is a multiple of 512
 * would end without a short packet, so the last entry is written separately then. */
static int write_entries(struct kisrsm_dev *dev, uint32_t at, uint32_t from, uint32_t to)
{
	uint32_t last = from, pos = from;
	if (from == to)
		return 0;
	while (pos < to) {
		last = pos;
		pos += 4 + (((get32(dev->batch + pos) & 0xFFFFFF) + 3) & ~3u);
	}
	uint32_t first_end = to;
	if ((24 + (to - from)) % 512 == 0 && last > from)
		first_end = last;
	if (mem_write(dev->handle, dev->h2d + at, dev->batch + from, first_end - from) != 0)
		return -1;
	if (first_end < to && mem_write(dev->handle, dev->h2d + at + (first_end - from), dev->batch + first_end, to - first_end) != 0)
		return -1;
	return 0;
}

/* Writes the collected entries and rings the doorbell. An entry that crosses the ring end is
 * written contiguously past it (as macOS does); the entries after it start again at the base. */
static int flush(struct kisrsm_dev *dev)
{
	if (dev->batch_len) {
		if (ring_used(dev) + dev->batch_len + RING_MARGIN > RING_SIZE) {
			/* the device has not read enough yet; keep the batch for the next pump */
			return 0;
		}
		uint32_t pos = 0, split = dev->batch_len;
		while (pos < dev->batch_len) {
			if (dev->hw + pos >= RING_SIZE) {
				split = pos;
				break;
			}
			pos += 4 + (((get32(dev->batch + pos) & 0xFFFFFF) + 3) & ~3u);
		}
		if (write_entries(dev, dev->hw, 0, split) != 0)
			return -1;
		if (split < dev->batch_len && write_entries(dev, dev->hw + split - RING_SIZE, split, dev->batch_len) != 0)
			return -1;
		dev->hw = (dev->hw + dev->batch_len) % RING_SIZE;
		dev->batch_len = 0;
		dev->batch_last = 0;
	}
	uint32_t doorbell = (((dev->dr >> 12) & 0xFF) << 24) | ((dev->hw / 4) & 0xFFFFF);
	if (doorbell != dev->last_doorbell) {
		if (doorbell_write(dev->handle, DB_HOST_WP + dev->ch, doorbell) != 0)
			return -1;
		dev->last_doorbell = doorbell;
	}
	return 0;
}

/* ---------------------------------------------------------------- bring-up */

struct cmd_step { uint32_t cmd, a0, a1, a2; };

/* Controller and port bring-up as macOS does it (Neo, macOS 27). */
static const struct cmd_step controller_steps[] = {
	{ 0x01, 0x7102, 0, 0 }, { 0x05, 0, 0, 0 }, { 0x03, 0, 0, 0 }, { 0x04, 0, 0, 0 },
	{ 0x03, 0, 0, 0 }, { 0x10, PORT, 0, 0 }, { 0x16, PORT, 0, 0 }, { 0x04, 0, 0, 0 },
};
static const struct cmd_step port_steps[] = {
	{ 0x03, 0, 0, 0 }, { 0x16, PORT, 0, 0 }, { 0x16, PORT, 0x40000, 0 }, { 0x16, PORT, 0, 0 },
	{ 0x14, PORT, 0, 0 }, { 0x16, PORT, 0, 0 }, { 0x30, PORT, 0, 0 }, { 0x40, DEV_ADDR, 0x400000, 0x40 },
};
#define N_CONTROLLER (int)(sizeof(controller_steps) / sizeof(controller_steps[0]))
#define N_PORT (int)(sizeof(port_steps) / sizeof(port_steps[0]))

static void next_step(struct kisrsm_dev *dev, int step)
{
	dev->step = step;
	dev->step_deadline = now_ms() + (step == ST_WAIT_CONNECT ? CONNECT_TIMEOUT_MS : STEP_TIMEOUT_MS);
}

static void fail(struct kisrsm_dev *dev, const char *what)
{
	usbmuxd_log(LL_ERROR, "KIS RSM: restore device bring-up failed: %s (step %d)", what, dev->step);
	dev->step = ST_FAILED;
}

/* Finds the usbmux interface (class ff/fe/02) in a configuration descriptor. */
static int find_usbmux_endpoints(struct kisrsm_dev *dev, const unsigned char *d, int length)
{
	int pos = 0, in_usbmux = 0;
	while (pos + 2 <= length && d[pos] >= 2) {
		if (d[1 + pos] == 4 && pos + 9 <= length) {
			in_usbmux = (d[pos + 5] == 0xff && d[pos + 6] == 0xfe && d[pos + 7] == 0x02 && d[pos + 4] == 2);
		} else if (d[1 + pos] == 5 && in_usbmux && pos + 7 <= length && (d[pos + 3] & 3) == 2) {
			if (d[pos + 2] & 0x80)
				dev->ep_in = d[pos + 2];
			else
				dev->ep_out = d[pos + 2];
		}
		pos += d[pos];
	}
	return (dev->ep_in && dev->ep_out) ? 0 : -1;
}

static void ascii_string(const unsigned char *d, int length, char *out, size_t out_size)
{
	size_t n = 0;
	int i;
	for (i = 2; i + 1 < length && i < d[0] && n + 1 < out_size; i += 2)
		out[n++] = (d[i + 1] || (d[i] & 0x80)) ? '?' : (char)d[i];
	out[n] = 0;
	/* new style UDID: hyphen after the first 8 digits, as usbmuxd does for USB devices */
	if (n == 24 && n + 2 < out_size) {
		memmove(out + 9, out + 8, 17);
		out[8] = '-';
	}
}

/* Control transfer steps during enumeration: issue, then wait for completion. */
static int enum_step(struct kisrsm_dev *dev, int index)
{
	switch (index) {
	case 0: return control(dev, 0x80, 0x06, 0x0100, 0, 18);
	case 1: return control(dev, 0x80, 0x06, 0x0200, 0, 9);
	case 2: return control(dev, 0x80, 0x06, 0x0200, 0, dev->config_total);
	case 3: return control(dev, 0xC0, 0x45, 0, 0, 4);        /* Apple get mode, as macOS */
	case 4: return control(dev, 0xC0, 0x52, 0, 3, 1);        /* Apple set mode 3, as macOS */
	case 5: return control(dev, 0x00, 0x09, 1, 0, 0);        /* SET_CONFIGURATION 1 */
	case 6: return control(dev, 0x80, 0x06, 0x0300 | dev->devdesc.iSerialNumber, 0x0409, 255);
	default: return 0;
	}
}
#define N_ENUM 7

static void enum_done(struct kisrsm_dev *dev, int index)
{
	switch (index) {
	case 0:
		if (dev->ctrl_len >= 18) {
			memcpy(&dev->devdesc, dev->ctrl_data, sizeof(dev->devdesc) < 18 ? sizeof(dev->devdesc) : 18);
			dev->devdesc.idVendor = dev->ctrl_data[8] | (dev->ctrl_data[9] << 8);
			dev->devdesc.idProduct = dev->ctrl_data[10] | (dev->ctrl_data[11] << 8);
			dev->devdesc.bcdDevice = dev->ctrl_data[12] | (dev->ctrl_data[13] << 8);
			dev->devdesc.bcdUSB = dev->ctrl_data[2] | (dev->ctrl_data[3] << 8);
			usbmuxd_log(LL_INFO, "KIS RSM: restore device %04x:%04x", dev->devdesc.idVendor, dev->devdesc.idProduct);
		}
		break;
	case 1:
		dev->config_total = (dev->ctrl_len >= 4) ? (dev->ctrl_data[2] | (dev->ctrl_data[3] << 8)) : 0;
		if (dev->config_total > sizeof(dev->ctrl_data))
			dev->config_total = sizeof(dev->ctrl_data);
		break;
	case 2:
		if (find_usbmux_endpoints(dev, dev->ctrl_data, dev->ctrl_len) != 0)
			fail(dev, "no usbmux interface in configuration 1");
		else
			usbmuxd_log(LL_INFO, "KIS RSM: usbmux endpoints %02x/%02x", dev->ep_out, dev->ep_in);
		break;
	case 6:
		ascii_string(dev->ctrl_data, dev->ctrl_len, dev->serial, sizeof(dev->serial));
		usbmuxd_log(LL_INFO, "KIS RSM: restore device serial %s", dev->serial);
		break;
	default:
		break;
	}
}

static void run_steps(struct kisrsm_dev *dev)
{
	uint64_t now = now_ms();
	if (dev->step >= ST_RUNNING || dev->step == ST_FAILED)
		return;
	if (now > dev->step_deadline) {
		fail(dev, "timeout");
		return;
	}
	if (dev->step >= ST_CMD_START && dev->step < ST_CMD_START + N_CONTROLLER) {
		int i = dev->step - ST_CMD_START;
		if (dev->cmd_wait == 0) {
			command(dev, controller_steps[i].cmd, controller_steps[i].a0, controller_steps[i].a1, controller_steps[i].a2);
		} else if (dev->cmd_done) {
			if (controller_steps[i].cmd == 0x16)
				dev->port_status = dev->cmd_reply[2];
			dev->cmd_wait = 0;
			next_step(dev, (i + 1 < N_CONTROLLER) ? dev->step + 1 : ST_WAIT_CONNECT);
		}
		return;
	}
	if (dev->step == ST_WAIT_CONNECT) {
		if (dev->cmd_wait && dev->cmd_done) {
			dev->port_status = dev->cmd_reply[2];
			dev->cmd_wait = 0;
		}
		/* Before the restore OS connects the port reports 0xa1; the connect arrives as event
		 * 0x40285 (0x40000 = connect change), then 0x285 (0x200 set while connected). */
		if (dev->port_status & 0x40200) {
			usbmuxd_log(LL_INFO, "KIS RSM: restore device connected (port status 0x%x)", dev->port_status);
			next_step(dev, ST_PORT_START);
		} else if (!dev->cmd_wait && now >= dev->next_status_poll) {
			command(dev, 0x16, PORT, 0, 0);
			dev->next_status_poll = now + 1000;
		}
		return;
	}
	if (dev->step >= ST_PORT_START && dev->step < ST_PORT_START + N_PORT) {
		int i = dev->step - ST_PORT_START;
		if (dev->cmd_wait == 0) {
			command(dev, port_steps[i].cmd, port_steps[i].a0, port_steps[i].a1, port_steps[i].a2);
		} else if (dev->cmd_done) {
			dev->cmd_wait = 0;
			next_step(dev, (i + 1 < N_PORT) ? dev->step + 1 : ST_ENUM_START);
		}
		return;
	}
	if (dev->step >= ST_ENUM_START && dev->step < ST_ENUM_START + N_ENUM) {
		int i = dev->step - ST_ENUM_START;
		if (!dev->ctrl_active) {
			enum_step(dev, i);
		} else if (dev->ctrl_done) {
			dev->ctrl_active = 0;
			if (dev->ctrl_status != 1) {
				if (i == 3 || i == 4) {
					/* optional Apple mode requests: clear the stall and go on */
					command(dev, 0x44, DEV_ADDR, 0, 0);
					dev->cmd_wait = 0;
				} else {
					fail(dev, "control transfer stalled");
					return;
				}
			} else {
				enum_done(dev, i);
				if (dev->step == ST_FAILED)
					return;
			}
			next_step(dev, (i + 1 < N_ENUM) ? dev->step + 1 : ST_OPEN_EPS);
		}
		return;
	}
	if (dev->step == ST_OPEN_EPS || dev->step == ST_OPEN_EPS + 1) {
		uint8_t ep = (dev->step == ST_OPEN_EPS) ? dev->ep_out : dev->ep_in;
		if (dev->cmd_wait == 0) {
			command(dev, 0x40, ((uint32_t)ep << 8) | DEV_ADDR, 0x2000022, 0x200);
		} else if (dev->cmd_done) {
			dev->cmd_wait = 0;
			if (dev->step == ST_OPEN_EPS) {
				next_step(dev, ST_OPEN_EPS + 1);
			} else {
				usbmuxd_log(LL_NOTICE, "KIS RSM: restore device %s ready on channel %d", dev->serial, dev->ch);
				dev->step = ST_RUNNING;
			}
		}
	}
}

/* ---------------------------------------------------------------- data phase */

static void run_data(struct kisrsm_dev *dev)
{
	uint16_t ep_in_id = ((uint16_t)dev->ep_in << 8) | DEV_ADDR;
	uint8_t out_cls = (DEV_ADDR << 4) | (dev->ep_out & 0x0F);
	while (dev->in_queued < IN_READS) {
		emit_words(dev, CLS_XFER, 0x1000, ep_in_id, IN_READ_SIZE, 0);
		dev->in_queued++;
	}
	while (dev->tx_head && dev->out_credits > 0) {
		struct txbuf *tx = dev->tx_head;
		uint32_t remaining = tx->length - tx->offset;
		uint32_t chunk = remaining > BULK_CHUNK ? BULK_CHUNK : remaining;
		if (remaining == 0 && !tx->zlp)
			chunk = 0;
		if (ring_used(dev) + dev->batch_len + chunk + 8 + RING_MARGIN > RING_SIZE)
			break;
		if (remaining > 0) {
			emit(dev, out_cls, tx->data + tx->offset, chunk);
			tx->offset += chunk;
		} else {
			emit(dev, out_cls, NULL, 0); /* zero-length packet */
			tx->zlp = 0;
		}
		dev->out_credits--;
		dev->last_activity = now_ms();
		if (tx->offset == tx->length && !tx->zlp) {
			dev->tx_head = tx->next;
			if (!dev->tx_head)
				dev->tx_tail = NULL;
			free(tx->data);
			free(tx);
		}
	}
}

/* ---------------------------------------------------------------- API */

struct kisrsm_dev *kisrsm_probe(libusb_device *device)
{
	libusb_device_handle *handle = NULL;
	uint32_t bells[256];
	int available = 0, ch;
	if (libusb_open(device, &handle) != 0 || !handle)
		return NULL;
	if (libusb_claim_interface(handle, 0) != 0) {
		libusb_close(handle);
		return NULL;
	}
	if (read_doorbells(handle, bells, &available) != 0 || !available || (ch = find_channel(bells, CHANNEL_VHCI)) < 0) {
		libusb_release_interface(handle, 0);
		libusb_close(handle);
		return NULL;
	}
	if (bells[DB_HOST_WP + ch] != 0) {
		/* another host already brought this channel up; its port state is unknown */
		usbmuxd_log(LL_WARNING, "KIS RSM: restore channel %d of device %d-%d is already in use", ch,
			libusb_get_bus_number(device), libusb_get_device_address(device));
		libusb_release_interface(handle, 0);
		libusb_close(handle);
		return NULL;
	}
	if (config_write(handle, KIS_INDEX_PORTAL_ENABLE, KIS_PORTAL_ENABLE_RSM) != 0) {
		libusb_release_interface(handle, 0);
		libusb_close(handle);
		return NULL;
	}
	struct kisrsm_dev *dev = calloc(1, sizeof(struct kisrsm_dev));
	dev->d2h_buf = malloc(D2H_READ_CHUNK);
	if (!dev || !dev->d2h_buf) {
		if (dev)
			free(dev->d2h_buf);
		free(dev);
		libusb_release_interface(handle, 0);
		libusb_close(handle);
		return NULL;
	}
	dev->handle = handle;
	dev->ch = ch;
	dev->desc = bells[DB_CHAN_DESC + ch];
	dev->h2d = bells[DB_H2D_BASE + 2 * ch] | ((uint64_t)bells[DB_H2D_BASE + 2 * ch + 1] << 32);
	dev->d2h = bells[DB_D2H_BASE + 2 * ch] | ((uint64_t)bells[DB_D2H_BASE + 2 * ch + 1] << 32);
	dev->dr = (bells[DB_DEVICE_WP + ch] & 0xFFFFF) * 4 % RING_SIZE;
	dev->drp = (bells[DB_DEVICE_WP + ch] >> 24) * 0x1000;
	next_step(dev, ST_CMD_START);
	dev->last_activity = now_ms();
	usbmuxd_log(LL_NOTICE, "KIS RSM: restore channel %d on device %d-%d (H2D 0x%llx, D2H 0x%llx)", ch,
		libusb_get_bus_number(device), libusb_get_device_address(device),
		(unsigned long long)dev->h2d, (unsigned long long)dev->d2h);
	return dev;
}

enum kisrsm_state kisrsm_pump(struct kisrsm_dev *dev)
{
	if (dev->step == ST_FAILED)
		return KISRSM_CLOSED;
	if (read_records(dev) != 0) {
		usbmuxd_log(LL_NOTICE, "KIS RSM: restore channel %d closed", dev->ch);
		dev->step = ST_FAILED;
		return KISRSM_CLOSED;
	}
	run_steps(dev);
	if (dev->step == ST_RUNNING)
		run_data(dev);
	if (flush(dev) != 0) {
		dev->step = ST_FAILED;
		return KISRSM_CLOSED;
	}
	if (dev->step == ST_FAILED)
		return KISRSM_CLOSED;
	if (dev->step == ST_RUNNING) {
		if (!dev->ready_reported) {
			dev->ready_reported = 1;
			return KISRSM_READY;
		}
		return KISRSM_RUNNING;
	}
	return KISRSM_PENDING;
}

int kisrsm_poll_interval(struct kisrsm_dev *dev)
{
	if (dev->tx_head || dev->batch_len || dev->step < ST_RUNNING)
		return dev->step == ST_WAIT_CONNECT ? 50 : 0;
	/* poll fast while data flows, slower when idle */
	return (now_ms() - dev->last_activity < 200) ? 1 : 10;
}

int kisrsm_send(struct kisrsm_dev *dev, unsigned char *buf, int length)
{
	struct txbuf *tx = calloc(1, sizeof(struct txbuf));
	if (!tx)
		return -1; /* the caller still owns buf */
	tx->data = buf;
	tx->length = (uint32_t)length;
	tx->zlp = (length % kisrsm_max_packet_size(dev)) == 0;
	if (dev->tx_tail)
		dev->tx_tail->next = tx;
	else
		dev->tx_head = tx;
	dev->tx_tail = tx;
	return 0;
}

void kisrsm_set_rx_callback(struct kisrsm_dev *dev, kisrsm_rx_cb cb, void *user_data)
{
	dev->rx_cb = cb;
	dev->rx_user = user_data;
}

const struct libusb_device_descriptor *kisrsm_device_descriptor(struct kisrsm_dev *dev)
{
	return &dev->devdesc;
}

const char *kisrsm_serial(struct kisrsm_dev *dev)
{
	return dev->serial;
}

libusb_device_handle *kisrsm_handle(struct kisrsm_dev *dev)
{
	return dev->handle;
}

int kisrsm_max_packet_size(struct kisrsm_dev *dev)
{
	(void)dev;
	return 512;
}

void kisrsm_free(struct kisrsm_dev *dev)
{
	if (!dev)
		return;
	while (dev->tx_head) {
		struct txbuf *tx = dev->tx_head;
		dev->tx_head = tx->next;
		free(tx->data);
		free(tx);
	}
	if (dev->handle) {
		libusb_release_interface(dev->handle, 0);
		libusb_close(dev->handle);
	}
	free(dev->batch);
	free(dev->d2h_buf);
	free(dev);
}
