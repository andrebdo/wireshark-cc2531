/*
 * Wireshark extcap interface for the Texas Instruments CC2531 USB dongle
 * with the factory-installed IEEE 802.15.4 packet sniffer firmware.
 *
 * Copyright (C) 2019 Andre B. Oliveira
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <initguid.h>
#include <setupapi.h>
#include <usbiodef.h>
#include <winusb.h>
#else
#include <dirent.h>
#include <fcntl.h>
#include <linux/usbdevice_fs.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <unistd.h>
#endif

#ifdef _WIN32
typedef WINUSB_INTERFACE_HANDLE cc2531_handle;
#else
typedef int cc2531_handle;
#endif

/*
 * Opens the first TI CC2531 USB device found on the system.
 */
static cc2531_handle
cc2531_open(void)
{
#ifdef _WIN32
    WINUSB_INTERFACE_HANDLE winusbhandle = INVALID_HANDLE_VALUE;
    const GUID *const guid = &GUID_DEVINTERFACE_USB_DEVICE;
    HDEVINFO hdevinfo = SetupDiGetClassDevsA(guid, 0, 0, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (hdevinfo != INVALID_HANDLE_VALUE) {
        SP_DEVICE_INTERFACE_DATA data;
        data.cbSize = sizeof(data);
        for (int i = 0; SetupDiEnumDeviceInterfaces(hdevinfo, 0, guid, i, &data); i++) {
            struct { SP_DEVICE_INTERFACE_DETAIL_DATA_A data; char buf[128]; } detail;
            detail.data.cbSize = sizeof(detail.data);
            if (SetupDiGetDeviceInterfaceDetailA(hdevinfo, &data, &detail.data, sizeof(detail), 0, 0)) {
                if (strncmp(detail.data.DevicePath, "\\\\?\\usb#vid_0451&pid_16ae", 25) == 0) {
                    HANDLE handle = CreateFileA(detail.data.DevicePath, GENERIC_WRITE | GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, 0);
                    if (handle != INVALID_HANDLE_VALUE) {
                        if (WinUsb_Initialize(handle, &winusbhandle)) {
                            break;
                        }
                        CloseHandle(handle);
                    }
                }
            }
        }
        SetupDiDestroyDeviceInfoList(hdevinfo);
    }
    return winusbhandle;
#else
    const unsigned char cc2531_usb_device_descriptor[] = {
        0x12,        /* bLength */
        0x01,        /* bDescriptorType */
        0x00, 0x02,  /* bcdUSB */
        0x00,        /* bDeviceClass */
        0x00,        /* bDeviceSubClass */
        0x00,        /* bDeviceProtocol */
        0x20,        /* bMaxPacketSize0 */
        0x51, 0x04,  /* idVendor */
        0xae, 0x16,  /* idProduct */
    };
    char path[21] = "/dev/bus/usb/";  /* "/dev/bus/usb/XXX/YYY" */
    DIR *dir1 = opendir(path);
    if (dir1) {
        struct dirent e, *r;
        while (readdir_r(dir1, &e, &r) == 0 && r != NULL) {
            if (strlen(e.d_name) == 3) {
                path[13] = e.d_name[0];
                path[14] = e.d_name[1];
                path[15] = e.d_name[2];
                path[16] = '/';
                path[17] = 0;
                DIR *dir2 = opendir(path);
                if (dir2) {
                    while (readdir_r(dir2, &e, &r) == 0 && r != NULL) {
                        if (strlen(e.d_name) == 3) {
                            path[17] = e.d_name[0];
                            path[18] = e.d_name[1];
                            path[19] = e.d_name[2];
                            int fd = open(path, O_RDWR);
                            if (fd >= 0) {
                                char descriptor[sizeof(cc2531_usb_device_descriptor)];
                                int n = read(fd, descriptor, sizeof(descriptor));
                                if (n == sizeof(descriptor) && memcmp(descriptor, cc2531_usb_device_descriptor, n) == 0) {
                                    closedir(dir2);
                                    closedir(dir1);
                                    return fd;
                                }
                                close(fd);
                            }
                        }
                    }
                    closedir(dir2);
                }
            }
        }
        closedir(dir1);
    }
    return -1;
#endif
}

/*
 * Executes a USB control transfer on the CC2531.
 * Returns the number of data bytes transferred, or -1 in case of error.
 */
static int
cc2531_control(cc2531_handle handle, int request, int index, int length, unsigned char data_byte)
{
    const int request_type = 64;
#ifdef _WIN32
    ULONG transferred;
    WINUSB_SETUP_PACKET setup;
    setup.RequestType = request_type;
    setup.Request = request;
    setup.Value = 0;
    setup.Index = index;
    setup.Length = length;
    if (!WinUsb_ControlTransfer(handle, setup, &data_byte, length, &transferred, NULL)) {
        return -1;
    }
    return transferred;
#else
    struct usbdevfs_ctrltransfer ctrl;
    ctrl.bRequestType = request_type;
    ctrl.bRequest = request;
    ctrl.wValue = 0;
    ctrl.wIndex = index;
    ctrl.wLength = length;
    ctrl.data = &data_byte;
    ctrl.timeout = 5000; /* milliseconds */
	return ioctl(handle, USBDEVFS_CONTROL, &ctrl);
#endif
}

/*
 * Sends the commands to the CC2531 to start capturing
 * on the specified 802.15.4 2.4GHz radio channel (11 to 26).
 */
static void
cc2531_start(cc2531_handle handle, int channel)
{
    /* Set power */
    cc2531_control(handle, 197, 4, 0, 0);

    /* Wait until powered up */
#ifdef _WIN32
    Sleep(1000);
#else
    sleep(1);
#endif

    /* Set channel */
    cc2531_control(handle, 210, 0, 1, channel);
    cc2531_control(handle, 210, 1, 1, 0);

    /* Start capture */
    cc2531_control(handle, 208, 0, 0, 0);
}

static void
cc2531_stop(cc2531_handle handle)
{
    cc2531_control(handle, 209, 0, 0, 0);
}

/*
 * Reads the captured packet bytes from the CC2531.
 */
static int
cc2531_read(cc2531_handle handle, void *data, int length)
{
    const int endpoint = 0x83;
#ifdef _WIN32
    ULONG transferred;
    if (!WinUsb_ReadPipe(handle, endpoint, data, length, &transferred, NULL)) {
        return -1;
    }
    return transferred;
#else
    struct usbdevfs_bulktransfer bulk;
    bulk.ep = endpoint;
    bulk.len = length;
    bulk.data = data;
    bulk.timeout = 5000;  /* milliseconds */
	return ioctl(handle, USBDEVFS_BULK, &bulk);
#endif
}

/*
 * Gets a CC2531 capture packet from a buffer.
 * The format of the CC2531 capture packets is:
 *
 * Offset  Bytes  Description
 * --------------------------
 * 0       1      ?
 * 1       1      Number of bytes from offset 3 to the end of this packet
 * 2       1      ?
 * --------------------------
 * 3       4      Some kind of timestamp
 * 7       1      Payload length (N)
 * -------------------------------------
 * 8       N-2    Payload
 * 8+N-2   1      RSSI
 * 8+N-1   1      CRC OK
 *
 * The CC2531 also sends the following packet periodically when idle:
 * 01 01 00 XX  (where XX is a counter that increments by 4)
 */
static int
cc2531_get_packet(unsigned char *buffer, int *head, int *tail, int *length)
{
    for (;;) {
        int available = *head - *tail;
        if (*tail > 0) {
            memmove(buffer, buffer + *tail, available);
            *head = available;
            *tail = 0;
        }
        if (available < 4) {
            return 0;
        }
        if (buffer[0] == 1 && buffer[1] == 1 && buffer[2] == 0) {
            /* alive packet */
            *tail = 4;
            continue;
        }
        if (available < 8) {
            return 0;
        }
        int phy_payload_length = buffer[7];
        if (available < 8 + phy_payload_length) {
            return 0;
        }
        *head -= 8;
        memmove(buffer, buffer + 8, *head);
		*tail = phy_payload_length;
		*length = phy_payload_length;
		return 1;
    }
}

/*
 * Writes the header of a PCAP file.
 * References:
 * - https://wiki.wireshark.org/Development/LibpcapFileFormat
 * - http://www.tcpdump.org/linktypes.html
 */
static void
cc2531_write_pcap_global_header(FILE *file)
{
    const struct pcap_global_header {
        int magic_number;
        short version_major;
        short version_minor;
        int thiszone;
        int sigfigs;
        int snaplen;
        int network;
    } header = {
        0xa1b2c3d4,  /* byte-order magic number */
        2,           /* version major number */
        4,           /* version minor number */
        0,           /* timezone correction (GMT) */
        0,           /* timestamp accuracy (microseconds) */
        127,         /* snapshot length (IEEE 802.15.4 PHY payload max size) */
        195,         /* network link type (LINKTYPE_IEEE802_15_4_WITHFCS) */
    };
    fwrite(&header, sizeof(header), 1, file);
    fflush(file);
}

/*
 * Writes the header of a capture packet.
 */
static void
cc2531_write_pcap_packet(FILE *file, const void *packet, int length)
{
    struct timeval t;
#ifdef _WIN32
    /* Get the system time as hundreds of nanoseconds since Jan 1 1601 */
    FILETIME ft;
    ULARGE_INTEGER hns;
    GetSystemTimeAsFileTime(&ft);
    hns.LowPart = ft.dwLowDateTime;
    hns.HighPart = ft.dwHighDateTime;
    /* Convert to seconds and microseconds since Jan 1 1970 */
    t.tv_sec = (long)(hns.QuadPart / 10000000 - 11644473600);
    t.tv_usec = (long)(hns.QuadPart / 10 % 1000000);
#else
    gettimeofday(&t, NULL);
#endif
    struct pcap_packet_header {
      int ts_sec;
      int ts_usec;
      int incl_len;
      int orig_len;
    } header = {
      t.tv_sec,   /* timestamp seconds */
      t.tv_usec,  /* timestamp microseconds */
      length,     /* number of bytes of packet data that follow this header */
      length,     /* number of bytes of the packet */
    };
    fwrite(&header, sizeof(header), 1, file);
    fwrite(packet, length, 1, file);
    fflush(file);
}

/*
 * Starts capturing packets and writes them in PCAP format.
 */
static int
cc2531_capture(int channel, const char *path)
{
    cc2531_handle handle;

    FILE *file = fopen(path, "wb");
    if (file)
    {
        cc2531_write_pcap_global_header(file);

        handle = cc2531_open();
        cc2531_start(handle, channel);

        unsigned char buffer[512];
        int tail = 0;
        int head = 0;
        for (;;)
        {
            int n = cc2531_read(handle, buffer + head, sizeof(buffer) - head);
            if (n < 0) {
                break;
            }
            head += n;

            int length;
            while (cc2531_get_packet(buffer, &head, &tail, &length))
            {
                if (length > 127)
                {
                    cc2531_stop(handle);
                    return 1;
                }
                cc2531_write_pcap_packet(file, buffer, length);
            }
        }

        cc2531_stop(handle);
    }

    return 1;
}

/*
 * Wireshark executes this program as follows:
 * 1. cc2531 --extcap-interfaces --extcap-version=3.0
 * 2. cc2531 --extcap-config --extcap-interface cc2531
 * 3. cc2531 --extcap-dlts --extcap-interface cc2531
 * 4. cc2531 --capture --extcap-interface cc2531 --fifo \\.\pipe\wireshark_extcap_cc2531_YYYYMMDDhhmmss --channel XX
 */
int main(int argc, char *argv[])
{
    int channel = 0;
    char *fifo = NULL;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--extcap-interfaces") == 0) {
            puts("extcap {version=0.0.1}\n"
                 "interface {value=cc2531}{display=TI CC2531 802.15.4 packet sniffer}");
            return 0;
        } else if (strcmp(argv[i], "--extcap-config") == 0) {
            puts("arg {number=0}{call=--channel}{display=IEEE 802.15.4 2.4GHz radio channel to capture (11 to 26)}{type=integer}{range=11,26}{default=11}");
            return 0;
        } else if (strcmp(argv[i], "--extcap-dlts") == 0) {
            puts("dlt {number=195}{name=cc2531}{display=IEEE802_15_4_WITHFCS (TI CC24xx FCS format)}");
            return 0;
        } else if (strcmp(argv[i], "--channel") == 0) {
            channel = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--fifo") == 0) {
            fifo = argv[++i];
        }
    }

    if (channel && fifo) {
        return cc2531_capture(channel, fifo);
    }

    puts("Usage:\n"
         " cc2531 --extcap-interfaces\n"
         " cc2531 --extcap-config\n"
         " cc2531 --extcap-dlts\n"
         " cc2531 --channel <11-26> --fifo <path>");
    return 1;
}
