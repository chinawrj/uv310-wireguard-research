"""Read USB identity and interface descriptors without configuring devices.

Requires PyUSB and libusb. Never reads serial numbers, claims interfaces,
sends endpoint payloads, resets devices, or changes their configuration.
An empty list in a sandbox does not prove hardware is absent.
"""
import argparse
import datetime
import json
from pathlib import Path
import usb.core
import usb.util

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output', type=Path)
a = p.parse_args()
rows = []
for device in usb.core.find(find_all=True):
    row = {'vid': f'{device.idVendor:04x}', 'pid': f'{device.idProduct:04x}',
           'bus': device.bus, 'address': device.address,
           'device_class': device.bDeviceClass, 'interfaces': []}
    try:
        for field, index in [('manufacturer', device.iManufacturer),
                             ('product', device.iProduct)]:
            try:
                row[field] = usb.util.get_string(device, index) if index else None
            except usb.core.USBError as error:
                row[field + '_error'] = type(error).__name__
        for config in device:
            for interface in config:
                row['interfaces'].append({
                    'configuration': config.bConfigurationValue,
                    'interface': interface.bInterfaceNumber,
                    'alternate': interface.bAlternateSetting,
                    'class': interface.bInterfaceClass,
                    'subclass': interface.bInterfaceSubClass,
                    'protocol': interface.bInterfaceProtocol,
                    'endpoints': [{'address': hex(e.bEndpointAddress),
                                   'attributes': e.bmAttributes,
                                   'max_packet': e.wMaxPacketSize}
                                  for e in interface]})
    except usb.core.USBError as error:
        row['descriptor_error'] = type(error).__name__
    finally:
        usb.util.dispose_resources(device)
    rows.append(row)
result = {'observed_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'scope': 'USB identity and interface descriptors only; serials omitted',
          'devices': rows}
output = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
if a.output:
    a.output.write_text(output)
print(output, end='')
