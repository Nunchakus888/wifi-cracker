import sys
import CoreWLAN
import CoreLocation


def get_interface_object(interface):
    # First check available WiFi Interfaces. If given
    # inteface is valid and present in list return
    # CoreWLAN interface object else return None.
    interfaces_list = CoreWLAN.CWWiFiClient.interfaceNames()
    if interface in interfaces_list:
        return CoreWLAN.CWWiFiClient.sharedWiFiClient().interfaceWithName_(interface)
    else:
        return None


def scan_ssid(interface, ssid):
    CoreLocation.CLLocationManager.new().requestAlwaysAuthorization()
    cwinterface = get_interface_object(interface)
    if cwinterface is not None:
        scan = cwinterface.scanForNetworksWithName_error_(
            ssid, None)
        for ssids in scan:
            if ssids is not None:
                for ssid in ssids:
                    print(ssid)
        return
    else:
        print("Not able to get interface object.")


if __name__ == "__main__":
    CoreLocation.CLLocationManager.new().requestAlwaysAuthorization()
    if len(sys.argv) < 2:
        print("Mandatory argument missing.\n"
              "Usage: For SCAN /usr/bin/python bssid.py interface_name ssid")
    interface = sys.argv[1]
    ssid = sys.argv[2]
    scan_ssid(interface, ssid)
