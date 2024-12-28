import CoreLocation
from time import sleep

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