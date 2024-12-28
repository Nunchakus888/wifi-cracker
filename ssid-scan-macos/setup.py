from setuptools import setup

APP = ['bssid.py']
OPTIONS = {
    'argv_emulation': True
}

setup(
    app=APP,
    options=dict(
        py2app=dict(
            plist=dict(
                NSLocationWhenInUseUsageDescription="Need access to location",
                NSLocationAlwaysUsageDescription="Need access to location",
                NSLocationUsageDescription="Need access to location",
                NSLocationAlwaysAndWhenInUseUsageDescription="Need access to location"
            )
        )
    )
)
