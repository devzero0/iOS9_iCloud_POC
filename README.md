# IOS 9 iCloud Proof of Concept

This is a (probably poor) reimplementation of some of the functionality of [InflatableDonkey](https://github.com/horrorho/InflatableDonkey) in Python 2.7 for folks that want to play with trying to recover iOS 9 iCloud backups in Python. For more information on what this is all about see the [InflatableDonkey](https://github.com/horrorho/InflatableDonkey) project and [this iLoot issue](https://github.com/hackappcom/iloot/issues/62).

The code is far from "production quality" and is just a Proof of Concept for hacking on.

## Build
First, create a virtualenv, as one is wont to do. E.g.:

    mkvirtualenv ios9_icloud_poc --no-site-packages

Then install the requirements:

    pip install -r requirements.txt

## Usage
    
    iOS9_iCloud_POC.py [-d <device> -s <snapshot> -m <manifest>] (<token> | <appleid> <password>)
    iOS9_iCloud_POC.py --token <appleid> <password>
    iOS9_iCloud_POC.py (-h | --help)
    iOS9_iCloud_POC.py --version

      Options:
      -d,--device <int>     Device, default: 0 = first device
      -s,--snapshot <int>   Snapshot, default: 0 = first snapshot
      -m,--manifest <int>   Manifest, default: 0 = first manifest
      --token               Display dsPrsID:mmeAuthToken token and exit
      -h --help             Show this screen
      --version             Show version

## Notes
As noted in the [InflatableDonkey](https://github.com/horrorho/InflatableDonkey) writeup, the cryptographical aspects are troublesome. 

## Credits
[horrorho](https://github.com/horrorho) for inflatableDonkey, and everyone that is credited there

[hackappcom](https://github.com/hackappcom) for iLoot
