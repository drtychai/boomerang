# Project Name

Boomerang

## Installation

In order to use Boomerang, the following must be installed:

	python 2.7x
	python Stem module
	Tor 

Please see online documentation on how to install each of the above. 

The following line must also be added to your torrc file (typically found in /usr/local/etc/tor/):
	```ControlPort = 9051```

## Usage

Usage of Boomerang is quite simple. Begin by starting Tor (running the command ```tor``` in a terminal). Once tor is fully bootstrapped, Boomerang can be used.

To host a server:

	python boomerang.py —-server=NAME_OF_SERVER
	python boomerang.py -s NAME_OF_SERVER
	

To connect to a server:

	python boomerang.py —-connect=NAME_OF_SERVER
	python boomerang.py -c NAME_OF_SERVER


To view help menu:

	python boomerang.py —-help
	python boomerang.py -h
	


## Bugs

Please note the user interface does not allow the use of backspace, however the delete key does work. 

## Credits

Justin Angra

## License

No licensing, but this program is free and available for distribution and modification. 
