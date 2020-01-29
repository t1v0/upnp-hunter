UPnP BHunter
===================

# Description
UPnP BHunter is a Burp Suite Extension written in Python/Jython which could be useful to find active UPnP services/devices and extract the related SOAP requests (IPv4 and IPv6 are supported), then analyze them using any of the various Burp tools (i.e. Intruder, Repeater).


# Usage
UPnP BHunter provides a nice ;) three-step hunting console: 
1. UPnP Discovery (definition of target IP address version and discovery of active UPnP via SSDP protocol)
2. UPnP Selection (selection of the found UPnP service and action) 
3. UPnP Attack (extraction of the found UPnP SOAP requests). 

The tutorial below explain, better than so many words, how to use the plugin:

![UBH-Tutorial](ubh_tutorial.gif)


# Author
- UPnP BHunter plugin was developed by Maurizio Siddu
- This version of UPnP BHunter plugin was modified by t1v0

# Changes in this version
- Changed MSearch to perform both ssdp:all and upnp:rootdevices since some devices will only respond to one or the other (i.e. Belkin WeMo switch)
- Fixed unsigned integer conversion error when creating byte array
- Modified the UI to expose services and actions directly and show the full request in a text area with the option to send to either repeater or interpreter
- Changed the xml parsing to use xmldom library instead of regex search since some scdp files don't follow the syntax previously expected (i.e. Belkin WeMo switch had <retVal/> tags which broke argument parsing)


# GNU License
Copyright (c) 2019 UPnP BHunter

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>

