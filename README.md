# monitor-fgt-sigs
Python-built custom sensor for PRTG that monitors the age of AV and IPS signatures of fortigate firewalls

This file needs to be placed in the custom sensors folder of the PRTG program files directory. If you are using a remote probe the script needs to be stored on the probe. This is usually: C:\Program Files (x86)\PRTG Network Monitor\Custom Sensors\python

You will also need to install netmiko to the instance of python that is included with PRTG. To do this it is recommended to install pip.

1. Download the get-pip.py file from here: https://pip.pypa.io/en/stable/installing/
2. Open cmd as admin and run: C:\Program Files (x86)\PRTG Network Monitor\Python34\python.exe C:\<path to file>\get-pip.py
3. Run: C:\Program Files (x86)\PRTG Network Monitor\Python34\Scripts\pip.exe install netmiko

In PRTG you will need to add credentials to the device, the script uses the credentials called CREDENTIALS FOR LINUX/SOLARIS/MAC OS (SSH/WBEM) SYSTEMS. Add can either add unique credentials to each device or add them to a device group and inherit them to the devices. 

You should now be able to add a sensor to the fortigate device in PRTG, choose "custom python sensor" and pick the script from the drop down. Select "Transmit Linux Credentials"
