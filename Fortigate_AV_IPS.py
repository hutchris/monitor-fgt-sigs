import json,re,sys,os,time
from netmiko import ConnectHandler,ssh_exception
from datetime import datetime,timedelta
from paepy.ChannelDefinition import CustomSensorResult

#take the raw output from the ssh session and extract a list of strings based the compiled regex
def ExtractLines(outputString,regex):
	outputlines = outputString.split("\n")
	returnList = []
	#for each line in output if matched against regex, append to list
	for line in outputlines:
		if regex.match(line):
			returnList.append(line.replace("\r",""))
	return(returnList)

#take the list of strings and turn each into a date object.	
def ExtractDates(sigString):
	dateOutput = []
	#for each av/ips signature turn the string into a dateobject based on the text after the "(" symbol
	for string in sigString:
		date = string.split("(")[1]
		dateObj = datetime.strptime(date,"%Y-%m-%d %H:%M)")
		dateOutput.append(dateObj)
	return(dateOutput)

if __name__ == "__main__":
	#load parameters from prtg
	data = json.loads(sys.argv[1])
	
	#extract key values from parameters
	password = data['linuxloginpassword']
	host = data['host']
	username = data['linuxloginusername']
	
	sensor = CustomSensorResult("")
	connectSuccess = ""
	connectCount = 1
	
	while connectSuccess not in ["success","failure"] and connectCount < 4: 
		try:
			#try connecting to the device
			device = ConnectHandler(device_type='fortinet',ip=host,username=username,password=password,global_delay_factor=connectCount)
			connectSuccess = "success"
		
		#this catches the ValueError("Unable to find prompt: {}") error that occurs on high latency devices. Increase the delay and try again.
		except ValueError:
			connectCount += 1
		
		#catch an error for timeout. If device is unreachable or ip address is incorrect.
		except ssh_exception.NetMikoTimeoutException:
			sensor.add_error("Device Unresponsive")
			connectSuccess = "failure"
			
		#catch an error of wrong creds, this will occur if the AD account is locked out or pw expired	
		except ssh_exception.NetMikoAuthenticationException:
			sensor.add_error("Authentication failure")
			connectSuccess = "failure"
			
		#catch all other errors and send error string to prtg. Otherwise prtg displays an ugly xml/json parsing error.
		except Exception as err:
			sensor.add_error(repr(err))	
			connectSuccess = "failure"
	
	if connectSuccess == "success":
		#send command to fortigate and recieve output
		output = device.send_command_timing('get system status')
		
		#compile regex queries
		IPSreg = re.compile(r"^IPS")
		AVreg = re.compile(r"(^Virus)|(^Extended)")
		
		#turn the lines of text pertaining to each UTM into date objects
		avStrings = ExtractLines(output,AVreg)
		ipsStrings = ExtractLines(output,IPSreg)
		count = 3
		
		while (len(avStrings) == 0 or len(ipsStrings) == 0) and count < 20:
			output = device.send_command_timing('get system status',delay_factor=count)
			avStrings = ExtractLines(output,AVreg)
			ipsStrings = ExtractLines(output,IPSreg)
			time.sleep(1)
			count += 1
		
		#turns signature strings into dateobjects
		ipsOutput = ExtractDates(ipsStrings)
		avOutput = ExtractDates(avStrings)
		
		if device.vdoms:
			vdoms = device.send_command_timing('config global')
		output2 = device.send_command_timing('diagnose autoupdate versions')
		
		EXPreg = re.compile(r"Contract Expiry Date:")
		expStrings = ExtractLines(output2,EXPreg)
		expString = expStrings[8]
		
		if expString.upper().find("N/A") != -1:
			update = device.send_command_timing("execute update-now")
			time.sleep(30)
			
		count = 3
		
		while (len(expString) == 0 or expString.upper().find("N/A") != -1) and count < 5:
			output2 = device.send_command_timing('diagnose autoupdate versions',delay_factor=count)
			expStrings = ExtractLines(output2,EXPreg)
			expString = expStrings[8]
			time.sleep(1)
			count += 1
		
		deviceContract = expString[expString.index(":")+2:]
		daysUntilExpiry = (datetime.strptime(deviceContract,"%a %b %d %Y") - datetime.now()).days
			
		#if the ssh session return the type of strings that we are looking for then the Output lists will have a length > 0.
		#In this case, build the prtg sensor and add the channels. Otherwise put the unexpected result in an error for debugging.
		if len(avOutput) > 0 and len(ipsOutput) > 0:
			now = datetime.now()
			daysWithoutIPS = str(max(0,(now - max(ipsOutput)).days))
			daysWithoutAV = str(max(0,(now - max(avOutput)).days))
			sensor.add_channel(channel_name="Days since AV update",unit="Days",value=daysWithoutAV,is_limit_mode=True,limit_max_warning=2,limit_max_error=14)
			sensor.add_channel(channel_name="Days since IPS update",unit="Days",value=daysWithoutIPS,is_limit_mode=True,limit_max_warning=2,limit_max_error=14)
			sensor.add_channel(channel_name="Days until contract expires",unit="Days",value=daysUntilExpiry,is_limit_mode=True,limit_min_warning=90,limit_min_error=7,primary_channel=True)
		else:
			sensor.add_error("Unexpected output: {0}".format(output))
		
		device.disconnect()

	#send the sensor to prtg in json format.
	print(sensor.get_json_result())
