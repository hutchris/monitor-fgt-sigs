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
	#try connecting to the device
	try:
		#load parameters from prtg
		data = json.loads(sys.argv[1])
		
		#extract key values from parameters
		password = data['linuxloginpassword']
		host = data['host']
		username = data['linuxloginusername']
		device = ConnectHandler(device_type='fortinet',ip=host,username=username,password=password,global_delay_factor=2)
		
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
		
		#if the ssh session return the type of strings that we are looking for then the Output lists will have a length > 0.
		#In this case, build the prtg sensor and add the channels. Otherwise put the unexpected result in an error for debugging.
		if len(avOutput) > 0 and len(ipsOutput) > 0:
			now = datetime.now()
			daysWithoutIPS = str(max(0,(now - max(ipsOutput)).days))
			daysWithoutAV = str(max(0,(now - max(avOutput)).days))
			sensor = CustomSensorResult("OK")
			sensor.add_channel(channel_name="Days since AV update",unit="Days",value=daysWithoutAV)
			sensor.add_channel(channel_name="Days since IPS update",unit="Days",value=daysWithoutIPS)
		else:
			sensor = CustomSensorResult()
			sensor.add_error("Unexpected output: {0}".format(output))
	
		device.disconnect()
	#catch an error for time out. this will occur if device is unreachable or ssh is broken
	except ssh_exception.NetMikoTimeoutException:
		sensor = CustomSensorResult("")
		sensor.add_error("Device Unresponsive")
		
	#catch an error of wrong creds, this will occur if the AD account is locked out or pw expired	
	except ssh_exception.NetMikoAuthenticationException:
		sensor = CustomSensorResult("")
		sensor.add_error("Authentication failure")
	
	#catch all other errors and send error string to prtg. Otherwise prtg displays an ugly xml/json parsing error.
	except Exception as err:
		sensor = CustomSensorResult("")
		sensor.add_error(repr(err))
	
	#send the sensor to prtg in json format.
	print(sensor.get_json_result())
