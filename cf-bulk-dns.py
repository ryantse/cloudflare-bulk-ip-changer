#!/usr/bin/python
#
# CloudFlare Bulk IP Changer
#
# The goal of this script was to implement a bulk IP changer
# that changes all instances of an IP to another IP. This script
# requires no packages/dependencies other than built-in
# Python modules.
#
# Copyright (c) 2015 Ryan Tse, unless otherwise noted.
# All rights reserved. CloudFlare is a registered trademark
# of CloudFlare, Inc.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
# CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
# OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import urllib2
import urllib
import socket
import json
import sys
import time

# Code Snippet by Ed Marshall
# https://gist.github.com/logic/2715756
class MethodRequest(urllib2.Request):
	def __init__(self, *args, **kwargs):
		if 'method' in kwargs:
			self._method = kwargs['method']
			del kwargs['method']
		else:
			self._method = None
		return urllib2.Request.__init__(self, *args, **kwargs)

	def get_method(self, *args, **kwargs):
		if self._method is not None:
			return self._method
		return urllib2.Request.get_method(self, *args, **kwargs)
# END (https://gist.github.com/logic/2715756)

# Note: This script presumes that the API is version 4,
# this script may be incompatible with newer versions
# of the API.

CLOUDFLARE_API = "https://api.cloudflare.com/client/v4"
CLOUDFLARE_REQUESTS = []
CLOUDFLARE_REQUESTS_MAX = 1200
CLOUDFLARE_REQUESTS_PERIOD = 300

def queryVerify(question):
	valid = {"yes": True, "ye": True, "y": True, "no": False, "n": False}
	failureCount = 0
	while failureCount < 5:
		sys.stdout.write(question + " [y/N] ")
		response = raw_input().lower()
		if response == '':
			return False
		elif response in valid:
			return valid[response]
		else:
			sys.stdout.write("Unrecognized response. Please respond with either: [Y]es or [N]o.\n")
			failureCount = failureCount + 1
	print "The response(s) given could not be understood. Defaulting to \"no\"."
	return False

def verifyIP(ip_address):
	try:
		socket.inet_aton(ip_address)
		return True
	except socket.error:
		return False

def ratelimit_verify():
	global CLOUDFLARE_REQUESTS
	CLOUDFLARE_REQUESTS.append(time.time())
	CLOUDFLARE_REQUESTS = filter(lambda a: a > (time.time()-CLOUDFLARE_REQUESTS_PERIOD), CLOUDFLARE_REQUESTS)

	sleep_seconds = abs(((time.time()-CLOUDFLARE_REQUESTS_PERIOD) - min(CLOUDFLARE_REQUESTS)))

	if len(CLOUDFLARE_REQUESTS) == CLOUDFLARE_REQUESTS_MAX:
		print "Max number of API requests made in the last " + str(CLOUDFLARE_REQUESTS_PERIOD) + " seconds. Cooling down for " + str(sleep_seconds) + " seconds."
		time.sleep(sleep_seconds)

def fetch_user(cloudflare_email, cloudflare_apikey):
	request_headers = {
		"X-Auth-Email": cloudflare_email,
		"X-Auth-Key": cloudflare_apikey
	}

	try:
		request_user = urllib2.Request(CLOUDFLARE_API + "/user", headers=request_headers)
		user_data = json.loads(urllib2.urlopen(request_user).read())
	except urllib2.HTTPError as error:
		user_error_response = error.read()
		user_data = json.loads(user_error_response)

	ratelimit_verify()

	if not user_data["success"]:
		return False

	return user_data["result"]["first_name"]

def fetch_zones(cloudflare_email, cloudflare_apikey):
	request_headers = {
		"X-Auth-Email": cloudflare_email,
		"X-Auth-Key": cloudflare_apikey,
	}

	zones = {}

	try:
		request_zones = urllib2.Request(CLOUDFLARE_API + "/zones?per_page=50", headers=request_headers)
		zone_data = json.loads(urllib2.urlopen(request_zones).read())
	except urllib2.HTTPError as error:
		zone_error_response = error.read()
		zone_data = json.loads(zone_error_response)

	ratelimit_verify()

	if not zone_data["success"]:
		return False

	for i in range(0, zone_data["result_info"]["count"]):
		zones[zone_data["result"][i]["id"]] = zone_data["result"][i]["name"];

	if zone_data["result_info"]["total_count"] > zone_data["result_info"]["per_page"]:
		for current_page in range(2, (zone_data["result_info"]["total_count"]/zone_data["result_info"]["per_page"])+1):
			try:
				request_zones = urllib2.Request(CLOUDFLARE_API + "/zones?per_page=" + str(zone_data["result_info"]["per_page"]) + "&page=" + str(current_page), headers=request_headers)
				zone_data = json.loads(urllib2.urlopen(request_zones).read())
			except urllib2.HTTPError as error:
				zone_error_response = error.read()
				zone_data = json.loads(zone_error_response)

			ratelimit_verify()

			if not zone_data["success"]:
				return False

			for i in range(0, zone_data["result_info"]["count"]):
				zones[zone_data["result"][i]["id"]] = zone_data["result"][i]["name"];

	return zones

def fetch_dns_records(cloudflare_email, cloudflare_apikey, zone):
	request_headers = {
		"X-Auth-Email": cloudflare_email,
		"X-Auth-Key": cloudflare_apikey
	}

	dns_records = []

	try:
		request_dns_records = urllib2.Request(CLOUDFLARE_API + "/zones/" + zone + "/dns_records?per_page=50", headers=request_headers)
		dns_records_data = json.loads(urllib2.urlopen(request_dns_records).read())
	except urllib2.HTTPError as error:
		dns_records_error_response = error.read()
		dns_records_data = json.loads(dns_records_error_response)

	ratelimit_verify()

	if not dns_records_data["success"]:
		return False

	for i in range(0, dns_records_data["result_info"]["count"]):
		dns_record_data = {}
		dns_record_data["id"] = dns_records_data["result"][i]["id"]
		dns_record_data["type"] = dns_records_data["result"][i]["type"]
		dns_record_data["name"] = dns_records_data["result"][i]["name"]
		dns_record_data["content"] = dns_records_data["result"][i]["content"]
		dns_records.append(dns_record_data)

	if dns_records_data["result_info"]["total_count"] > dns_records_data["result_info"]["per_page"]:
		for current_page in range(2, (dns_records_data["result_info"]["total_count"]/dns_records_data["result_info"]["per_page"])+1):
			try:
				request_dns_records = urllib2.Request(CLOUDFLARE_API + "/zones/" + zone + "/dns_records?per_page=" + str(dns_records_data["result_info"]["per_page"]) + "&page=" + str(current_page), headers=request_headers)
				dns_records_data = json.loads(urllib2.urlopen(request_zones).read())
			except urllib2.HTTPError as error:
				dns_records_error_response = error.read()
				dns_records_data = json.loads(dns_records_error_response)

			ratelimit_verify()

			if not dns_records_data["success"]:
				return False

			for i in range(0, dns_records_data["result_info"]["count"]):
				dns_record_data = {}
				dns_record_data["id"] = dns_records_data["result"][i]["id"]
				dns_record_data["type"] = dns_records_data["result"][i]["type"]
				dns_record_data["name"] = dns_records_data["result"][i]["name"]
				dns_record_data["content"] = dns_records_data["result"][i]["content"]
				dns_records.append(dns_record_data)

	return dns_records

def update_dns_record(cloudflare_email, cloudflare_apikey, zone_id, dns_record_id, record_type, record_name, record_content):
	request_headers = {
		"X-Auth-Email": cloudflare_email,
		"X-Auth-Key": cloudflare_apikey,
		"Content-Type": "application/json"
	}

	update_data = {
		"id": dns_record_id,
		"type": record_type,
		"name": record_name,
		"content": record_content
	}

	try:
		update_dns_record = MethodRequest(CLOUDFLARE_API + "/zones/" + zone_id + "/dns_records/" + dns_record_id, method='PUT', data=json.dumps(update_data), headers=request_headers)
		ratelimit_verify()
		update_dns_record_data = json.loads(urllib2.urlopen(update_dns_record).read())
	except urllib2.HTTPError as error:
		update_dns_record_error_response = error.read()
		print update_dns_record_error_response
		update_dns_record_data = json.loads(update_dns_record_error_response)

	ratelimit_verify()

	return update_dns_record_data["success"]


def main():
	cloudflare_email = raw_input("CloudFlare Email: ")
	cloudflare_apikey = raw_input("CloudFlare API Key: ")

	print "Verifying user credentials."
	user = fetch_user(cloudflare_email, cloudflare_apikey)

	if not user:
		print "Unable to authenticate with CloudFlare REST API. Please check your credentials."
		sys.exit(1)

	print "Sucessfully verified user credentials, " + user + "."

	original_ip_address = raw_input("Original IPv4 Address: ")
	new_ip_address = raw_input("New IPv4 Address: ")

	if (verifyIP(original_ip_address) != True or verifyIP(new_ip_address) != True):
		print "The original and/or new IPv4 address provided could not be validated."
		print "Note: This script does not support modifying IPv6 values."
		sys.exit(1)

	if (original_ip_address == new_ip_address):
		print "The new IP specified matches the original IP address."
		sys.exit(1)

	print "Fetching zones from CloudFlare."
	zones = fetch_zones(cloudflare_email, cloudflare_apikey)

	if not zones:
		print "Unable to fetch zones from CloudFlare."
		sys.exit(1)

	print "Found " + str(len(zones)) + " zones."

	target_records = []

	print "Fetching DNS records for each zone from CloudFlare."

	total_modifiable_records = 0

	for zone_id in zones:
		dns_records = fetch_dns_records(cloudflare_email, cloudflare_apikey, zone_id)

		print "Found " + str(len(dns_records)) + " DNS records for " + zones[zone_id] + " (Zone ID: " + zone_id + ")."

		if not dns_records:
			print "Failed to fetch DNS records for " + zones[zone_id] + " (Zone ID: " + zone_id + ")."
			sys.exit(1)

		target_records_inzone = []

		for i in range(0, len(dns_records)):
			if original_ip_address in dns_records[i]["content"]:
				dns_modify_data = {}
				dns_modify_data["id"] = dns_records[i]["id"]
				dns_modify_data["type"] = dns_records[i]["type"]
				dns_modify_data["name"] = dns_records[i]["name"]
				dns_modify_data["old_content"] = dns_records[i]["content"]
				dns_modify_data["new_content"] = dns_records[i]["content"].replace(original_ip_address, new_ip_address)
				target_records_inzone.append(dns_modify_data)

		target_records.append((zone_id, target_records_inzone))
		total_modifiable_records = total_modifiable_records + len(target_records_inzone)

	if total_modifiable_records == 0:
		print "======================"
		print "Nothing to be changed. There were no records with the given original IP address."
		sys.exit(1)

	print "========================================================"
	print "The following changes will be made to your DNS settings:"
	for i in range(0, len(target_records)):
		if(len(target_records[i][1]) == 0):
			continue
		print "   Zone: " + zones[target_records[i][0]] + " (Zone ID: " + target_records[i][0] + ")"
		for j in range(0, len(target_records[i][1])):
			print "      + Record Type: " + target_records[i][1][j]["type"] + ", Record Name: " + target_records[i][1][j]["name"] + ", Record ID: " + target_records[i][1][j]["id"]
			print "            Original Value: " + target_records[i][1][j]["old_content"]
			print "                 New Value: " + target_records[i][1][j]["new_content"]

	print "Total records matching: " + str(total_modifiable_records)
	print ""

	verifyResponse = queryVerify("Proceed to make these changes to your DNS settings?")

	if verifyResponse:
		for i in range(0, len(target_records)):
			if(len(target_records[i][1]) == 0):
				continue
			for j in range(0, len(target_records[i][1])):
				print "Updating DNS record " + target_records[i][1][j]["name"] + " (Record ID: " + target_records[i][1][j]["id"] + ") in zone " + zones[target_records[i][0]] + " (Zone ID: " + target_records[i][0] + ")."
				update_result = update_dns_record(cloudflare_email, cloudflare_apikey, target_records[i][0], target_records[i][1][j]["id"], target_records[i][1][j]["type"], target_records[i][1][j]["name"], target_records[i][1][j]["new_content"])
				if not update_result:
					print "DNS record update failed."
					sys.exit(1)
		print "DNS record update complete."

if __name__ == "__main__":
	main()
