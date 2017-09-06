from collections import OrderedDict
import json,urllib

class R:
	"""Helper class to parse raw http request/response.
	Attributes: 
		_rawrequest (str)
		protocol (str): http or https
	Example:
	>>> a = ReqWrap(req,"http")
	>>> a.headers; a.url; a.protocol
	"""

	def __init__(self,raw_request,protocol="http",exclude=None):
		"""Method to parse the supplied request
		Arguments:
			protocol (str) : http/https
			exclude (List): Pass header list to be excluded
		Returns dict of headers (original sequence)"""
		if exclude and not isinstance(exclude,list):
			raise Exception("exclude must be list type")
		raw_request = urllib.unquote(raw_request)
		request_lines = raw_request.strip().split("\n")
		request_info = request_lines[0].split(" ")
		self.type  = request_info[0]
		self.path  = request_info[1]
		self.protocol = protocol
		self.headers = OrderedDict()
		if self.type == "POST":
			request_lines = raw_request.split("\n\n",1)[0].split("\n")
			body = raw_request.split("\n\n",1)[1].strip()
			data_params_values = body.split("&")
			if "boundary" not in body:
				x = OrderedDict()
				self.data = x
				for data in data_params_values:
					data = data.split("=",1)
					param = data[0]
					value = data[1]
					x[param] = value
			else:
				self.data = body
			self.data = body

		for line in request_lines:
			try:
				headers_name = line.split(":",1)[0].strip()
				headers_value = line.split(":",1)[1].strip()
				if exclude and headers_name in exclude:
					pass
				else:
					self.headers[headers_name] = headers_value
					setattr(self.headers, headers_name.replace('-','_'), headers_value)
					
			except IndexError:
				pass
		# incase host header is excluded, no url is generated
		try:
			self.url = protocol + "://" + self.headers['Host'] + self.path
		except KeyError:
			self.url = None


	def cookies(self):
		headers_value = self.headers["Cookie"]
		g = OrderedDict()
		self.headers["Cookie"] = g
		cookie_param_values = headers_value.split(";")
		for cookie_data in cookie_param_values:
			cookie_data = cookie_data.strip().split("=",1)
			cookie_param = cookie_data[0]
			cookie_value = cookie_data[1]
			g[cookie_param] = cookie_value
		return self.headers["Cookie"]


	def __str__(self):
		return str(json.dumps(self.__dict__,indent=4))
