from flask import *
import numpy as np
import sqlite3, hashlib, os,re,whois,time
from datetime import datetime
from urllib.parse import urlparse,urlencode
import pandas as pd
from classificate import predicts
import requests as r

# from bs4 import BeautifulSoup
# import requests, re,urllib2, os, cookielib,json,shutil,glob

app=Flask(__name__)
app.config["CACHE_TYPE"] = "null"

app.secret_key = 'random string'
def getLoginDetails():
    with sqlite3.connect('database.db') as conn:
        cur = conn.cursor()
        if 'email' not in session:
            loggedIn = False
            firstName = ''
            noOfItems = 0
        else:
            loggedIn = True
            cur.execute("SELECT userId, firstName FROM users WHERE email = '" + session['email'] + "'")
            userId, firstName = cur.fetchone()
    conn.close()
    return (loggedIn, firstName)
@app.route('/')
def root():
    loggedIn, firstName = getLoginDetails()
    return render_template('mainindex.html',loggedIn=loggedIn,firstName=firstName)
@app.route("/logout")
def logout():
    session.pop('email', None)
    return redirect(url_for('root'))

def is_valid(email, password):
    con = sqlite3.connect('database.db')
    cur = con.cursor()
    cur.execute('SELECT email, password FROM users')
    data = cur.fetchall()
    for row in data:
        if row[0] == email and row[1] == hashlib.md5(password.encode()).hexdigest():
            return True
    return False
@app.route("/registrationForm")
def registrationForm():
    return render_template("register.html")
@app.route("/loginForm")
def loginForm():
    if 'email' in session:
        return redirect(url_for('root'))
    else:
        return render_template('login.html', error='')
@app.route("/login", methods = ['POST', 'GET'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if is_valid(email, password):
            session['email'] = email
            return redirect(url_for('root'))
        else:
            error = 'Invalid UserId / Password'
            return render_template('login.html', error=error)
@app.route("/phishing",methods=['POST','GET'])
def phishing():
    return render_template('phishing.html')
@app.route("/phishingd",methods=['POST','GET'])
def phishingd():
    if request.method=='POST':
        urli=request.form['url']
        testsUrl=[urli]
        testUrl=pd.DataFrame(testsUrl,columns=['url'])
        seperation_of_protocol = testUrl['url'].str.split("://",expand = True)
        seperation_domain_name = seperation_of_protocol[1].str.split("/",1,expand = True)
        splitted_data = pd.concat([seperation_of_protocol[0],seperation_domain_name],axis=1)
        seperation_domain_name.columns=["domain_name","address"]
        splitted_data.columns = ['protocol','domain_name','address']
        testData=[]
        def haveAtSymbol(url):
            if '@'in url:
                return 1
            else:
                return 0
        testData.append(testUrl['url'].apply(haveAtSymbol)[0])
         # test=splitted_data['age_domain'][0]
        def having_ip_address(url):

            match=re.search('(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  #IPv4
                        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  #IPv4 in hexadecimal
                        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',url)     #Ipv6
            if match:
                return 1
            else:
                return 0
        testData.append(testUrl['url'].apply(having_ip_address)[0])
        def prefix_suffix_seperation(l):
            if '-' in l:
                return 1
            return 0
        testData.append(seperation_domain_name['domain_name'].apply(prefix_suffix_seperation)[0])
        def haveRedirection(u):
            if "//" in u:
                return 1
            else: return 0
        testData.append(seperation_of_protocol[1].apply(haveRedirection)[0])
        def sub_domains(l):
            if l.count('.') < 3:

                return 0
            elif l.count('.') == 3:
                return 2
            return 1
        testData.append(splitted_data['domain_name'].apply(sub_domains)[0])
        def longUrl(url):
            if len(url)<54:
                return 0
            elif len(url)>=54 and len(url)<=75:
                return 2
            else:
                return 1
        testData.append(testUrl['url'].apply(longUrl)[0])
        def age_domain(url):
            dns = 0
            try:
                domain_name = whois.whois(urlparse(url).netloc)
            except:
                dns = 1
        
            if dns == 1:
                return 1
            else:
                creation_date = domain_name.creation_date
                expiration_date = domain_name.expiration_date
                if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
                    try:
                        creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
                        expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
                    except:
                        return 2
                if ((expiration_date is None) or (creation_date is None)):
                    return 1
                elif ((type(expiration_date) is list) or (type(creation_date) is list)):
                    return 2
                else:
                    ageofdomain = abs((expiration_date - creation_date).days)
                if ((ageofdomain/30) < 6):
                    return 1
                else:
                    return 0
        testData.append(testUrl['url'].apply(age_domain)[0])
        def dns_record(url):
            dns=0
            try:
                domain_name=whois.whois(urlparse(url).netloc)
            except:
                dns=1
            if dns==1:
                return 1
            else:
                return 0
        testData.append(testUrl['url'].apply(dns_record)[0])
        def domain_registration_length(url):

            dns = 0
            try:
                domain_name = whois.whois(urlparse(url).netloc)
            except:
                dns = 1
                
            if dns == 1:
                return 1      #phishing
            else:
                expiration_date = domain_name.expiration_date
                today = time.strftime('%Y-%m-%d')
                today = datetime.strptime(today, '%Y-%m-%d')
                if expiration_date is None:
                    return 1
                elif type(expiration_date) is list or type(today) is list :
                    return 2     #If it is a type of list then we can't select a single value from list. So,it is regarded as suspected website  
                else:
                    creation_date = domain_name.creation_date
                    expiration_date = domain_name.expiration_date
                    if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
                        try:
                            creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
                            expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
                        except:
                            return 2
                    registration_length = abs((creation_date - today).days)
                    print(registration_length)
                    if registration_length / 365 <= 1:
                        return 1 #phishing
                    else:
                        return 0 # legitimate
        testData.append(testUrl['url'].apply(domain_registration_length)[0])
        if(testData[0]==0):
            testData.append(0)
        else:
            testData.append(1)


        def https_token(url):
            match=re.search('https://|http://',url)
            try:
                if match.start(0)==0 and match.start(0) is not None:
                    url=url[match.end(0):]
                    match=re.search('http|https',url)
                    if match:
                        return 1
                    else:
                        return 0
            except:
                return 1
        testData.append(testUrl['url'].apply(https_token)[0])

        def statistical_report(url):
            hostname = url
            h = [(x.start(0), x.end(0)) for x in re.finditer('https://|http://|www.|https://www.|http://www.', hostname)]
            z = int(len(h))
            if z != 0:
                y = h[0][1]
                hostname = hostname[y:]
                h = [(x.start(0), x.end(0)) for x in re.finditer('/', hostname)]
                z = int(len(h))
                if z != 0:
                    hostname = hostname[:h[0][0]]
            url_match=re.search('at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly',url)
            try:
                ip_address = socket.gethostbyname(hostname)
                ip_match=re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',ip_address)  
            except:
                return 1

            if url_match:
                return 1
            else:
                return 0
        testData.append(testUrl['url'].apply(statistical_report)[0])
        def shortening_service(url):
            """Tiny URL -> phishing otherwise legitimate"""
            match=re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                        'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                        'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                        'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                        'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                        'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                        'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',url)
            if match:
                return 1               # phishing
            else:
                return 0
        testData.append(testUrl['url'].apply(shortening_service)[0])
        def web_traffic(url):
            from bs4 import BeautifulSoup
            import urllib.request
            try:
                url = "https://www.alexa.com/siteinfo/" + url
                respone = r.get(url) # get information from page
                soup = BeautifulSoup(respone.content,'html.parser')  
                for match in soup.find_all('span'): #remove all span tag
                    match.unwrap()
                global_rank = soup.select('p.big.data') # select any p tag with big and data class
                if(len(global_rank)>0):

                    global_rank = str(global_rank[0])
                else:
                    return 2
                res = re.findall(r"([0-9,]{1,12})", global_rank) # find rank_str 
            except ValueError:
                return 0
            if(int(res[0])<100000):
                return 0
            else:
                return 2
            
        testData.append(splitted_data['domain_name'].apply(web_traffic)[0])
        testDataArray=np.asarray(testData)
        testDataN=np.reshape(testDataArray,(1,14))
        result=predicts(testDataN)
        if (result==0):
            test=0
        else:
            test=1
        return render_template('phishing.html',url=result)
        app.run()
@app.route("/botnet")
def botnet():
    return render_template('botnet.html')
@app.route("/register", methods = ['GET', 'POST'])
def register():
    if request.method == 'POST':
        #Parse form data    
        password = request.form['password']
        email = request.form['email']
        firstName = request.form['firstName']
        lastName = request.form['lastName']
        with sqlite3.connect('database.db') as con:
            try:
                cur = con.cursor()
                cur.execute('INSERT INTO users (password, email, firstName, lastName) VALUES (?, ?, ?, ?)', (hashlib.md5(password.encode()).hexdigest(), email, firstName, lastName))

                con.commit()

                msg = "Registered Successfully"
            except:
                con.rollback()
                msg = "Error occured"
        con.close()
        return render_template("login.html", error=msg)

if __name__=='__main__':
    app.run(debug=True)
