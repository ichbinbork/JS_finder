
import os
from distutils.command.clean import clean
from itertools import count
import requests
import argparse
import re
from bs4 import BeautifulSoup
from bs4 import SoupStrainer


parser = argparse.ArgumentParser(description='Trying to help bug bounty processes')

parser.add_argument('-u', '--url', help='URL to scan', required=True)
parser.add_argument('-w', '--wordlist', help='Wordlist to scan', required=True)
argsx = parser.parse_args() #Parser for arguments
dangerous_functions_files = parser.parse_args() #Open the wordlist
content_of_page = requests.get(argsx.url).text #Get the content of the page

javascript_injection = ["eval",
"window.location",
"document.cookie",
"document.write",
"WebSocket",
"element.src",
"postMessage",
"setRequestHeader",
"FileReader.readAsText",
"ExecuteSql",
"sessionStorage.setItem",
"localStorage.setItem",
"document.evaluate",
"JSON.parse",
"JSON.stringify",
"parseJSON",
"element.evaluate",
"FileReader.readAsArrayBuffer",
"FileReader.readAsBinaryString",
"FileReader.readAsDataURL",
"FileReader.readAsFile",
"FileReader.root.getFile",
"element.setAttribute",
"element.setAttribute"
"element.search",
"element.text",
"element.textContent",
"element.innerText",
"element.outerText",
"element.value",
"element.name",
"element.target",
"element.method",
"element.type",
"element.backgroundImage",
"element.cssText",
"element.codebase",
"autofocus"
]
with open (argsx.wordlist, 'r') as f: 
    lines = f.readlines()  
clean_list = []
for line in lines: 
        if line not in clean_list:
            clean_list.append(line.strip())
        else:
            clean_list.append(line)
def checker (line,source_code): #Check if the function is dangerous or not
    print("Possibly javascript injection on line",repr(source_code.sourceline),"in source code")
    if line == 'eval':
        print("Possible Javascript Injection")
        print("Look at the eval() function parameters. If parameters has user input, it is vulnerable to javascript injection")
        print("Possible payloads: eval(document.cookie), eval(document.domain), eval(document.location)")
        print("More info at https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval")
    if line == 'document.write':
        print("Might cause DOM XSS")
        print("Possible payloads: \"><svg onload=alert(1)>")
        print("More info at https://developer.mozilla.org/en-US/docs/Web/API/Document/write")
    if line == 'window.location':
        print("Possible payloads: window.location = 'https://www.attecker_website.com'")
        print("Might cause Open redirection vulnerability")
        print("More info at https://developer.mozilla.org/en-US/docs/Web/API/Window/location")
    if line == 'document.cookie':
        print("The document.cookie sink can lead to DOM-based cookie-manipulation vulnerabilities.")
        print("More info at https://developer.mozilla.org/en-US/docs/Web/API/Document/cookie and https://portswigger.net/web-security/dom-based/cookie-manipulation")
    if line == 'WebSocket':
        print("Possible payloads: new WebSocket('ws://attacker.com')")
        print("More info at https://developer.mozilla.org/en-US/docs/Web/API/WebSocket")
    if line == 'element.src':
        print("Might cause DOM-based link manipulation")
        print("\"element.href, element.src, element.action main sinks\" can lead to DOM-based link-manipulation vulnerabilities.")
    if line == 'postMessage':
        print("Possible payloads: window.postMessage('hello', 'https://attacker.com')")
        print("More info at https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage")
    if line == 'setRequestHeader':
        print("Possible payloads: xhr.setRequestHeader('X-Forwarded-For', ')")
        print("More info at https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest/setRequestHeader")
    if line == 'FileReader.readAsText' or line == 'FileReader.readAsDataURL' or line == 'FileReader.readAsBinaryString' or line == 'FileReader.readAsArrayBuffer':
        print("Possible payloads: reader.readAsText(file)")
        print("More info at https://developer.mozilla.org/en-US/docs/Web/API/FileReader/readAsText")
    if line == 'ExecuteSql':
        print("Client Side SQLi | Possible payloads: db.executeSql('SELECT * FROM users')")
        print("More info at https://developer.mozilla.org/en-US/docs/Web/API/SQLDatabase/executeSql")
    if line == 'sessionStorage.setItem' or line == 'localStorage.setItem':
        print("Possible payloads: sessionStorage.setItem('key', 'value')", "localStorage.setItem('key', 'value')")
        print("More info at https://developer.mozilla.org/en-US/docs/Web/API/Window/sessionStorage")
    if line == 'document.evaluate' or line == 'element.evaluate':
        print("Client-side XPath injection | Possible payloads: document.evaluate('string', document, null, XPathResult.ANY_TYPE, null)")
        print("More info at https://developer.mozilla.org/en-US/docs/Web/API/Document/evaluate")
    if line == 'JSON.parse' or line == 'JSON.stringify' or line == 'parseJSON':
        print("Possible payloads: JSON.parse('string')")
        print("More info at https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse")
    if line == 'element.setAttribute' or line == 'element.search' or line == 'element.textContent' or line == 'element.innerText' or line == 'element.innerHTML' or line == 'element.outerText' or line == 'element.outerText' or line == 'element.value' or line == 'element.href' or line == 'element.src' or line == 'element.target':
        print("Might cause DOM XSS")
        print("Possible payloads: \"><svg onload=alert(1)>")
        print("More info at https://developer.mozilla.org/en-US/docs/Web/API/Element/setAttribute")
        print("Might cause DOM-based link manipulation")
        print("\"element.href, element.src, element.action main sinks\" can lead to DOM-based link-manipulation vulnerabilities.")
def checker_v2(line, js_path): 
    print("Might be dangerous function in javascript file", js_path)
    if line == 'eval':
        print("Possible Javascript Injection in javascript file", js_path)
        print("Look at the eval() function parameters. If parameters has user input, it is vulnerable to javascript injection")
        print("Possible payloads: eval(document.cookie), eval(document.domain), eval(document.location)")
        print("More info at https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval")
    if line == 'document.write':
        print("Might cause DOM XSS in javascript file", js_path)
        print("Might cause DOM XSS")
        print("Possible payloads: \"><svg onload=alert(1)>")
        print("More info at https://developer.mozilla.org/en-US/docs/Web/API/Document/write")
    if line == 'window.location':
        print("Possible payloads: window.location = 'https://www.attecker_website.com'")
        print("Might cause Open redirection vulnerability in javascript file", js_path)
        print("More info at https://developer.mozilla.org/en-US/docs/Web/API/Window/location")
    if line == 'document.cookie':
        print("The document.cookie sink can lead to DOM-based cookie-manipulation vulnerabilities in javascript file", js_path)
        print("More info at https://developer.mozilla.org/en-US/docs/Web/API/Document/cookie and https://portswigger.net/web-security/dom-based/cookie-manipulation")
    if line == 'WebSocket':
        print("Websocket vuln in javascript file", js_path)
        print("Possible payloads: new WebSocket('ws://attacker.com')")
        print("More info at https://developer.mozilla.org/en-US/docs/Web/API/WebSocket")
    if line == 'element.src':
        print("Might cause DOM-based link manipulation in javascript file", js_path)
        print("\"element.href, element.src, element.action main sinks\" can lead to DOM-based link-manipulation vulnerabilities.")
    if line == 'postMessage':
        print ("PostMessage vuln in javascript file", js_path)
        print("Possible payloads: window.postMessage('hello', 'https://attacker.com')")
        print("More info at https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage")
    if line == 'setRequestHeader':
        print("setRequestHeader in javascript file", js_path)
        print("Possible payloads: xhr.setRequestHeader('X-Forwarded-For', ')")
        print("More info at https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest/setRequestHeader")
    if line == 'FileReader.readAsText' or line == 'FileReader.readAsDataURL' or line == 'FileReader.readAsBinaryString' or line == 'FileReader.readAsArrayBuffer':
        print("FileReader in javascript file", js_path)
        print("Possible payloads: reader.readAsText(file)")
        print("More info at https://developer.mozilla.org/en-US/docs/Web/API/FileReader/readAsText")
    if line == 'ExecuteSql':
        print("ExecuteSql in", js_path)
        print("Client Side SQLi | Possible payloads: db.executeSql('SELECT * FROM users')")
        print("More info at https://developer.mozilla.org/en-US/docs/Web/API/SQLDatabase/executeSql")
    if line == 'sessionStorage.setItem' or line == 'localStorage.setItem':
        print("sessionStorange or localStorage in javascript file", js_path)
        print("Possible payloads: sessionStorage.setItem('key', 'value')", "localStorage.setItem('key', 'value')")
        print("More info at https://developer.mozilla.org/en-US/docs/Web/API/Window/sessionStorage")
    if line == 'document.evaluate' or line == 'element.evaluate':
        print("Possible Client-side XPath injection in javascript file", js_path)
        print("Client-side XPath injection | Possible payloads: document.evaluate('string', document, null, XPathResult.ANY_TYPE, null)")
        print("More info at https://developer.mozilla.org/en-US/docs/Web/API/Document/evaluate")
    if line == 'JSON.parse' or line == 'JSON.stringify' or line == 'parseJSON':
        print("JSON.parse in javascript file", js_path)
        print("Possible payloads: JSON.parse('string')")
        print("More info at https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/JSON/parse")
    if line == 'element.setAttribute' or line == 'element.search' or line == 'element.textContent' or line == 'element.innerText' or line == 'element.innerHTML' or line == 'element.outerText' or line == 'element.outerText' or line == 'element.value' or line == 'element.href' or line == 'element.src' or line == 'element.target':
        print("Might cause DOM XSS in javascript file", js_path)
        print("Possible payloads: \"><svg onload=alert(1)>")
        print("More info at https://developer.mozilla.org/en-US/docs/Web/API/Element/setAttribute")
        print("Might cause DOM-based link manipulation")
        print("\"element.href, element.src, element.action main sinks\" can lead to DOM-based link-manipulation vulnerabilities.")
    
source_code = BeautifulSoup(content_of_page, 'html.parser',store_line_numbers=True) #parsing the source code of the page
for script in source_code.find_all('script'): #finding all the scripts in the source code
    print("Javascript found on line",repr(script.sourceline),"in source code")
    if "src" in script.attrs: 
        print(f"Found {script.attrs['src']}")
        script.attrs['src'] = re.sub(r'^.','', script.attrs['src'])  # Regex to remove the first character of the string        
        js_url_path = argsx.url + script.attrs['src']
        print(js_url_path)
    
        content_of_page_js = requests.get(js_url_path).text
        for line in clean_list:
            if line in content_of_page_js:
                if line in javascript_injection:
                    
                    checker_v2(line, js_url_path)
def investigate_js(content_of_page,wordlist): #function to compare the wordlist with the source code of the page
    source_code = BeautifulSoup(content_of_page, 'html.parser',store_line_numbers=True)
    for script_content in source_code.find_all('script'):
        for lines_of_script_content in script_content:
            if "src" not in source_code.attrs:
                for line in wordlist:
                    if line in lines_of_script_content:
                        if line in javascript_injection:
                            checker(line, source_code)
                        print(f"Found {line} function in script page at line {script_content.sourceline}")

investigate_js(content_of_page,clean_list) 

f.close()